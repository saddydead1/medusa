"""Цепочки: пользователь видит её как один хост, вход — в первую ноду.

Создание цепочки сразу заводит хост (как и на настоящих панелях), удаление —
забирает хост с собой. Логика инбаундов на нодах пока не делается.
"""
from __future__ import annotations

import json
import sqlite3

from fastapi import APIRouter, Depends

from src.panel.db import get_conn, now_ms
from src.panel.deps import bad_request, conflict, fetch_one, writer
from src.panel.schemas import ChainCreate

router = APIRouter(prefix="/api/chains", tags=["chains"])


def hops_of(conn: sqlite3.Connection, raw: str) -> list[dict]:
    """Хопы наружу именами нод: если ноду удалили — остаётся имя из снимка."""
    out = []
    for hop in json.loads(raw):
        node = conn.execute("SELECT name FROM nodes WHERE id = ?", (hop["node_id"],)).fetchone()
        out.append({
            "node": node["name"] if node else hop.get("node", f"#{hop['node_id']}"),
            "protocol": hop["protocol"],
            "network": hop["network"],
            "security": hop["security"],
            "port": hop["port"],
        })
    return out


def as_dict(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    return {"id": row["id"], "name": row["name"], "hops": hops_of(conn, row["hops"])}


def used_ports(conn: sqlite3.Connection, skip_chain: int | None = None) -> dict[int, set[int]]:
    used: dict[int, set[int]] = {}
    for row in conn.execute("SELECT node_id, port FROM hosts").fetchall():
        used.setdefault(row["node_id"], set()).add(row["port"])
    for row in conn.execute("SELECT id, hops FROM chains").fetchall():
        if skip_chain is not None and row["id"] == skip_chain:
            continue
        for hop in json.loads(row["hops"]):
            used.setdefault(hop["node_id"], set()).add(hop["port"])
    return used


@router.get("")
def list_chains(conn: sqlite3.Connection = Depends(get_conn)) -> list[dict]:
    return [as_dict(conn, r) for r in conn.execute("SELECT * FROM chains ORDER BY name").fetchall()]


@router.post("", status_code=201)
def create_chain(
    body: ChainCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    nodes = {}
    for hop in body.hops:
        row = conn.execute("SELECT id, name FROM nodes WHERE name = ?", (hop.node,)).fetchone()
        if row is None:
            raise bad_request(f"ноды «{hop.node}» нет")
        nodes[hop.node] = row["id"]

    for a, b in zip(body.hops, body.hops[1:], strict=False):
        if a.node == b.node:
            raise bad_request("соседние хопы должны быть на разных нодах")
        if a.security == "reality" and a.network == "ws":
            raise bad_request("reality не работает поверх ws")

    used = used_ports(conn)
    for hop in body.hops:
        node_id = nodes[hop.node]
        if hop.port in used.get(node_id, set()):
            raise conflict(f"порт {hop.port} на ноде {hop.node} уже занят")
        used.setdefault(node_id, set()).add(hop.port)

    hops = [{"node_id": nodes[h.node], "node": h.node, "protocol": h.protocol,
             "network": h.network, "security": h.security, "port": h.port} for h in body.hops]
    try:
        cur = conn.execute("INSERT INTO chains (name, hops, created_at) VALUES (?,?,?)",
                           (body.name, json.dumps(hops, ensure_ascii=False), now_ms()))
    except sqlite3.IntegrityError:
        raise conflict(f"цепочка «{body.name}» уже есть")
    first = hops[0]
    conn.execute(
        "INSERT INTO hosts (name, node_id, protocol, port, network, security, chain_id, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (body.name, first["node_id"], first["protocol"], first["port"], first["network"], first["security"], cur.lastrowid, now_ms()),
    )
    conn.commit()
    return as_dict(conn, fetch_one(conn, "SELECT * FROM chains WHERE id = ?", (cur.lastrowid,)))


@router.patch("/{chain_id}")
def rename_chain(
    chain_id: int,
    body: ChainCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    """Переименование цепочки заодно правит и её хост — расхождений быть не должно."""
    fetch_one(conn, "SELECT id FROM chains WHERE id = ?", (chain_id,))
    try:
        conn.execute("UPDATE chains SET name = ? WHERE id = ?", (body.name, chain_id))
        conn.execute("UPDATE hosts SET name = ? WHERE chain_id = ?", (body.name, chain_id))
    except sqlite3.IntegrityError:
        raise conflict(f"цепочка «{body.name}» уже есть")
    conn.commit()
    return as_dict(conn, fetch_one(conn, "SELECT * FROM chains WHERE id = ?", (chain_id,)))


@router.delete("/{chain_id}", status_code=204)
def delete_chain(
    chain_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> None:
    fetch_one(conn, "SELECT id FROM chains WHERE id = ?", (chain_id,))
    conn.execute("DELETE FROM chains WHERE id = ?", (chain_id,))   # hosts.chain_id ON DELETE CASCADE
    conn.commit()

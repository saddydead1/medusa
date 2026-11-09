"""Хосты — то, что пользователь видит в подписке.

Хост цепочки здесь не выдумывается фронтендом: он создаётся вместе с цепочкой
и живёт в той же таблице, ссылаясь на неё (цепочка -> хост через chain_id).
"""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends

from src.panel.db import get_conn, now_ms
from src.panel.deps import bad_request, conflict, fetch_one, node_by_name, writer
from src.panel.schemas import HostCreate

router = APIRouter(prefix="/api/hosts", tags=["hosts"])

SELECT = """
SELECT h.*, n.name AS node_name, c.name AS chain_name
FROM hosts h
JOIN nodes n ON n.id = h.node_id
LEFT JOIN chains c ON c.id = h.chain_id
"""
ORDER = "ORDER BY (h.chain_id IS NOT NULL), h.name"


def as_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "node": row["node_name"],
        "protocol": row["protocol"],
        "port": row["port"],
        "network": row["network"],
        "security": row["security"],
        "chain": row["chain_id"],
        "chain_name": row["chain_name"],
    }


@router.get("")
def list_hosts(conn: sqlite3.Connection = Depends(get_conn)) -> list[dict]:
    return [as_dict(r) for r in conn.execute(SELECT + ORDER).fetchall()]


@router.post("", status_code=201)
def create_host(
    body: HostCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    node = node_by_name(conn, body.node)
    if body.security == "reality" and body.network == "ws":
        raise bad_request("reality не работает поверх ws")
    if body.protocol == "ss" and body.network != "tcp":
        raise bad_request("shadowsocks тут только через tcp")
    busy = conn.execute("SELECT id FROM hosts WHERE node_id = ? AND port = ?", (node["id"], body.port)).fetchone()
    if busy:
        raise conflict(f"порт {body.port} на ноде {body.node} уже занят")
    try:
        conn.execute(
            "INSERT INTO hosts (name, node_id, protocol, port, network, security, chain_id, created_at) VALUES (?,?,?,?,?,?,NULL,?)",
            (body.name, node["id"], body.protocol, body.port, body.network, body.security, now_ms()),
        )
    except sqlite3.IntegrityError:
        raise conflict(f"порт {body.port} на ноде {body.node} уже занят")
    conn.commit()
    new_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    return as_dict(fetch_one(conn, SELECT + " WHERE h.id = ?", (new_id,)))


@router.delete("/{host_id}", status_code=204)
def delete_host(
    host_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> None:
    row = fetch_one(conn, "SELECT chain_id FROM hosts WHERE id = ?", (host_id,))
    if row["chain_id"] is not None:
        raise conflict("хост цепочки удаляется вместе с цепочкой")
    conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
    conn.commit()

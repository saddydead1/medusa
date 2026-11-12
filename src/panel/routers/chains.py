"""Цепочки: пользователь видит её как один хост, вход — в первую ноду.

Цепочка живёт в таблице `hosts` своими строками — по одной на каждый хоп (`hop_index`
0..n-1, у обычного хоста -1). Вход цепочки (хоп 0) человек видит в списке хостов как хост
с именем цепочки: к нему он подключается, ему же отдаётся ссылка подписки. Промежуточные
хопа — те же строки hosts, но наружу они не показываются: это внутренняя связь нод, и
правятся они только вместе с цепочкой.

Такой порядок даёт цепочке всё, что есть у обычного хоста: занятый порт учитывается наравне
(UNIQUE (node_id, port)), ключи reality выпускаются при создании, а tls-хосту цепочки панель
выпускает сертификат сама (src/panel/host_keys.py) — иначе соседняя нода не смогла бы ему
доверять.

Логика инбаундов и переходов — в `src/core/xray_config.py` (hop_clients, hop_outbound,
routing по inboundTag); здесь только смысл записи и её границы.
"""
from __future__ import annotations

import json
import sqlite3

from fastapi import APIRouter, Depends

from src.core.xray_config import security_issue, unsupported_protocol, UNSUPPORTED_HINT
from src.panel import config_push
from src.panel.chain_hops import insert_hop
from src.panel.db import get_conn, now_ms
from src.panel.deps import bad_request, conflict, fetch_one, writer
from src.panel.schemas import ChainCreate

router = APIRouter(prefix="/api/chains", tags=["chains"])


def check_hop(hop) -> None:
    """Хоп цепочки обязан быть тем же набором, что и хост: инбаунд цепочки — это
    её первый хоп, а из него собираются и конфиг, и ссылка подписки."""
    if unsupported_protocol(hop.protocol):
        raise bad_request(UNSUPPORTED_HINT)
    issue = security_issue(hop.protocol, hop.security)
    if issue:
        raise bad_request(issue)
    if hop.security == "reality" and hop.network == "ws":
        raise bad_request("reality не работает поверх ws")
    if hop.protocol == "ss" and hop.network != "tcp":
        raise bad_request("shadowsocks тут только через tcp")


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
    """Занятые порты нод. Хопа цепочки занимают порт наравне с обычными хостами:
    на ноде поднимается инбаунд каждого хопа, и два инбаунда на одном порту — не вариант."""
    used: dict[int, set[int]] = {}
    for row in conn.execute("SELECT node_id, port, chain_id FROM hosts").fetchall():
        if skip_chain is not None and row["chain_id"] == skip_chain:
            continue
        used.setdefault(row["node_id"], set()).add(row["port"])
    return used


def resolve_hops(conn: sqlite3.Connection, body: ChainCreate, skip_chain: int | None) -> tuple[list[dict], list[int]]:
    """Хопы запроса -> хопы базы: ноды по именам, порты проверены, порядок сохранён."""
    nodes = {}
    for hop in body.hops:
        check_hop(hop)
        row = conn.execute("SELECT id, name, address FROM nodes WHERE name = ?", (hop.node,)).fetchone()
        if row is None:
            raise bad_request(f"ноды «{hop.node}» нет")
        nodes[hop.node] = row

    for a, b in zip(body.hops, body.hops[1:], strict=False):
        if a.node == b.node:
            raise bad_request("соседние хопы должны быть на разных нодах")

    used = used_ports(conn, skip_chain=skip_chain)
    for hop in body.hops:
        node_id = nodes[hop.node]["id"]
        if hop.port in used.get(node_id, set()):
            raise conflict(f"порт {hop.port} на ноде {hop.node} уже занят")
        used.setdefault(node_id, set()).add(hop.port)

    resolved = [{"node_id": nodes[h.node]["id"], "node": h.node, "protocol": h.protocol,
                 "network": h.network, "security": h.security, "port": h.port} for h in body.hops]
    return resolved, [h["node_id"] for h in resolved]


@router.get("")
def list_chains(conn: sqlite3.Connection = Depends(get_conn)) -> list[dict]:
    return [as_dict(conn, r) for r in conn.execute("SELECT * FROM chains ORDER BY name").fetchall()]


@router.post("", status_code=201)
def create_chain(
    body: ChainCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    hops, node_ids = resolve_hops(conn, body, skip_chain=None)
    try:
        cur = conn.execute("INSERT INTO chains (name, hops, created_at) VALUES (?,?,?)",
                           (body.name, json.dumps(hops, ensure_ascii=False), now_ms()))
        chain_id = cur.lastrowid
        for index, hop in enumerate(hops):
            insert_hop(conn, chain_id, body.name, index, hop, now_ms())
    except sqlite3.IntegrityError:
        conn.rollback()
        raise conflict(f"цепочка «{body.name}» уже есть (или её порты уже заняты)")
    conn.commit()
    config_push.mark_dirty(conn, node_ids)
    config_push.schedule_push(node_ids)
    return as_dict(conn, fetch_one(conn, "SELECT * FROM chains WHERE id = ?", (chain_id,)))


@router.patch("/{chain_id}")
def patch_chain(
    chain_id: int,
    body: ChainCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    """Цепочка правится целиком, вместе со своими хопами.

    Хост цепочки нельзя править отдельно (`409` в hosts), поэтому здесь принимаются и
    новые хопа: строки хостов пересоздаются вместе с описанием цепочки. Ключи при этом
    выпускаются заново — подпись цепочки (ссылка подписки на её вход) меняется вслед за
    конфигами, расхождений «человек видит одно, нода работает по другому» не остаётся.
    """
    fetch_one(conn, "SELECT id FROM chains WHERE id = ?", (chain_id,))
    before = [row["node_id"] for row in conn.execute(
        "SELECT node_id FROM hosts WHERE chain_id = ?", (chain_id,)).fetchall()]
    hops, node_ids = resolve_hops(conn, body, skip_chain=chain_id)
    try:
        conn.execute("DELETE FROM hosts WHERE chain_id = ?", (chain_id,))
        conn.execute("UPDATE chains SET name = ?, hops = ? WHERE id = ?",
                     (body.name, json.dumps(hops, ensure_ascii=False), chain_id))
        for index, hop in enumerate(hops):
            insert_hop(conn, chain_id, body.name, index, hop, now_ms())
    except sqlite3.IntegrityError:
        conn.rollback()
        raise conflict(f"цепочка «{body.name}» уже есть (или её порты уже заняты)")
    conn.commit()
    touched = sorted(set(before) | set(node_ids))
    config_push.mark_dirty(conn, touched)
    config_push.schedule_push(touched)
    return as_dict(conn, fetch_one(conn, "SELECT * FROM chains WHERE id = ?", (chain_id,)))


@router.delete("/{chain_id}", status_code=204)
def delete_chain(
    chain_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> None:
    fetch_one(conn, "SELECT id FROM chains WHERE id = ?", (chain_id,))
    node_ids = [row["node_id"] for row in conn.execute(
        "SELECT node_id FROM hosts WHERE chain_id = ?", (chain_id,)).fetchall()]
    conn.execute("DELETE FROM chains WHERE id = ?", (chain_id,))   # hosts.chain_id ON DELETE CASCADE
    conn.commit()
    config_push.mark_dirty(conn, node_ids)
    config_push.schedule_push(node_ids)

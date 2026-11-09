"""Ноды — серверы, где крутится VPN. Панель ходит к ним сама: свой порт, свой API-ключ."""
from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.core.api_keys import api_key_fingerprint
from src.panel.db import get_conn, now_ms
from src.panel.deps import bad_request, conflict, fetch_one, writer
from src.panel.node_check import check_node as run_check
from src.panel.nodes_rows import NODE_COLUMNS, as_dict
from src.panel.schemas import NodeCreate, NodePatch

router = APIRouter(prefix="/api/nodes", tags=["nodes"])


@router.get("")
def list_nodes(conn: sqlite3.Connection = Depends(get_conn)) -> list[dict]:
    return [as_dict(r) for r in conn.execute(f"SELECT {NODE_COLUMNS} FROM nodes ORDER BY name").fetchall()]


@router.post("", status_code=201)
def create_node(
    body: NodeCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    try:
        conn.execute(
            """INSERT INTO nodes (name, address, online, xray_version, users_count, traffic_bytes,
                                   api_port, api_key, created_at)
               VALUES (?,?,0,?,0,0,?,?,?)""",
            (body.name, body.address, body.xray, body.apiPort or 9443, body.apiKey, now_ms()),
        )
    except sqlite3.IntegrityError:
        raise conflict(f"нода «{body.name}» уже есть")
    conn.commit()
    return as_dict(fetch_one(conn, f"SELECT {NODE_COLUMNS} FROM nodes WHERE name = ?", (body.name,)))


@router.patch("/{node_id}")
def patch_node(
    node_id: int,
    body: NodePatch,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    before = fetch_one(conn, f"SELECT {NODE_COLUMNS} FROM nodes WHERE id = ?", (node_id,))
    # поле трогается только если его прислали: null значит «убрать», но только там,
    # где колонка и правда может быть пустой (ключ ноды, версия Xray)
    provided = body.model_fields_set
    nullable = {"xray"}   # API-ключ не снимается: без него нода остаётся декоративной
    changes = {k: v for k, v in body.model_dump().items() if k in provided and (v is not None or k in nullable)}
    columns = {"name": "name", "address": "address", "online": "online", "xray": "xray_version",
               "apiPort": "api_port", "apiKey": "api_key"}
    if not changes:
        return as_dict(fetch_one(conn, f"SELECT {NODE_COLUMNS} FROM nodes WHERE id = ?", (node_id,)))
    sets = ", ".join(f"{columns[k]} = ?" for k in changes)
    values = [int(v) if k == "online" else v for k, v in changes.items()]
    # «связь есть» перестаёт быть честным, только если адрес, порт или API-ключ правда
    # поменялись. Форма присылает их всегда одними и теми же — значит, и сбрасывать
    # ничего не надо: иначе каждый сохранённый диалог ронял бы ноду в «недоступна».
    same = {"address": before["address"], "apiPort": before["api_port"], "apiKey": before["api_key"]}
    if any(k in changes and changes[k] != same[k] for k in same):
        sets += ", seen_at = 0, agent_version = NULL, online = 0"
    try:
        conn.execute(f"UPDATE nodes SET {sets} WHERE id = ?", (*values, node_id))
    except sqlite3.IntegrityError:
        raise conflict(f"нода «{changes.get('name')}» уже есть")
    conn.commit()
    return as_dict(fetch_one(conn, f"SELECT {NODE_COLUMNS} FROM nodes WHERE id = ?", (node_id,)))


@router.delete("/{node_id}", status_code=204)
def delete_node(
    node_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> None:
    before = fetch_one(conn, f"SELECT {NODE_COLUMNS} FROM nodes WHERE id = ?", (node_id,))
    conn.execute("DELETE FROM nodes WHERE id = ?", (node_id,))   # хосты ноды падают по cascade
    conn.commit()


@router.get("/{node_id}/key")
def node_api_key(
    node_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    """API-ключ ноды целиком. Нужен один раз: чтобы скопировать его на саму ноду
    (`MEDUSA_NODE_API_KEY`). В списках и карточках ключ не показывается никогда — только
    начало и отпечаток.
    """
    row = fetch_one(conn, "SELECT api_key FROM nodes WHERE id = ?", (node_id,))
    api_key = row["api_key"]
    if not api_key:
        raise conflict("API-ключа у этой ноды нет — в старой базе его просто не было")
    return {"key": api_key, "fingerprint": api_key_fingerprint(api_key)}


@router.post("/{node_id}/check")
def check_node(
    node_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    """Панель стучится на ноду тем же походом, что и опрос по таймеру: сначала витрина
    `/node/health` без ключа, потом `/node/identity` с ним (см. `src/panel/node_check.py`).
    """
    try:
        return run_check(conn, node_id)
    except LookupError as err:
        raise HTTPException(status_code=404, detail=str(err)) from err

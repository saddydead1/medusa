"""Ноды — серверы, где крутится VPN. Панель ходит к ним сама: свой порт, свой API-ключ."""
from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.core.api_keys import api_key_fingerprint
from src.panel import config_push, ports
from src.panel.chain_hops import reissue_hop_certs
from src.panel.db import get_conn, now_ms
from src.panel.deps import bad_request, conflict, current_admin, fetch_one, writer
from src.panel.node_check import check_node as run_check
from src.panel.nodes_rows import NODE_COLUMNS, as_dict
from src.panel.schemas import NodeCreate, NodePatch

router = APIRouter(prefix="/api/nodes", tags=["nodes"])


@router.get("")
def list_nodes(conn: sqlite3.Connection = Depends(get_conn)) -> list[dict]:
    return [as_dict(r) for r in conn.execute(f"SELECT {NODE_COLUMNS} FROM nodes ORDER BY name").fetchall()]


def check_api_port(conn: sqlite3.Connection, node_id: int | None, address: str, port: int) -> None:
    """API-порт ноды не должен наступать на чужой слушатель на той же машине.

    Это не придирка: нода и её же хосты живут на одном адресе, и если API-порт совпадёт с
    портом хоста (своего или чужой ноды на этой машине), Xray не поднимется — а панель будет
    видеть живую ноду с мёртвыми хостами.
    """
    issue = ports.port_conflict(conn, address, port, skip_node=node_id)
    if issue:
        raise conflict(issue)


@router.post("", status_code=201)
def create_node(
    body: NodeCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    check_api_port(conn, None, body.address, body.apiPort or 9443)
    try:
        conn.execute(
            """INSERT INTO nodes (name, address, online, xray_version, traffic_bytes,
                                   api_port, api_key, created_at)
               VALUES (?,?,0,?,0,?,?,?)""",        # трафик и подписчиков считает нода, не INSERT
            (body.name, body.address, body.xray, body.apiPort or 9443, body.apiKey, now_ms()),
        )
    except sqlite3.IntegrityError:
        raise conflict(f"нода «{body.name}» уже есть")
    conn.commit()
    created = fetch_one(conn, f"SELECT {NODE_COLUMNS} FROM nodes WHERE name = ?", (body.name,))
    if created["api_key"]:
        config_push.mark_dirty(conn, [created["id"]])   # свежую ноду стоит познакомить с конфигом
    return as_dict(fetch_one(conn, f"SELECT {NODE_COLUMNS} FROM nodes WHERE id = ?", (created["id"],)))


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
    # чем нода станет после правки: адрес и API-порт проверяются уже новыми значениями,
    # вместе с портами её хостов (они переезжают на новый адрес вместе с нодой)
    address = changes.get("address", before["address"])
    api_port = int(changes.get("apiPort", before["api_port"]))
    check_api_port(conn, node_id, address, api_port)
    for host in conn.execute("SELECT id, name, port FROM hosts WHERE node_id = ?", (node_id,)).fetchall():
        issue = ports.port_conflict(conn, address, int(host["port"]),
                                    skip_node=node_id, skip_host=int(host["id"]))
        if issue:
            raise conflict(f"хост «{host['name']}»: {issue}")

    tls_chains: list[int] = []
    if "address" in changes and changes["address"] != before["address"]:
        # адрес ноды поехал — сертификаты её tls-хопов должны называть новое имя
        tls_chains = reissue_hop_certs(conn, node_id)

    try:
        conn.execute(f"UPDATE nodes SET {sets} WHERE id = ?", (*values, node_id))
    except sqlite3.IntegrityError:
        raise conflict(f"нода «{changes.get('name')}» уже есть")
    conn.commit()
    config_push.mark_dirty(conn, [node_id] + tls_chains_nodes(conn, tls_chains))
    config_push.schedule_push([node_id] + tls_chains_nodes(conn, tls_chains))
    return as_dict(fetch_one(conn, f"SELECT {NODE_COLUMNS} FROM nodes WHERE id = ?", (node_id,)))


def tls_chains_nodes(conn: sqlite3.Connection, chain_ids: list[int]) -> list[int]:
    """Все ноды, которых касаются перевыпущенные сертификаты хопов (и отправитель, и приёмник)."""
    if not chain_ids:
        return []
    marks = ",".join("?" * len(chain_ids))
    return [int(row["node_id"]) for row in conn.execute(
        f"SELECT DISTINCT node_id FROM hosts WHERE chain_id IN ({marks})", chain_ids).fetchall()]


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


@router.post("/{node_id}/apply")
def apply_node_config(
    node_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    """Применить конфиг сейчас же, не дожидаясь опроса. Нужен редко: правки хостов
    и пользователей панель доставляет сама. Отказ ноды — не ошибка HTTP: в отчёте
    `ok: false` и человеческое `error`."""
    try:
        return config_push.push_node(conn, node_id)
    except LookupError as err:
        raise HTTPException(status_code=404, detail=str(err)) from err


@router.get("/{node_id}/config")
def node_config(
    node_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(current_admin),
) -> dict:
    """Посмотреть конфиг Xray этой ноды таким, каким панель собралась его отправить.
    Только чтение: правки хостов и пользователей пересобирают конфиг целиком,
    а приватные ключы в этом показе скрыты."""
    try:
        return config_push.node_config_view(conn, node_id)
    except LookupError as err:
        raise HTTPException(status_code=404, detail=str(err)) from err

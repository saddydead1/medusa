"""Занятость портов на машине ноды.

Порт хоста нельзя проверять «внутри одной ноды»: две ноды с одним адресом живут на одной
машине (или выходят наружу под одним адресом), и там их слушатели сталкиваются. Xray при этом
не поднимает половинку конфига — он падает целиком с `bind: address already in use` и уносит
за собой все хосты этой ноды, включая те, что вчера работали. Проверка поэтому смотрит на
пару (адрес ноды, порт) и считает занятостью и API-порты нод: они слушают на той же машине.

Хопа цепочки — такие же слушатели, как обычные хосты: у каждого хопа на его ноде поднимается
инбаунд. Поэтому они участвуют в проверке наравне со всеми.
"""
from __future__ import annotations

import sqlite3

PORT_MIN = 1
PORT_MAX = 65535


def norm(address: str | None) -> str:
    """Адрес ноды для сравнения: без регистра и пробелов."""
    return (address or "").strip().lower()


def node_address(conn: sqlite3.Connection, node_id: int) -> str:
    row = conn.execute("SELECT address FROM nodes WHERE id = ?", (node_id,)).fetchone()
    return norm(row["address"]) if row else ""


def port_conflict(conn: sqlite3.Connection, address: str, port: int, *,
                  skip_node: int | None = None, skip_host: int | None = None,
                  skip_chain: int | None = None) -> str | None:
    """Кем занят (адрес, порт). None — свободно.

    `skip_node` — чей API-порт вот-вот изменится (правка ноды: её собственный порт конфликтом
    не является). `skip_host` — строка хоста, которую правят. `skip_chain` — цепочку, которую
    пересобирают целиком: её прежние хопа исчезнут в той же транзакции.
    """
    target = norm(address)
    if not target:
        return None

    for node in conn.execute("SELECT id, name, address, api_port FROM nodes ORDER BY name").fetchall():
        if norm(node["address"]) != target or int(node["api_port"]) != port:
            continue
        if skip_node is not None and int(node["id"]) == skip_node:
            continue
        return (f"порт {port} на {target} уже занят API-портом ноды «{node['name']}» — "
                f"Xray на этой машине не поднимется")

    rows = conn.execute(
        """SELECT h.id, h.name, h.port, h.chain_id, n.id AS node_id, n.name AS node_name,
                  n.address AS node_address
           FROM hosts h JOIN nodes n ON n.id = h.node_id ORDER BY h.id""").fetchall()
    for row in rows:
        if int(row["port"]) != port or norm(row["node_address"]) != target:
            continue
        if skip_host is not None and int(row["id"]) == skip_host:
            continue
        if skip_chain is not None and row["chain_id"] == skip_chain:
            continue
        same_node = int(row["node_id"]) == (skip_node if skip_node is not None else -1)
        where = "на этой ноде" if same_node else "на этом же адресе"
        kind = "хостом цепочки" if row["chain_id"] is not None else "хостом"
        return (f"порт {port} на {target} уже занят {kind} «{row['name']}» "
                f"ноды «{row['node_name']}» {where}")
    return None


def host_port_conflict(conn: sqlite3.Connection, node_id: int, port: int, *,
                       skip_host: int | None = None, skip_chain: int | None = None) -> str | None:
    """Конфликт порта хоста: адрес берётся из ноды, куда этот хост должен сесть."""
    return port_conflict(conn, node_address(conn, node_id), port,
                         skip_node=node_id, skip_host=skip_host, skip_chain=skip_chain)


def free_port(conn: sqlite3.Connection, node_id: int, wanted: int, *,
              reserved: set[tuple[int, int]] | None = None) -> int | None:
    """Первый свободный порт от `wanted` вверх — нужно миграции прежних цепочек.

    Живые порты людей панель молча не двигает: это решает человек. Миграции же приходится:
    прежняя цепочка могла занять чужой порт (например API-порт соседней ноды на той же
    машине), и оставить его занятым — значит опустить ноду целиком. Найденный порт миграция
    записывает и в ряд хопа, и в hops цепочки, и печатает в лог, чтобы это не было сюрпризом.
    """
    reserved = reserved or set()
    address = node_address(conn, node_id)
    for port in range(max(PORT_MIN, wanted), PORT_MAX + 1):
        if (node_id, port) in reserved:
            continue
        if port_conflict(conn, address, port, skip_node=node_id) is None:
            return port
    return None

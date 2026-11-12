"""Строка хопа цепочки в таблице hosts — общая для создания цепочки и для миграции прежних.

Цепочка заводит свой ряд hosts на каждый хоп (`hop_index` 0 — вход, 1.. — промежуточные),
поэтому хоп получает всё, что есть у обычного хоста: занятый порт (`UNIQUE (node_id, port)`),
ключи reality, а tls-хосту цепочки — сертификат, выпущенный панелью (её отпечаток потом
закрепляется за соседней нодой: Xray 26 самоподписанный сертификат «на веру» не принимает).

Здесь нет ни FastAPI, ни зависимостей: функции принимает соединение и готовое описание хопа,
чтобы ими пользовались и эндпоинты (`routers/chains.py`), и миграция схемы (`db.py`).
"""
from __future__ import annotations

import sqlite3

from src.panel.host_keys import new_hop_certificate, new_reality_keys

# hop_index входа: человек видит этот ряд хостом цепочки, остальные — нет
ENTRY_HOP = 0


def hop_name(chain_name: str, index: int) -> str:
    """Имя хопа: вход носит имя цепочки (его видит человек), дальше — «цепочка hop N».

    Имя хоста становится тегом инбаунда в конфиге Xray, поэтому по нему в логе ноды видно,
    какой переход какой цепочки обслужил трафик.
    """
    return chain_name if index == ENTRY_HOP else f"{chain_name} hop {index + 1}"


def hop_keys(conn: sqlite3.Connection, hop: dict, node_address: str) -> dict[str, str]:
    """Ключи защиты хопа: reality — пара x25519, tls — сертификат от панели.

    Сертификат выпускается на адрес ноды этого хопа: своего адреса у хопа нет, клиентом для
    соседней ноды является сама нода.
    """
    keys = {"private_key": "", "public_key": "", "cert_pem": "", "key_pem": "", "cert_sha256": ""}
    if hop["security"] == "reality":
        keys["private_key"], keys["public_key"] = new_reality_keys()
    elif hop["security"] == "tls":
        keys["cert_pem"], keys["key_pem"], keys["cert_sha256"] = new_hop_certificate(node_address)
    return keys


def insert_hop(conn: sqlite3.Connection, chain_id: int, chain_name: str, index: int,
               hop: dict, created_at: int) -> int:
    """Завести ряд хопа цепочки. `hop` — описание из цепочки: node_id, protocol,
    network, security, port. Возвращает id строки hosts."""
    node = conn.execute("SELECT id, address FROM nodes WHERE id = ?", (hop["node_id"],)).fetchone()
    if node is None:
        raise LookupError(f"ноды {hop['node_id']} нет — хоп цепочки завести некуда")
    keys = hop_keys(conn, hop, node["address"])
    conn.execute(
        """INSERT INTO hosts (name, node_id, protocol, port, network, security, chain_id, hop_index,
                              address, private_key, public_key, dest, fp, sni, server_names,
                              cert_file, key_file, cert_pem, key_pem, cert_sha256, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (hop_name(chain_name, index), node["id"], hop["protocol"], hop["port"], hop["network"],
         hop["security"], chain_id, index, "", keys["private_key"], keys["public_key"], "", "", "", "",
         "", "", keys["cert_pem"], keys["key_pem"], keys["cert_sha256"], created_at),
    )
    return conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

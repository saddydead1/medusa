"""Хосты — то, что пользователь видит в подписке.

Хост цепочки здесь не выдумывается фронтендом: он создаётся вместе с цепочкой
и живёт в той же таблице, ссылаясь на неё (цепочка -> хост через chain_id).
"""
from __future__ import annotations

import base64
import sqlite3

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from fastapi import APIRouter, Depends

from src.core.xray_config import is_ip
from src.panel import config_push
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


def new_reality_keys() -> tuple[str, str]:
    """Пара x25519 для reality-хоста: приватный ключ едет в конфиг ноде,
    публичный — в ссылку подписки. Формат — base64url без дополнения, как у `xray x25519`."""
    private = X25519PrivateKey.generate()
    raw = lambda data: base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    return (raw(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
            raw(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)))


def as_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "node": row["node_name"],
        "address": row["address"],
        "protocol": row["protocol"],
        "port": row["port"],
        "network": row["network"],
        "security": row["security"],
        "chain": row["chain_id"],
        "chain_name": row["chain_name"],
        # публичный ключ reality не секрет: именно он нужен клиенту в ссылке;
        # приватного наружу никогда не отдаём
        "publicKey": row["public_key"],
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
    address = (body.address or "").strip()
    if body.security == "reality" and is_ip(address or node["address"]):
        raise bad_request("хосту reality нужен адрес-домен: клиент не умеет подставлять IP в SNI")
    private_key = public_key = ""
    if body.security == "reality":
        private_key, public_key = new_reality_keys()
    try:
        conn.execute(
            """INSERT INTO hosts (name, node_id, protocol, port, network, security, chain_id,
                                  address, private_key, public_key, created_at)
               VALUES (?,?,?,?,?,?,NULL,?,?,?,?)""",
            (body.name, node["id"], body.protocol, body.port, body.network, body.security,
             address, private_key, public_key, now_ms()),
        )
    except sqlite3.IntegrityError:
        raise conflict(f"порт {body.port} на ноде {body.node} уже занят")
    conn.commit()
    new_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    config_push.mark_dirty(conn, [node["id"]])
    config_push.schedule_push([node["id"]])
    return as_dict(fetch_one(conn, SELECT + " WHERE h.id = ?", (new_id,)))


@router.delete("/{host_id}", status_code=204)
def delete_host(
    host_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> None:
    row = fetch_one(conn, "SELECT chain_id, node_id FROM hosts WHERE id = ?", (host_id,))
    if row["chain_id"] is not None:
        raise conflict("хост цепочки удаляется вместе с цепочкой")
    conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
    conn.commit()
    config_push.mark_dirty(conn, [row["node_id"]])
    config_push.schedule_push([row["node_id"]])

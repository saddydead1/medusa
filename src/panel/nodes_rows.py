"""Как строка ноды превращается в ответ панели.

Здесь же единственное место, где API-ключ ноды превращается в masked-форму: список нод
не должен уносить ключи, а окну правки он нужен целиком — отдельным запросом.
"""
from __future__ import annotations

import sqlite3

from src.core.api_keys import api_key_fingerprint, mask_api_key

NODE_COLUMNS = ("id, name, address, online, xray_version, users_count, traffic_bytes, "
                "api_port, api_key, agent_version, seen_at")


def as_dict(row: sqlite3.Row) -> dict:
    api_key = row["api_key"]
    return {
        "id": row["id"],
        "name": row["name"],
        "address": row["address"],
        "online": bool(row["online"]),
        "xray": row["xray_version"],
        "users": row["users_count"],
        "traffic": row["traffic_bytes"],
        "apiPort": row["api_port"],
        "apiPath": "/node/health",
        "keySet": bool(api_key),
        "keyMasked": mask_api_key(api_key) if api_key else None,
        "fingerprint": api_key_fingerprint(api_key) if api_key else None,
        "agent": row["agent_version"],
        "seenAt": row["seen_at"] or None,
    }



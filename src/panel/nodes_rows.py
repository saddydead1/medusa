"""Как строка ноды превращается в ответ панели.

Здесь же единственное место, где API-ключ ноды превращается в masked-форму: список нод
не должен уносить ключи, а окну правки он нужен целиком — отдельным запросом.
"""
from __future__ import annotations

import sqlite3

from src.core.api_keys import api_key_fingerprint, mask_api_key
from src.panel.proxy_url import mask_proxy

# Сколько подписчиков эта нода обслуживает, считает сама панель: активному человеку на
# этой ноде должен быть куда подключаться — прямой хост или вход цепочки. Нода, которая
# несёт только транзит цепочек, подписчиков не обслуживает вовсе (но трафик несёт).
SERVED_USERS = ("(SELECT COUNT(*) FROM users u WHERE u.status = 'active' AND EXISTS "
                "(SELECT 1 FROM hosts h WHERE h.node_id = nodes.id "
                "AND (h.chain_id IS NULL OR h.hop_index = 0)))")

NODE_COLUMNS = ("id, name, address, online, xray_version, traffic_bytes, traffic_error, "
                "api_port, api_key, api_proxy, agent_version, seen_at, "
                "config_rev, config_dirty, applied_rev, applied_at, apply_error, "
                f"{SERVED_USERS} AS served_users")


def as_dict(row: sqlite3.Row) -> dict:
    api_key = row["api_key"]
    return {
        "id": row["id"],
        "name": row["name"],
        "address": row["address"],
        "online": bool(row["online"]),
        "xray": row["xray_version"],
        "users": int(row["served_users"]),
        "traffic": row["traffic_bytes"],
        # почему байтов нет или они не обновляются: нода обязана сказать это честно
        "trafficError": row["traffic_error"],
        "apiPort": row["api_port"],
        "apiPath": "/node/health",
        # socks5-прокси, через который панель доходит до этой ноды: в списке виден адрес
        # прокси, но не его пароль; целиком — отдельным запросом
        "proxy": mask_proxy(row["api_proxy"]),
        "proxySet": bool(row["api_proxy"]),
        "keySet": bool(api_key),
        "keyMasked": mask_api_key(api_key) if api_key else None,
        "fingerprint": api_key_fingerprint(api_key) if api_key else None,
        "agent": row["agent_version"],
        "seenAt": row["seen_at"] or None,
        # конфиг Xray: чего хочет панель и что нода подтвердила
        "configRev": row["config_rev"],
        "configDirty": bool(row["config_dirty"]),
        "appliedRev": row["applied_rev"],
        "appliedAt": row["applied_at"] or None,
        "applyError": row["apply_error"],
    }



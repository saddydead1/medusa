"""Доставка конфига Xray от панели к ноде.

Логика такая: любая правка, от которой зависит конфиг (хосты, пользователи), помечает
ноду грязной (`nodes.config_dirty`) и тут же запускает фоновую доставку: панель
собирает конфиг и отправляет его сама, человек об этом не думает. Опрос нод — страховка:
если доставка не удалась (нода молчала), при первой же успешной связи конфиг уедет снова.

Две детали, которые делают автодоставку спокойной:
* `config_hash` — отпечаток собранного конфига. Если после всех правок конфиг вышел
  тем же, что уже применён (добавил и убрал, отключил и включил), ноду не дёргаем;
* один глобальный замок: доставка одной ноды не идёт параллельно самой себе, иначе
  два потока перезапускали бы Xray наперегонки.

Ревизии: каждая настоящая отправка поднимает `config_rev`; подтверждённое нодой
возвращается в `applied_rev`. Для показа человеку, не для редактирования, конфиг
отдаёт `node_config_view`.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from typing import Any

from src.core.xray_config import cert_paths, render_node_config
from src.panel.db import DB_PATH, connect
from src.panel.nodes_client import NodeError, NodeTarget, node_apply

_PUSH_LOCK = threading.Lock()


def node_timeout(conn: sqlite3.Connection) -> float:
    row = conn.execute("SELECT nodeTimeout FROM settings WHERE id = 1").fetchone()
    return float(row[0]) if row else 10.0


def mark_dirty(conn: sqlite3.Connection, node_ids: list[int] | None = None) -> None:
    """Конфиг этих нод больше не актуален. Ноды без API-ключа не помечаются:
    отправить им всё равно нечем."""
    if node_ids:
        marks = ", ".join("?" for _ in node_ids)
        conn.execute(f"UPDATE nodes SET config_dirty = 1 WHERE api_key <> '' AND id IN ({marks})", node_ids)
    else:
        conn.execute("UPDATE nodes SET config_dirty = 1 WHERE api_key <> ''")
    conn.commit()


def schedule_push(node_ids: list[int] | None = None) -> None:
    """Фоновая доставка: правка хостов или пользователей не должна ждать опроса.

    Поток берёт своё соединение к базе: запросное соединение к моменту старта потока
    уже закрыто. Ничего страшного в сбое нет — строка ноды сохранит ошибку, а опрос
    повторит попытку при следующей успешной связи.
    """
    def run() -> None:
        conn: sqlite3.Connection | None = None
        try:
            conn = connect(DB_PATH)
            ids = node_ids if node_ids is not None else dirty_nodes(conn)
            for node_id in ids:
                push_node(conn, node_id)
        except Exception as err:  # noqa: BLE001 — автодоставка не роняет панель
            print(f"[medusa] автоприменение конфига не удалось: {err}", flush=True)
        finally:
            if conn is not None:
                conn.close()

    threading.Thread(target=run, name="medusa-config-push", daemon=True).start()


def dirty_nodes(conn: sqlite3.Connection) -> list[int]:
    return [int(r[0]) for r in conn.execute(
        "SELECT id FROM nodes WHERE config_dirty = 1 AND api_key <> '' ORDER BY name").fetchall()]


def collect(conn: sqlite3.Connection, node_id: int) -> dict[str, Any]:
    """Всё, из чего собирается конфиг одной ноды. Цепочки не участвуют: их хопа —
    про связь нод между собой, инбаундом для подписчика они пока не являются."""
    node = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
    if node is None:
        raise LookupError(f"ноды {node_id} уже нет")
    hosts = [dict(r) for r in conn.execute(
        """SELECT h.id, h.name, h.address, h.protocol, h.port, h.network, h.security,
                  h.private_key, h.public_key, n.address AS node_address
           FROM hosts h JOIN nodes n ON n.id = h.node_id
           WHERE h.node_id = ? AND h.chain_id IS NULL ORDER BY h.port""", (node_id,)).fetchall()]
    users = [dict(r) for r in conn.execute("SELECT name, token, status FROM users ORDER BY name").fetchall()]
    certs = []
    for host in hosts:
        if host["security"] != "tls":
            continue
        crt, key = cert_paths(host["id"])
        certs.append({"file": crt, "key": key, "host": host["address"] or node["address"]})
    return {"node": dict(node), "hosts": hosts, "users": users,
            "config": render_node_config(dict(node), hosts, users), "certs": certs}


def _digest(config: dict) -> str:
    return hashlib.sha256(json.dumps(config, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def push_node(conn: sqlite3.Connection, node_id: int) -> dict[str, Any]:
    """Собрать и отправить конфиг одной ноды. Никогда не бросает: отказ ноды
    возвращается отчётом и остаётся в строке ноды («ошибка применения»)."""
    with _PUSH_LOCK:
        data = collect(conn, node_id)
        node = data["node"]
        summary = {"nodeId": node_id, "hosts": len(data["hosts"]),
                   "clients": sum(1 for u in data["users"] if u["status"] == "active")}

        if not node["api_key"]:
            return {**summary, "ok": False, "revision": node["config_rev"],
                    "appliedRev": node["applied_rev"], "lastApplyAt": node["applied_at"] or None,
                    "error": "API-ключа для этой ноды в панели нет — отправить конфиг нечем"}

        digest = _digest(data["config"])
        if node["config_hash"] == digest and node["applied_rev"] == node["config_rev"]:
            # правки были, но по делу конфиг вышел прежним — ноду не трогаем
            conn.execute("UPDATE nodes SET config_dirty = 0, apply_error = NULL WHERE id = ?", (node_id,))
            conn.commit()
            return {**summary, "ok": True, "skipped": True, "revision": node["config_rev"],
                    "appliedRev": node["applied_rev"], "lastApplyAt": node["applied_at"] or None, "error": None}

        revision = node["config_rev"] + 1
        conn.execute("UPDATE nodes SET config_rev = ? WHERE id = ?", (revision, node_id))
        conn.commit()

        target = NodeTarget(node["address"], node["api_port"], node["api_key"])
        try:
            report = node_apply(target, revision, data["config"], data["certs"], node_timeout(conn))
        except NodeError as err:
            conn.execute("UPDATE nodes SET config_dirty = 1, apply_error = ? WHERE id = ?", (str(err), node_id))
            conn.commit()
            return {**summary, "ok": False, "skipped": False, "revision": revision,
                    "appliedRev": node["applied_rev"], "lastApplyAt": node["applied_at"] or None,
                    "error": str(err)}

        conn.execute(
            """UPDATE nodes SET config_dirty = ?, applied_rev = ?, applied_at = ?, apply_error = ?,
                      config_hash = ? WHERE id = ?""",
            (0 if report.ok else 1, report.appliedRev, report.lastApplyAt, report.error,
             digest if report.ok else node["config_hash"], node_id))
        conn.commit()
        return {**summary, "ok": report.ok, "skipped": False, "revision": report.desiredRev,
                "appliedRev": report.appliedRev, "lastApplyAt": report.lastApplyAt, "error": report.error}


def push_dirty(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Прогнать конфиг по всем грязным нодам (нужно для опроса: связь уже проверена)."""
    return [push_node(conn, node_id) for node_id in dirty_nodes(conn)]


def node_config_view(conn: sqlite3.Connection, node_id: int) -> dict[str, Any]:
    """Конфиг ноды для показа: человек видит, что панель собирается отправить,
    но не может это отредактировать. Приватные ключи здесь скрыты."""
    data = collect(conn, node_id)
    config = json.loads(json.dumps(data["config"]))
    for inbound in config.get("inbounds", []):
        reality = (inbound.get("streamSettings") or {}).get("realitySettings")
        if reality and reality.get("privateKey"):
            reality["privateKey"] = "скрыто панелью"
    node = data["node"]
    return {"config": config, "configRev": node["config_rev"], "appliedRev": node["applied_rev"],
            "applyError": node["apply_error"]}

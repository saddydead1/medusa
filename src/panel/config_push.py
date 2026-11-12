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


HOST_FIELDS = """h.id, h.name, h.address, h.protocol, h.port, h.network, h.security,
                  h.private_key, h.public_key, h.dest, h.fp, h.reject_unknown_sni,
                  h.sni, h.cert_file, h.key_file, h.server_names,
                  h.path, h.host_header, h.service_name, h.grpc_authority,
                  h.chain_id, h.hop_index, h.cert_pem, h.key_pem, h.cert_sha256"""


def cert_hint(host: dict) -> dict[str, str]:
    """Подсказка ноде о tls-сертификате этого инбаунда.

    Обычному хосту панель называет имя, под которое нода выпустит self-signed сама, и
    своё (пути к файлам, которые указал человек) не просит вовсе. Хопу цепочки панель
    привозит готовый сертификат и закрытый ключ: их выпустила панель, потому что отпечаток
    этого сертификата обязан знать соседний узел, идущий по этому хопу (Xray 26 принимает
    самоподписанный сертификат только по pinnedPeerCertSha256).
    """
    crt, key = cert_paths(host["id"])
    name = host["sni"] or host["address"] or host["node_address"]
    hint = {"file": crt, "key": key, "host": name}
    if host.get("cert_pem") and host.get("key_pem"):
        hint["certificate"], hint["privateKey"] = host["cert_pem"], host["key_pem"]
    return hint


def collect(conn: sqlite3.Connection, node_id: int) -> dict[str, Any]:
    """Всё, из чего собирается конфиг одной ноды.

    Хопа цепочки — тоже строки hosts, и инбаунд своего хопа нода получает наравне с
    обычными хостами. Отдельно отдаются сами цепочки, которые через эту ноду проходят:
    из их порядка рендер собирает переход (outbound) в следующий хоп и правило маршрута.
    """
    node = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
    if node is None:
        raise LookupError(f"ноды {node_id} уже нет")
    hosts = [dict(r) for r in conn.execute(
        f"""SELECT {HOST_FIELDS}, n.address AS node_address
            FROM hosts h JOIN nodes n ON n.id = h.node_id
            WHERE h.node_id = ? ORDER BY h.port""", (node_id,)).fetchall()]
    # id пользователя нужен рендеру: его метка (`u<id>`) живёт в конфиге как email клиента
    # и по ней же возвращается трафик конкретного человека
    users = [dict(r) for r in conn.execute("SELECT id, name, token, status FROM users ORDER BY name").fetchall()]

    chain_ids = [r["chain_id"] for r in conn.execute(
        "SELECT DISTINCT chain_id FROM hosts WHERE node_id = ? AND chain_id IS NOT NULL", (node_id,)).fetchall()]
    chains: list[dict[str, Any]] = []
    if chain_ids:
        marks = ", ".join("?" for _ in chain_ids)
        grouped: dict[int, dict[str, Any]] = {}
        for row in conn.execute(
                f"""SELECT {HOST_FIELDS}, n.address AS node_address, c.id AS chain_pk, c.name AS chain_name
                    FROM hosts h JOIN nodes n ON n.id = h.node_id JOIN chains c ON c.id = h.chain_id
                    WHERE h.chain_id IN ({marks}) ORDER BY h.chain_id, h.hop_index""", chain_ids).fetchall():
            chain = grouped.setdefault(row["chain_pk"], {"id": row["chain_pk"], "name": row["chain_name"],
                                                          "hops": []})
            chain["hops"].append(dict(row))
        chains = list(grouped.values())

    certs = [cert_hint(host) for host in hosts
             # свои файлы сертификатов ноде подсказывать не нужно: они уже лежат там, где их указали
             if host["security"] == "tls" and not (host["cert_file"] and host["key_file"])]
    return {"node": dict(node), "hosts": hosts, "users": users, "chains": chains,
            "config": render_node_config(dict(node), hosts, users, chains), "certs": certs}


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


# что в конфиге ноды является секретом: приватные ключи reality (у хоста и у перехода
# цепочки), пароли trojan/shadowsocks/vmess и ключи подписчиков, выведенные из токена
SECRET_KEYS = ("privateKey", "password")


def mask_secrets(config: dict) -> dict:
    """Скопировать конфиг и заменить в нём секреты: человек видит структуру,
    но не чужие ключи. Пути к сертификатам остаются — по ним понятно, что лежит на ноде."""
    shown = json.loads(json.dumps(config))

    def walk(node) -> None:
        if isinstance(node, dict):
            for key, value in list(node.items()):
                if key in SECRET_KEYS and isinstance(value, str) and value:
                    node[key] = "скрыто панелью"
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(shown)
    return shown


def node_config_view(conn: sqlite3.Connection, node_id: int) -> dict[str, Any]:
    """Конфиг ноды для показа: человек видит, что панель собирается отправить,
    но не может это отредактировать. Приватные ключи здесь скрыты."""
    data = collect(conn, node_id)
    # показываем то же, что уехало бы на ноду, но без приватных ключей и паролей:
    # и в инбаундах, и в переходах цепочек (у перехода свой пароль и свой x25519)
    config = mask_secrets(data["config"])
    node = data["node"]
    return {"config": config, "configRev": node["config_rev"], "appliedRev": node["applied_rev"],
            "applyError": node["apply_error"]}

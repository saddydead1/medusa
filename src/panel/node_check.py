"""Один поход панели к ноде — общий для кнопки «Проверить связь» и опроса по таймеру.

Логика одна и та же, и это не совпадение: опрос обязан показывать ровно то, что показала
бы ручная проверка, иначе «статус ноды» начал бы врать в зависимости от того, кто именно
его запросил.

Порядок такой: сначала витрина `/node/health` (она без API-ключа), потом `/node/identity`
с ключом. Так «нода не отвечает» не путается с «API-ключ не подходит» — это два разных
ответа, и панель различает их честно.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from src.core.api_keys import api_key_fingerprint
from src.panel import config_push
from src.panel.db import now_ms
from src.panel.node_traffic import apply_status
from src.panel.nodes_client import (NodeError, NodeTarget, node_health, node_identity,
                                    node_status)
from src.panel.nodes_rows import NODE_COLUMNS, as_dict

NO_KEY = "нода отвечает, но API-ключа для неё в панели нет"


def node_timeout(conn: sqlite3.Connection) -> float:
    row = conn.execute("SELECT nodeTimeout FROM settings WHERE id = 1").fetchone()
    return float(row[0]) if row else 10.0


def fetch_node(conn: sqlite3.Connection, node_id: int) -> sqlite3.Row:
    row = conn.execute(f"SELECT {NODE_COLUMNS} FROM nodes WHERE id = ?", (node_id,)).fetchone()
    if row is None:
        raise LookupError(f"ноды {node_id} уже нет")
    return row


def check_node(conn: sqlite3.Connection, node_id: int) -> dict[str, Any]:
    """Ходит на ноду, обновляет её строку и возвращает отчёт о связи.

    `ok` — связка полная: нода отвечает и API-ключ её. `reachable` — нода отвечает, даже
    когда ключ не подошёл. «В сети» бывает только `ok`: нода, которая отвечает чужому
    ключу, для панели бесполезна.
    """
    row = fetch_node(conn, node_id)
    timeout = node_timeout(conn)
    target = NodeTarget(row["address"], row["api_port"], row["api_key"])
    checked_at = now_ms()
    report: dict[str, Any] = {
        "ok": False, "reachable": False, "keyOk": False, "online": False,
        "panelFingerprint": api_key_fingerprint(target.api_key) if target.api_key else None,
        "node": None, "error": None, "checkedAt": checked_at,
    }

    try:
        hello = node_health(target, timeout)
    except NodeError as err:
        report["error"] = str(err)
    else:
        report["reachable"] = True
        report["node"] = {
            "role": hello.role, "fingerprint": hello.fingerprint,
            "agentVersion": hello.agentVersion, "apiVersion": hello.apiVersion,
            "uptimeMs": hello.uptimeMs, "xrayVersion": None,
        }
        if not target.configured:
            report["error"] = NO_KEY
        else:
            try:
                identity = node_identity(target, timeout)
            except NodeError as err:
                report["error"] = str(err)
            else:
                report["keyOk"] = identity.fingerprint == hello.fingerprint
                report["ok"] = report["keyOk"]
                report["online"] = report["keyOk"]
                report["node"].update({
                    "role": identity.role, "agentVersion": identity.agentVersion,
                    "apiVersion": identity.apiVersion, "xrayVersion": identity.xrayVersion,
                    "uptimeMs": identity.uptimeMs,
                })
                if not report["keyOk"]:
                    report["error"] = (f"нода называет отпечаток {identity.fingerprint}, "
                                       f"а у панели {report['panelFingerprint']}: API-ключ разный")

    store_report(conn, node_id, report)
    # связь есть и конфиг помечен несвежим — доставим его сразу, этот поход уже удался
    # и второй раз стучаться незачем
    if report["ok"] and row["config_dirty"]:
        report["apply"] = config_push.push_node(conn, node_id)
    if report["ok"]:
        # трафик читается после применения: свежий конфиг перезапустил Xray, и его
        # счётчики现在开始 с нуля — читать их до применения значит потерять байты
        report["traffic"] = read_traffic(conn, node_id, target, timeout)
    report["node_row"] = as_dict(fetch_node(conn, node_id))
    return report


def read_traffic(conn: sqlite3.Connection, node_id: int, target: NodeTarget,
                 timeout: float) -> dict[str, object]:
    """Счётчики трафика этой ноды. Их отдаёт `/node/status` — другого пути нет.

    Отказ чтения не обнуляет прежние цифры: байты были настоящими, а причина, по которой
    нода молчит сейчас, записывается отдельно (`nodes.traffic_error`) и видна человеку.
    """
    try:
        status = node_status(target, timeout)
    except NodeError as err:
        conn.execute("UPDATE nodes SET traffic_error = ? WHERE id = ?", (str(err), node_id))
        conn.commit()
        return {"bytes": None, "labels": 0, "at": None, "error": str(err)}
    summary = apply_status(conn, node_id, status)
    # беда самой ноды — её Xray умер (порт занят чужим слушателем, конфиг плохой, прав на
    # порт не хватило) — важнее всего, что панель знает о применении конфига: показывать её
    # надо в строке ноды, а не прятать за словом «применено». Когда нода отвечает чисто и
    # её применённая ревизия совпадает с желаемой, прежнюю ошибку снимаем.
    node_error = getattr(status, "lastError", None)
    if node_error:
        conn.execute("UPDATE nodes SET apply_error = ? WHERE id = ?", (node_error, node_id))
    else:
        conn.execute("""UPDATE nodes SET apply_error = NULL WHERE id = ?
                        AND config_dirty = 0 AND applied_rev = config_rev""", (node_id,))
    conn.commit()
    return summary


def store_report(conn: sqlite3.Connection, node_id: int, report: dict[str, Any]) -> None:
    """Записывает то, что нода сообщила про себя.

    Версии не должны исчезать из-за одного неудачного похода: если нода про Xray ничего
    не сказала, прежняя версия остаётся. `seen_at` двигается только когда нода правда
    отвечала — иначе «время последней встречи» станет враньем.
    """
    info = report["node"] or {}
    conn.execute(
        """UPDATE nodes
               SET online = ?,
                   agent_version = ?,
                   xray_version = COALESCE(?, xray_version),
                   seen_at = CASE WHEN ? THEN ? ELSE seen_at END
             WHERE id = ?""",
        (int(report["online"]), info.get("agentVersion"), info.get("xrayVersion"),
         int(report["reachable"]), report["checkedAt"], node_id),
    )
    conn.commit()

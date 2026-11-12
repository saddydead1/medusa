"""Как трафик ноды превращается в цифры панели.

Нода сообщает два числа одного рода: сколько она провела всего (`trafficBytes`) и сколько
по каждой метке Xray (`u<id>` подписчика или `hop<цепочка>-<номер>`). Панель хранит это
строками в `node_traffic` — по одной на пару (нода, метка), накопленными, как их сообщает
сама нода. Отсюда два честных правила:

* трафик человека — сумма по всем нодам, которые его обслуживают (на каждой ноде свои
  байты, складывать негде и незачем);
* трафик перехода цепочки остаётся трафиком ноды: он настоящий, но ни одному человеку не
  приписывается — человек прошёл через цепочку один раз, а посчитали его все ноды маршрута.

Метку придумывает панель (`src/core/xray_config.user_email`), поэтому обратный ход
`u<id> -> пользователь` для неё не загадка. Метку, которую панель не узнаёт, она честно
оставляет нераспознанной: выдумывать подписчика из чужой строки панель не будет.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from src.core.contract import NodeStatus
from src.core.xray_config import user_id_of_email
from src.panel.db import now_ms

USER_TRAFFIC_SQL = """SELECT COALESCE(SUM(bytes), 0) FROM node_traffic WHERE user_id = ?"""


def user_traffic_total(conn: sqlite3.Connection, user_id: int) -> int:
    """Сколько человек потратил по всем нодам панели."""
    return int(conn.execute(USER_TRAFFIC_SQL, (user_id,)).fetchone()[0])


def _resolve_user(conn: sqlite3.Connection, email: str) -> int | None:
    """Кому принадлежит метка. Не подписьчик (хоп цепочки) или чужая строка — None."""
    user_id = user_id_of_email(email)
    if user_id is None:
        return None
    row = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
    return int(row["id"]) if row else None


def apply_status(conn: sqlite3.Connection, node_id: int, status: NodeStatus) -> dict[str, Any]:
    """Записывает то, что нода насчитала.

    Значения накопленные и абсолютные: повтор того же отчёта ничего не удваивает, поэтому
    кнопка «Проверить связь» и фоновый опрос могут приходить сколько угодно раз.
    Метку, о которой нода перестала рассказывать (человека удалили, ноду пересобрали),
    панель убирает — иначе по ней остался бы计数, который никто не подтверждает.
    """
    moment = status.statsAt or now_ms()
    reported: list[str] = []
    for item in status.userTraffic:
        email = str(item.email)
        if not email:
            continue
        reported.append(email)
        conn.execute(
            """INSERT INTO node_traffic (node_id, email, user_id, bytes, updated_at)
               VALUES (?,?,?,?,?)
               ON CONFLICT (node_id, email) DO UPDATE
                 SET user_id = excluded.user_id, bytes = excluded.bytes, updated_at = excluded.updated_at""",
            (node_id, email, _resolve_user(conn, email), int(item.bytes), moment),
        )
    if reported:
        marks = ", ".join("?" for _ in reported)
        conn.execute(f"DELETE FROM node_traffic WHERE node_id = ? AND email NOT IN ({marks})",
                     (node_id, *reported))
    else:
        # нода не назвала ни одной метки: либо хостов нет, либо счётчики не считались.
        # Прежние строки панель сохраняет только когда счётчики сломаны (байты-то были
        # настоящие); пустой отчёт без ошибки означает, что трафика нет вовсе.
        if status.statsError is None:
            conn.execute("DELETE FROM node_traffic WHERE node_id = ?", (node_id,))
    conn.execute("UPDATE nodes SET traffic_bytes = ?, traffic_error = ? WHERE id = ?",
                 (int(status.trafficBytes), status.statsError, node_id))
    conn.commit()
    return {"bytes": int(status.trafficBytes), "labels": len(reported),
            "at": moment, "error": status.statsError}

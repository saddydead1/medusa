"""Опрос нод по таймеру.

Кнопка «Проверить связь» в окне ноды — ручная проверка. Но статус должен быть свежим и
без кликов: панель ходит к каждой ноде сама, с интервалом из настроек
(`settings.pollInterval`, секунд), и обновляет в базе «в сети», версию агента, версию
Xray и время последней встречи.

Здесь есть два правила, которые важнее самой экономии запросов:

* ноду без API-ключа панель не спрашивает — без ключа она увидела бы только «что-то
  отвечает», а это не статус ноды;
* опрос делает ровно тот же поход, что и ручная проверка (`src/panel/node_check.py`):
  статус не должен зависеть от того, кто именно его запросил.

Опрос можно выключить совсем (`MEDUSA_NODE_AUTO=0`) — например когда панель стоит на
машине, которой физически нечем ходить наружу.
"""
from __future__ import annotations

import asyncio
import os
import sqlite3
from typing import Any

from src.panel.db import DB_PATH, connect
from src.panel.node_check import check_node

ENV_FLAG = "MEDUSA_NODE_AUTO"
MIN_INTERVAL = 5


def enabled() -> bool:
    """Опрос включён по умолчанию; `MEDUSA_NODE_AUTO=0` — выключен."""
    return os.getenv(ENV_FLAG, "1").strip().lower() not in {"0", "off", "no", "false"}


def poll_interval(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT pollInterval FROM settings WHERE id = 1").fetchone()
    return max(MIN_INTERVAL, int(row[0])) if row else 60


def current_interval() -> int:
    """Интервал из настроек панели. База на мгновение недоступна — не повод падать:
    берём обычный 60 и пробуем в следующий раз."""
    conn = None
    try:
        conn = connect(DB_PATH)
        return poll_interval(conn)
    except Exception:
        return 60
    finally:
        if conn is not None:
            conn.close()


def pollable(conn: sqlite3.Connection) -> list[int]:
    """Идентификаторы нод, которых есть смысл спрашивать: только с API-ключом."""
    rows = conn.execute("SELECT id FROM nodes WHERE api_key <> '' ORDER BY name").fetchall()
    return [int(r[0]) for r in rows]   # индексом, а не по имени: так работает и с сырым sqlite3-соединением


def poll_once(conn: sqlite3.Connection | None = None,
              node_ids: list[int] | None = None) -> list[dict[str, Any]]:
    """Обход нод с API-ключом. Отчёт по каждой — как от ручной проверки.

    `node_ids` нужен тестам: они проверяют одну ноду, а не бегают по всему списку."""
    own = conn is None
    if own:
        conn = connect(DB_PATH)
    try:
        return [check_node(conn, node_id) for node_id in (node_ids if node_ids is not None else pollable(conn))]
    finally:
        if own:
            conn.close()


def summarize(report: list[dict[str, Any]]) -> str | None:
    """Строка в лог: опрос обычно молчит, и это правильно. Пишем только о неполадках."""
    silent = [x["node_row"]["name"] for x in report if not x["reachable"]]
    wrong = [x["node_row"]["name"] for x in report if x["reachable"] and not x["keyOk"]]
    if not silent and not wrong:
        return None
    return (f"[medusa] опрос нод: не отвечают {silent or '—'}, не тот API-ключ {wrong or '—'}")


async def poll_loop(stop: asyncio.Event) -> None:
    """Цикл опроса. Интервал перечитывается каждый круг — смена настройки действует без
    перезапуска панели. Сам поход к ноде блокирующий, поэтому он в threadpool."""
    while not stop.is_set():
        # сначала ждём, потом идём: панель только поднялась — спешить некуда, зато
        # остановка не упирается в незавершённый обход нод
        if await wait_or_stop(stop):
            return
        try:
            found = await asyncio.to_thread(poll_once)
        except Exception as err:  # опрос не должен ронять панель
            print(f"[medusa] опрос нод сорвался: {err}", flush=True)
        else:
            line = summarize(found)
            if line:
                print(line, flush=True)


async def wait_or_stop(stop: asyncio.Event) -> bool:
    """Ждёт, пока не пройдёт интервал из настроек, и по дороге следит за самим интервалом.

    Спит короткими кусками: если администратор уменьшил «Опрос нод», панель начнёт
    опрашивать чаще уже в следующем куске, а не после долгого сна, заснутого старым
    значением. `True` — пора сворачиваться.
    """
    waited = 0.0
    while True:
        interval = current_interval()
        piece = min(1.0, max(0.0, interval - waited))
        if piece <= 0:
            return False
        try:
            await asyncio.wait_for(stop.wait(), timeout=piece)
        except TimeoutError:
            waited += piece
        else:
            return True

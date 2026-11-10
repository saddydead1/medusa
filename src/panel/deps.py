"""Общие зависимости API: соединение, текущий администратор, права и мелкие хелперы.

Три уровня допуска:
* `current_admin` — просто кто-то вошёл (можно смотреть);
* `writer` — владелец или администратор (можно менять);
* `owner_only` — только владелец (разбирается с чужими аккаунтами).

Роли в панели две: владелец и администратор. Администратор меняет панель,
но не трогает чужие аккаунты — только свою (пароль и ключи).
"""
from __future__ import annotations

import os
import sqlite3

from fastapi import Depends, Header, HTTPException

from src.panel.db import get_conn, now_ms

WRITE_ROLES = ("owner", "admin")


def auth_required() -> bool:
    """Вход нужен по умолчанию. `MEDUSA_AUTH=0` открывает API целиком — только для
    разработки на своей машине: панель без учётки может менять кто угодно."""
    return os.getenv("MEDUSA_AUTH", "1").strip().lower() not in {"0", "off", "no", "false"}


def actor(
    conn: sqlite3.Connection = Depends(get_conn),
    authorization: str | None = Header(default=None),
) -> sqlite3.Row | None:
    """Текущий администратор по токену, если он есть; сессию не проверяет."""
    from src.panel.db import admin_by_token

    token = authorization.removeprefix("Bearer ").strip() if authorization else None
    return admin_by_token(conn, token)


def bearer_token(authorization: str | None = Header(default=None)) -> str | None:
    token = (authorization or "").removeprefix("Bearer ").strip()
    return token or None


def current_session(conn: sqlite3.Connection = Depends(get_conn),
                    token: str | None = Depends(bearer_token)) -> sqlite3.Row | None:
    """Сессия, которой пришёл запрос: именно её срок показывать в UI, а не «самую долгую»."""
    if not token:
        return None
    from src.panel.db import now_ms
    return conn.execute("SELECT * FROM sessions WHERE token = ? AND expires_at > ?",
                        (token, now_ms())).fetchone()


def current_admin(current: sqlite3.Row | None = Depends(actor)) -> sqlite3.Row | None:
    """Смотреть панель может только вошедший: без сессии — 401, фронт покажет окно входа."""
    if current is None and auth_required():
        raise HTTPException(status_code=401, detail="нужна сессия: войдите в панель")
    return current


def writer(current: sqlite3.Row | None = Depends(current_admin)) -> sqlite3.Row | None:
    """Менять панель могут владелец и администратор."""
    if current is None:
        return None                       # MEDUSA_AUTH=0: правка без учётки, разработка
    if current["role"] not in WRITE_ROLES:
        raise HTTPException(status_code=403, detail="правка доступна только владельцу и администратору")
    return current


def owner_only(current: sqlite3.Row | None = Depends(writer)) -> sqlite3.Row | None:
    """Чужими аккаунтами распоряжается только владелец: заводить людей, менять роли,
    отключать, менять пароли и записывать ключи. Администратору доступна только его
    собственная учётка (проверяется в самом роутере)."""
    if current is not None and current["role"] != "owner":
        raise HTTPException(status_code=403, detail="это умеет только владелец панели")
    return current


def fetch_one(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> sqlite3.Row:
    row = conn.execute(sql, params).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="не найдено")
    return row


def conflict(message: str) -> HTTPException:
    return HTTPException(status_code=409, detail=message)


def bad_request(message: str) -> HTTPException:
    return HTTPException(status_code=400, detail=message)


def node_by_name(conn: sqlite3.Connection, name: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM nodes WHERE name = ?", (name,)).fetchone()
    if row is None:
        raise bad_request(f"ноды «{name}» нет")
    return row

"""Администраторы панели, вход (пароль и аппаратный ключ) и сессии.

Роли и кто чем распоряжается:

* `owner` — владелец: создаётся вместе с панелью, единственный такой. Его нельзя
  отключить, удалить или сменить ему роль; пароль меняет только он сам.
* `admin` — администратор: может всё в панели (ноды, хосты, цепочки, пользователи,
  настройки), но не трогает чужие аккаунты. Своей учёткой — да: свой пароль, свои ключи.

Заводит, удаляет, отключает людей только владелец. Новая учётка всегда администратор:
роли в панели больше никто не выбирает.
"""
from __future__ import annotations

import sqlite3
from fastapi import APIRouter, Depends, HTTPException, Request

from src.panel import fido2
from src.panel.db import create_session, get_conn, now_ms
from src.panel.deps import actor, bad_request, conflict, current_admin, current_session, fetch_one, writer
from src.panel.schemas import AdminCreate, AdminPatch, FidoBegin, FidoKeyAdd, FidoLogin, Login
from src.panel.security import hash_password, verify_password

router = APIRouter(prefix="/api/admins", tags=["admins"])
auth_router = APIRouter(tags=["auth"])

MANAGE_ROLES = ("owner", "admin")


def as_dict(row: sqlite3.Row, current: sqlite3.Row | None, keys: int, sessions: int) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "status": row["status"],
        "last": row["last_login"],
        "keys": keys,
        "sessions": sessions,
        "self": bool(current and current["id"] == row["id"]),
    }


def session_hours(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT sessionHours FROM settings WHERE id = 1").fetchone()
    return int(row["sessionHours"]) if row else 72


def require_passkey(conn: sqlite3.Connection) -> None:
    if not fido2.passkey_enabled(conn):
        raise conflict("вход по аппаратному ключу выключен в настройках панели")


def can_manage(current: sqlite3.Row | None) -> bool:
    """Разбирается с аккаунтами только владелец (в режиме разработки без учётки — да)."""
    return current is None or current["role"] == "owner"


def account_guard(current: sqlite3.Row | None, row: sqlite3.Row, what: str) -> None:
    """Кому можно трогать этот аккаунт: владельцу — любой, администратору — только свой."""
    if current is None:
        return
    if current["role"] == "owner":
        return
    if current["id"] == row["id"]:
        return
    raise HTTPException(status_code=403, detail=f"администратору доступно только своё: {what}")


# ------------------------------------------------------------------ вход по паролю

@auth_router.post("/api/login")
def login(body: Login, conn: sqlite3.Connection = Depends(get_conn)) -> dict:
    row = conn.execute("SELECT * FROM admins WHERE username = ?", (body.username,)).fetchone()
    if row is None or not verify_password(body.password, row["password_hash"]):
        raise bad_request("неверный логин или пароль")
    if row["status"] != "active":
        raise conflict("администратор отключён")
    token = create_session(conn, row["id"], session_hours(conn))
    conn.execute("UPDATE admins SET last_login = ? WHERE id = ?", (now_ms(), row["id"]))
    conn.commit()
    return {"token": token, "admin": {"id": row["id"], "username": row["username"], "role": row["role"]}}


# ------------------------------------------------------------------ вход по аппаратному ключу

@auth_router.post("/api/fido/begin")
def fido_begin(body: FidoBegin, request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> dict:
    """Вызов входа. Имя можно не указывать: тогда браузер сам выбирает, каким ключом войти.

    Имя нужно, когда у панели много ключей и человек хочет сузить список до своих.
    """
    require_passkey(conn)
    names = [body.username] if body.username else None
    return {"options": fido2.assertion_options(conn, request, names)}


@auth_router.post("/api/fido/login")
def fido_login(body: FidoLogin, request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> dict:
    require_passkey(conn)
    try:
        done = fido2.verify_assertion(conn, body.response, request)
    except fido2.FidoError as err:
        raise HTTPException(status_code=401, detail=str(err)) from None
    admin = done["admin"]
    token = create_session(conn, admin["id"], session_hours(conn))
    conn.execute("UPDATE admins SET last_login = ? WHERE id = ?", (now_ms(), admin["id"]))
    conn.commit()
    return {"token": token,
            "admin": {"id": admin["id"], "username": admin["username"], "role": admin["role"]},
            "key": done["key"]}


# ------------------------------------------------------------------ сессия

@auth_router.get("/api/me")
def me(conn: sqlite3.Connection = Depends(get_conn),
       current: sqlite3.Row | None = Depends(actor),
       record: sqlite3.Row | None = Depends(current_session)) -> dict:
    if current is None or record is None:
        raise HTTPException(status_code=401, detail="сессии нет")
    return {"id": current["id"], "username": current["username"], "role": current["role"],
            "expiresAt": record["expires_at"] if record else None,
            "sessions": conn.execute("SELECT COUNT(*) FROM sessions WHERE admin_id = ?",
                                     (current["id"],)).fetchone()[0]}


@auth_router.post("/api/logout")
def logout(conn: sqlite3.Connection = Depends(get_conn),
           current: sqlite3.Row | None = Depends(actor)) -> dict:
    """Выход: сессия удаляется сразу, а не «истечёт потом». Все входы этого администратора."""
    if current is not None:
        conn.execute("DELETE FROM sessions WHERE admin_id = ?", (current["id"],))
        conn.commit()
    return {"ok": True}


# ------------------------------------------------------------------ список и права

@router.get("")
def list_admins(
    conn: sqlite3.Connection = Depends(get_conn),
    current: sqlite3.Row | None = Depends(current_admin),
) -> list[dict]:
    rows = conn.execute("""SELECT a.*,
                                  (SELECT COUNT(*) FROM sessions s WHERE s.admin_id = a.id) sessions,
                                  (SELECT COUNT(*) FROM admin_keys k WHERE k.admin_id = a.id) keys
                           FROM admins a
                           ORDER BY CASE role WHEN 'owner' THEN 0 ELSE 1 END, username""").fetchall()
    return [as_dict(r, current, r["keys"], r["sessions"]) for r in rows]


@router.post("", status_code=201)
def create_admin(
    body: AdminCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    current: sqlite3.Row | None = Depends(writer),
) -> dict:
    """Новых людей в панель заводит только владелец: администратор не вправе сам плодить
    себе равных. Новая учётка всегда администратор — роль не выбирается."""
    if not can_manage(current):
        raise HTTPException(status_code=403, detail="новых администраторов создаёт только владелец панели")
    try:
        conn.execute(
            "INSERT INTO admins (username, password_hash, role, status, last_login, created_at) VALUES (?,?,'admin','active',0,?)",
            (body.username, hash_password(body.password), now_ms()),
        )
    except sqlite3.IntegrityError:
        raise conflict(f"администратор «{body.username}» уже есть")
    conn.commit()
    row = fetch_one(conn, "SELECT * FROM admins WHERE username = ?", (body.username,))
    return as_dict(row, current, 0, 0)


@router.patch("/{admin_id}")
def patch_admin(
    admin_id: int,
    body: AdminPatch,
    conn: sqlite3.Connection = Depends(get_conn),
    current: sqlite3.Row | None = Depends(writer),
) -> dict:
    row = fetch_one(conn, "SELECT * FROM admins WHERE id = ?", (admin_id,))
    account_guard(current, row, "этот аккаунт")

    if body.status is not None:
        if not can_manage(current):
            raise HTTPException(status_code=403, detail="отключает и включает администраторов только владелец")
        if row["role"] == "owner":
            raise conflict("владельца нельзя отключить: панель без владельца не остаётся")
        if current is not None and current["id"] == admin_id:
            raise conflict("нельзя отключить самого себя")
    if body.password:
        if current is None or admin_id != current["id"]:
            raise HTTPException(status_code=409,
                                detail="пароль меняет только владелец аккаунта: чужой пароль не меняется")

    changes = {k: v for k, v in body.model_dump().items() if v is not None and k != "password"}
    if body.password:
        changes["password_hash"] = hash_password(body.password)
    if changes:
        sets = ", ".join(f"{k} = ?" for k in changes)
        conn.execute(f"UPDATE admins SET {sets} WHERE id = ?", (*changes.values(), admin_id))
        own_password = bool(body.password) and current is not None and current["id"] == admin_id
        if body.status == "disabled" or (body.password and not own_password):
            conn.execute("DELETE FROM sessions WHERE admin_id = ?", (admin_id,))
        conn.commit()
    return as_admin(conn, fetch_one(conn, "SELECT * FROM admins WHERE id = ?", (admin_id,)), current)


@router.delete("/{admin_id}", status_code=204)
def delete_admin(
    admin_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    current: sqlite3.Row | None = Depends(writer),
) -> None:
    row = fetch_one(conn, "SELECT * FROM admins WHERE id = ?", (admin_id,))
    if row["role"] == "owner":
        raise conflict("владельца удалить нельзя")
    if not can_manage(current):
        raise HTTPException(status_code=403, detail="удаляет администраторов только владелец панели")
    if current is not None and current["id"] == admin_id:
        raise conflict("нельзя удалить самого себя")
    conn.execute("DELETE FROM admins WHERE id = ?", (admin_id,))
    conn.commit()


def as_admin(conn: sqlite3.Connection, row: sqlite3.Row, current: sqlite3.Row | None) -> dict:
    keys = conn.execute("SELECT COUNT(*) FROM admin_keys WHERE admin_id = ?", (row["id"],)).fetchone()[0]
    sessions = conn.execute("SELECT COUNT(*) FROM sessions WHERE admin_id = ?", (row["id"],)).fetchone()[0]
    return as_dict(row, current, keys, sessions)


# ------------------------------------------------------------------ аппаратные ключи

@router.get("/{admin_id}/keys")
def list_keys(
    admin_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(current_admin),
) -> list[dict]:
    fetch_one(conn, "SELECT id FROM admins WHERE id = ?", (admin_id,))
    rows = conn.execute("SELECT * FROM admin_keys WHERE admin_id = ? ORDER BY created_at", (admin_id,)).fetchall()
    return [fido2.key_info(r) for r in rows]


# Ключи учётки: свою может вести всякий вошедший (роль от этого не меняется —
# ключ лишь способ входа), чужие доступны только владельцу панели.
@router.post("/{admin_id}/keys/begin")
def begin_key(
    admin_id: int,
    request: Request,
    conn: sqlite3.Connection = Depends(get_conn),
    current: sqlite3.Row | None = Depends(current_admin),
) -> dict:
    row = fetch_one(conn, "SELECT * FROM admins WHERE id = ?", (admin_id,))
    account_guard(current, row, "записывать ключи")
    require_passkey(conn)
    return {"options": fido2.registration_options(conn, row, request)}


@router.post("/{admin_id}/keys", status_code=201)
def add_key(
    admin_id: int,
    body: FidoKeyAdd,
    request: Request,
    conn: sqlite3.Connection = Depends(get_conn),
    current: sqlite3.Row | None = Depends(current_admin),
) -> dict:
    row = fetch_one(conn, "SELECT * FROM admins WHERE id = ?", (admin_id,))
    account_guard(current, row, "записывать ключи")
    require_passkey(conn)
    try:
        return fido2.verify_registration(conn, admin_id, body.response, request, body.nickname or "")
    except fido2.FidoError as err:
        raise bad_request(str(err)) from None


@router.delete("/{admin_id}/keys/{key_id}", status_code=204)
def remove_key(
    admin_id: int,
    key_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    current: sqlite3.Row | None = Depends(current_admin),
) -> None:
    row = fetch_one(conn, "SELECT * FROM admins WHERE id = ?", (admin_id,))
    account_guard(current, row, "снимать ключи")
    if conn.execute("DELETE FROM admin_keys WHERE id = ? AND admin_id = ?", (key_id, admin_id)).rowcount == 0:
        raise HTTPException(status_code=404, detail="такого ключа у этого администратора нет")
    conn.commit()

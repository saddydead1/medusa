"""Пользователи панели (они же email в Xray, когда займёмся VPN-логикой)."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException

from src.panel import config_push
from src.panel.db import get_conn, now_ms
from src.panel.node_traffic import user_traffic_total
from src.panel.deps import bad_request, conflict, fetch_one, writer
from src.panel.schemas import UserCreate, UserPatch
from src.panel.security import new_user_token

router = APIRouter(prefix="/api/users", tags=["users"])


def as_dict(row: sqlite3.Row, conn: sqlite3.Connection) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "token": row["token"],
        "status": row["status"],
        "used": user_traffic_total(conn, int(row["id"])),
        "client": row["client"],
    }


@router.get("")
def list_users(conn: sqlite3.Connection = Depends(get_conn)) -> list[dict]:
    rows = conn.execute("SELECT * FROM users ORDER BY name").fetchall()
    # `used` не хранится в таблице людей: это сумма того, что насчитала каждая нода
    return [as_dict(r, conn) for r in rows]


@router.post("", status_code=201)
def create_user(
    body: UserCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    try:
        conn.execute(
            "INSERT INTO users (name, token, status, client, created_at) VALUES (?,?,?,?,?)",
            (body.name, new_user_token(), "active", body.client, now_ms()),
        )
    except sqlite3.IntegrityError:
        raise conflict(f"пользователь «{body.name}» уже есть")
    conn.commit()
    config_push.mark_dirty(conn)      # список клиентов есть в конфиге каждой ноды
    config_push.schedule_push()
    return as_dict(fetch_one(conn, "SELECT * FROM users WHERE name = ?", (body.name,)), conn)


@router.patch("/{user_id}")
def patch_user(
    user_id: int,
    body: UserPatch,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    fetch_one(conn, "SELECT id FROM users WHERE id = ?", (user_id,))
    changes = {k: v for k, v in body.model_dump().items() if v is not None}
    # пустая строка в client — явное «приложения не названо»: None здесь означает
    # «поле не принесли», и без этого разбора приложение нельзя было бы снять
    if changes.get("client") == "":
        changes["client"] = None
    if not changes:
        raise HTTPException(status_code=400, detail="нечего менять")
    fields = {"status": "status", "client": "client", "name": "name"}
    sets = ", ".join(f"{fields[k]} = ?" for k in changes)
    conn.execute(f"UPDATE users SET {sets} WHERE id = ?", (*changes.values(), user_id))
    conn.commit()
    config_push.mark_dirty(conn)      # пользователь появился/исчез/отключился — конфиги устарели
    config_push.schedule_push()
    return as_dict(fetch_one(conn, "SELECT * FROM users WHERE id = ?", (user_id,)), conn)


@router.delete("/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> None:
    fetch_one(conn, "SELECT id FROM users WHERE id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    config_push.mark_dirty(conn)
    config_push.schedule_push()

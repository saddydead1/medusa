"""Пользователи панели (они же email в Xray, когда займёмся VPN-логикой)."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException

from src.panel.db import get_conn, now_ms
from src.panel.deps import bad_request, conflict, fetch_one, writer
from src.panel.schemas import UserCreate, UserPatch
from src.panel.security import new_user_token

router = APIRouter(prefix="/api/users", tags=["users"])


def as_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "token": row["token"],
        "status": row["status"],
        "used": row["used_bytes"],
        "client": row["client"],
    }


@router.get("")
def list_users(conn: sqlite3.Connection = Depends(get_conn)) -> list[dict]:
    rows = conn.execute("SELECT * FROM users ORDER BY name").fetchall()
    return [as_dict(r) for r in rows]


@router.post("", status_code=201)
def create_user(
    body: UserCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    try:
        conn.execute(
            "INSERT INTO users (name, token, status, used_bytes, client, created_at) VALUES (?,?,?,?,?,?)",
            (body.name, new_user_token(), "active", 0, body.client, now_ms()),
        )
    except sqlite3.IntegrityError:
        raise conflict(f"пользователь «{body.name}» уже есть")
    conn.commit()
    return as_dict(fetch_one(conn, "SELECT * FROM users WHERE name = ?", (body.name,)))


@router.patch("/{user_id}")
def patch_user(
    user_id: int,
    body: UserPatch,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    fetch_one(conn, "SELECT id FROM users WHERE id = ?", (user_id,))
    changes = {k: v for k, v in body.model_dump().items() if v is not None}
    if not changes:
        raise HTTPException(status_code=400, detail="нечего менять")
    fields = {"status": "status", "client": "client", "name": "name"}
    sets = ", ".join(f"{fields[k]} = ?" for k in changes)
    conn.execute(f"UPDATE users SET {sets} WHERE id = ?", (*changes.values(), user_id))
    conn.commit()
    return as_dict(fetch_one(conn, "SELECT * FROM users WHERE id = ?", (user_id,)))


@router.delete("/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> None:
    fetch_one(conn, "SELECT id FROM users WHERE id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()

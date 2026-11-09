"""Настройки панели: одна строка в таблице settings, ключи — как во фронтенде."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends

from src.panel.db import get_conn
from src.panel.deps import bad_request, conflict, current_admin, fetch_one, writer
from src.panel.schemas import SettingsPatch

router = APIRouter(prefix="/api/settings", tags=["settings"])

FIELDS = ("panelName", "theme", "subUrl", "subTitle", "subInterval", "pollInterval", "nodeTimeout",
          "sessionHours", "passkeyEnabled")


def as_dict(row: sqlite3.Row) -> dict:
    values = {key: row[key] for key in FIELDS}
    values["passkeyEnabled"] = bool(values["passkeyEnabled"])   # настройка-выключатель наружу честным bool
    return values


@router.get("")
def get_settings(conn: sqlite3.Connection = Depends(get_conn)) -> dict:
    conn.execute("INSERT OR IGNORE INTO settings (id) VALUES (1)")
    conn.commit()
    return as_dict(conn.execute("SELECT * FROM settings WHERE id = 1").fetchone())


@router.patch("")
def patch_settings(
    body: SettingsPatch,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    changes = {k: v for k, v in body.model_dump().items() if v is not None}
    if "passkeyEnabled" in changes:
        changes["passkeyEnabled"] = 1 if changes["passkeyEnabled"] else 0
    if changes:
        sets = ", ".join(f"{k} = ?" for k in changes)
        conn.execute(f"UPDATE settings SET {sets} WHERE id = 1", tuple(changes.values()))
        conn.commit()
    return as_dict(conn.execute("SELECT * FROM settings WHERE id = 1").fetchone())

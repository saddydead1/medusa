"""SQLite-слой Medusa: схема, соединения, начальные данные.

Здесь только данные панели: пользователи, ноды, хосты, цепочки, администраторы,
настройки. Логику самого VPN (Xray, выставку инбаундов на нодах) пока не делаем —
трафик и статусы нод в таблицах это заглушки, которые позже заменит реальный опрос нод.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path

from src.core.api_keys import new_api_key
from src.panel.security import hash_password, new_session_token, new_user_token, temporary_password

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = Path(os.getenv("MEDUSA_DB", str(ROOT / "data" / "medusa.db")))

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('owner','admin')) DEFAULT 'admin',
    status        TEXT    NOT NULL CHECK (status IN ('active','disabled'))    DEFAULT 'active',
    last_login    INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT    PRIMARY KEY,
    admin_id   INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- Аппаратные ключи (FIDO2): один credential = одна строка. Открытый ключ лежит здесь,
-- наружу панель отдаёт только nickname, алгоритм, aaguid и счётчик.
CREATE TABLE IF NOT EXISTS admin_keys (
    id         INTEGER PRIMARY KEY,
    admin_id   INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    cred_id    TEXT    NOT NULL UNIQUE,
    algo       INTEGER NOT NULL,
    public_key TEXT    NOT NULL,
    aaguid     TEXT    NOT NULL DEFAULT '',
    sign_count INTEGER NOT NULL DEFAULT 0,
    nickname   TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

-- Одноразовые вызовы FIDO2: challenge живёт 5 минут и расходуется на одну проверку.
CREATE TABLE IF NOT EXISTS fido_challenges (
    challenge  TEXT    PRIMARY KEY,
    purpose    TEXT    NOT NULL,
    admin_id   INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    panelName     TEXT NOT NULL DEFAULT 'Medusa',
    theme         TEXT NOT NULL DEFAULT 'auto',
    subUrl        TEXT NOT NULL DEFAULT 'http://127.0.0.1:8000/sub',
    subTitle      TEXT NOT NULL DEFAULT 'Medusa',
    subInterval   INTEGER NOT NULL DEFAULT 24 CHECK (subInterval BETWEEN 1 AND 168),
    pollInterval  INTEGER NOT NULL DEFAULT 30 CHECK (pollInterval BETWEEN 5 AND 3600),
    nodeTimeout   INTEGER NOT NULL DEFAULT 10 CHECK (nodeTimeout BETWEEN 2 AND 120),
    sessionHours  INTEGER NOT NULL DEFAULT 72 CHECK (sessionHours BETWEEN 1 AND 720),
    passkeyEnabled INTEGER NOT NULL DEFAULT 0 CHECK (passkeyEnabled IN (0,1))
);

CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE CHECK (length(name) BETWEEN 2 AND 32),
    token      TEXT    NOT NULL UNIQUE,
    status     TEXT    NOT NULL CHECK (status IN ('active','disabled')) DEFAULT 'active',
    used_bytes INTEGER NOT NULL DEFAULT 0,
    client     TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    id               INTEGER PRIMARY KEY,
    name             TEXT    NOT NULL UNIQUE CHECK (length(name) BETWEEN 2 AND 32),
    address          TEXT    NOT NULL,
    online           INTEGER NOT NULL DEFAULT 0,
    xray_version     TEXT,
    users_count      INTEGER NOT NULL DEFAULT 0,
    traffic_bytes    INTEGER NOT NULL DEFAULT 0,
    -- связь панели с нодой: отдельный порт API ноды и API-ключ, который создала сама нода
    api_port         INTEGER NOT NULL DEFAULT 9443 CHECK (api_port BETWEEN 1 AND 65535),
    api_key          TEXT    NOT NULL DEFAULT '',
    agent_version    TEXT,
    seen_at          INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS chains (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE CHECK (length(name) BETWEEN 2 AND 32),
    hops       TEXT    NOT NULL,            -- JSON: [{node_id, protocol, network, security, port}]
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL,
    node_id    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    protocol   TEXT    NOT NULL,
    port       INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    network    TEXT    NOT NULL DEFAULT 'tcp',
    security   TEXT    NOT NULL DEFAULT 'none',
    chain_id   INTEGER REFERENCES chains(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    UNIQUE (node_id, port)
);

CREATE INDEX IF NOT EXISTS idx_hosts_node   ON hosts(node_id);
CREATE INDEX IF NOT EXISTS idx_hosts_chain  ON hosts(chain_id);
"""


def now_ms() -> int:
    return int(time.time() * 1000)


def connect(path: Path | None = None) -> sqlite3.Connection:
    """Отдельное соединение на запрос: sqlite лёгкий, а блокировок не видно.

    check_same_thread=False нужен из-за threadpool FastAPI: синхронный эндпоинт
    выполняется в рабочем потоке, зависимость открывается в одном потоке, а
    закрывается в другом. Соединение живёт только один запрос и дальше не
    передаётся, поэтому гонки нет.
    """
    target = path or DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def get_conn() -> Iterator[sqlite3.Connection]:
    """Зависимость FastAPI."""
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


def ensure_settings(conn: sqlite3.Connection) -> None:
    conn.execute("INSERT OR IGNORE INTO settings (id) VALUES (1)")


def ensure_owner(conn: sqlite3.Connection) -> str | None:
    """Первый администратор-владелец: создаётся один раз, пароль — из окружения."""
    row = conn.execute("SELECT id FROM admins WHERE role = 'owner' LIMIT 1").fetchone()
    if row:
        return None
    password = os.getenv("MEDUSA_ADMIN_PASSWORD") or temporary_password()
    conn.execute(
        "INSERT INTO admins (username, password_hash, role, status, last_login, created_at) VALUES (?,?,?,?,?,?)",
        (os.getenv("MEDUSA_ADMIN_USER", "admin"), hash_password(password), "owner", "active", 0, now_ms()),
    )
    return password


# Новых колонок схема не знает: новую колонну приходится добавлять самим.
COLUMNS = {
    "settings": {"passkeyEnabled": "INTEGER NOT NULL DEFAULT 0 CHECK (passkeyEnabled IN (0,1))"},
    "sessions": {"created_at": "INTEGER NOT NULL DEFAULT 0"},
    "nodes": {
        "api_port": "INTEGER NOT NULL DEFAULT 9443",
        "api_key": "TEXT NOT NULL DEFAULT ''",
        "agent_version": "TEXT",
        "seen_at": "INTEGER NOT NULL DEFAULT 0",
        # применение конфига Xray: чего хочет панель (config_rev), что нода подтвердила
        # (applied_rev/applied_at), осталась ли несвежей после правок (config_dirty)
        "config_rev": "INTEGER NOT NULL DEFAULT 0",
        "config_dirty": "INTEGER NOT NULL DEFAULT 0",
        "applied_rev": "INTEGER NOT NULL DEFAULT 0",
        "applied_at": "INTEGER NOT NULL DEFAULT 0",
        "apply_error": "TEXT",
        # отпечаток последнего отправленного конфига: совпал — ноду не дёргаем
        "config_hash": "TEXT NOT NULL DEFAULT ''",
    },
    "hosts": {
        # адрес, к которому подключается подписчик; адрес ноды — только для панели
        "address": "TEXT NOT NULL DEFAULT ''",
        # ключи reality: пару создаёт панель (x25519), приватный уезжает в конфиг,
        # публичный — в ссылку подписки
        "private_key": "TEXT NOT NULL DEFAULT ''",
        "public_key": "TEXT NOT NULL DEFAULT ''",
    },
}


# Прежние колонки, которые были названы не так: переименовываем, а не заводим
# пустую рядом и теряем то, что человек уже ввёл руками.
RENAMED = {"nodes": {"node_key": "api_key"}}


def ensure_columns(conn: sqlite3.Connection) -> None:
    for table, columns in COLUMNS.items():
        known = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for old_name, new_name in RENAMED.get(table, {}).items():
            if old_name in known and new_name not in known:
                conn.execute(f"ALTER TABLE {table} RENAME COLUMN {old_name} TO {new_name}")
                known = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for column, definition in columns.items():
            if column not in known:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db(path: Path | None = None) -> None:
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        ensure_columns(conn)
        # роли наблюдателя больше нет: прежние наблюдатели становятся администраторами
        conn.execute("UPDATE admins SET role = 'admin' WHERE role = 'viewer'")
        ensure_settings(conn)
        password = ensure_owner(conn)
        if os.getenv("MEDUSA_DEMO") == "1":
            seed_demo(conn)
        conn.commit()
    finally:
        conn.close()
    if password:
        login = os.getenv("MEDUSA_ADMIN_USER", "admin")
        print(f"[medusa] создан владелец '{login}', пароль: {password}", flush=True)


def create_session(conn: sqlite3.Connection, admin_id: int, hours: int) -> str:
    """Сессия панели: токен и срок жизни из настройки `sessionHours`.

    Настройку меняет владелец — уже выданные сессии она не укорачивает и не удлиняет:
    она действует с следующего входа. Иначе «срок сессии 1 час» означал бы, что любой
    администратор может выбросить чужие сессии одной правкой настройки.
    """
    token = new_session_token()
    created = now_ms()
    conn.execute(
        "INSERT INTO sessions (token, admin_id, created_at, expires_at) VALUES (?,?,?,?)",
        (token, admin_id, created, created + hours * 3600_000),
    )
    return token


def admin_by_token(conn: sqlite3.Connection, token: str | None) -> sqlite3.Row | None:
    if not token:
        return None
    row = conn.execute(
        """SELECT a.* FROM sessions s JOIN admins a ON a.id = s.admin_id
           WHERE s.token = ? AND s.expires_at > ? AND a.status = 'active'""",
        (token, now_ms()),
    ).fetchone()
    return row


# ---------- тестовые данные: MEDUSA_DEMO=1 ----------
GB = 1024**3
DAY = 86_400_000


def seed_demo(conn: sqlite3.Connection) -> None:
    if conn.execute("SELECT COUNT(*) c FROM nodes").fetchone()["c"]:
        return
    now = now_ms()
    node_ids = {}
    for name, address, online, traffic, users in [
        ("home", "10.8.0.1", 1, 88 * GB, 4),
        ("vps-fi", "10.8.0.2", 1, 107 * GB, 5),
        ("vps-de", "10.8.0.3", 0, 14 * GB, 3),
    ]:
        cur = conn.execute(
            """INSERT INTO nodes (name, address, online, xray_version, users_count, traffic_bytes,
                                   api_port, api_key, created_at)
               VALUES (?,?,?,?,?,?,9443,?,?)""",
            (name, address, online, "25.8.3", users, traffic, new_api_key(), now),
        )
        node_ids[name] = cur.lastrowid

    for name, used, client in [
        ("vasya", 42.5 * GB, "happ"),
        ("masha", 91 * GB, "clash-verge"),
        ("brother", 50 * GB, "clash-meta"),
        ("old-phone", 12 * GB, "clash-verge"),
        ("tv", 0, "v2rayng"),
    ]:
        conn.execute(
            "INSERT INTO users (name, token, status, used_bytes, client, created_at) VALUES (?,?,?,?,?,?)",
            (name, new_user_token(), "disabled" if name in {"old-phone", "tv"} else "active", int(used), client, now),
        )

    conn.execute("INSERT INTO admins (username, password_hash, role, status, last_login, created_at) VALUES (?,?,?,?,?,?)",
                 ("mila", hash_password(temporary_password()), "admin", "active", now - 3 * DAY, now))

    hosts = [
        ("FI Reality", "vps-fi", "vless", 443, "tcp", "reality"),
        ("FI TLS WS", "vps-fi", "vless", 8443, "ws", "tls"),
        ("DE Reality", "vps-de", "vless", 443, "tcp", "reality"),
        ("Home VMess", "home", "vmess", 2083, "ws", "tls"),
    ]
    for name, node, protocol, port, network, security in hosts:
        conn.execute(
            "INSERT INTO hosts (name, node_id, protocol, port, network, security, chain_id, created_at) VALUES (?,?,?,?,?,?,NULL,?)",
            (name, node_ids[node], protocol, port, network, security, now),
        )

    chains = [
        ("FI-DE", [("vps-fi", "vless", "tcp", "reality", 2053), ("vps-de", "vless", "tcp", "reality", 2053)]),
        ("Home-FI-DE", [("home", "vless", "tcp", "reality", 443), ("vps-fi", "vless", "grpc", "tls", 2083),
                        ("vps-de", "vless", "tcp", "reality", 2083)]),
        ("Home-FI", [("home", "vless", "tcp", "reality", 2053), ("vps-fi", "vless", "tcp", "reality", 2053)]),
    ]
    for name, hops in chains:
        payload = [{"node_id": node_ids[h[0]], "protocol": h[1], "network": h[2], "security": h[3], "port": h[4]} for h in hops]
        cur = conn.execute("INSERT INTO chains (name, hops, created_at) VALUES (?,?,?)",
                           (name, json_column(payload), now))
        first = payload[0]
        conn.execute(
            "INSERT INTO hosts (name, node_id, protocol, port, network, security, chain_id, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (name, first["node_id"], first["protocol"], first["port"], first["network"], first["security"], cur.lastrowid, now),
        )


def json_column(value) -> str:
    return json.dumps(value, ensure_ascii=False)


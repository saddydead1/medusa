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
from src.core.xray_config import hop_email
from src.panel import ports
from src.panel.chain_hops import insert_hop
from src.panel.host_keys import new_reality_keys
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
    client     TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    id               INTEGER PRIMARY KEY,
    name             TEXT    NOT NULL UNIQUE CHECK (length(name) BETWEEN 2 AND 32),
    address          TEXT    NOT NULL,
    online           INTEGER NOT NULL DEFAULT 0,
    xray_version     TEXT,
    -- накопленный трафик этой ноды (сообщает сама нода, см. src/node/traffic.py):
    -- и подписчиков, и транзит цепочек; traffic_error — почему счётчиков нет
    traffic_bytes    INTEGER NOT NULL DEFAULT 0,
    traffic_error    TEXT,
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

-- что нода насчитала по каждой метке Xray (`u<id>` подписчика или `hop<цепочка>-<номер>`).
-- накопленные итоги конкретной ноды: трафик человека — сумма по всем его нодам,
-- поэтому здесь нет ни общего счётчика, ни дублирования байтов между нодами.
CREATE TABLE IF NOT EXISTS node_traffic (
    node_id    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    email      TEXT    NOT NULL,
    user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,   -- NULL, если метка не подписьчик (хоп цепочки)
    bytes      INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (node_id, email)
);
CREATE INDEX IF NOT EXISTS idx_node_traffic_user ON node_traffic(user_id);

CREATE TABLE IF NOT EXISTS hosts (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL,
    node_id    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    protocol   TEXT    NOT NULL,
    port       INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    network    TEXT    NOT NULL DEFAULT 'tcp',
    security   TEXT    NOT NULL DEFAULT 'none',
    chain_id   INTEGER REFERENCES chains(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL
);
-- порт ноды занят и обычным хостом, и хопом цепочки; индекс заводится отдельной
-- инструкцией (см. ensure_columns), чтобы достался и новым, и прежним базам
CREATE UNIQUE INDEX IF NOT EXISTS hosts_node_port ON hosts (node_id, port);

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


def ensure_chain_hops(conn: sqlite3.Connection) -> list[str]:
    """Прежние цепочки дорисовываются до строк хопов.

    Раньше цепочка создавала только хост входа, а хопа существовали лишь в описании. Теперь
    у цепочки свой ряд hosts на каждый хоп: вход (`hop_index` 0 — его человек и видит хостом
    цепочки) и промежуточные хопа, которые являются такими же инбаундами на своих нодах.
    Миграция расставляет метки прежних строк и заводит недостающие хопа вместе с ключами
    (reality — пара x25519, tls — сертификат от панели), иначе старая цепочка молча
    превратилась бы в обычный хост, а её reality-вход уехал бы на ноду с пустым ключом.
    """
    conn.execute("UPDATE hosts SET hop_index = 0 WHERE chain_id IS NOT NULL AND hop_index < 0")
    for chain in conn.execute("SELECT id, name, hops, created_at FROM chains").fetchall():
        try:
            hops = json.loads(chain["hops"])
        except json.JSONDecodeError:
            continue
        have = {row["hop_index"] for row in conn.execute(
            "SELECT hop_index FROM hosts WHERE chain_id = ?", (chain["id"],)).fetchall()}
        for index, hop in enumerate(hops):
            if index in have or "node_id" not in hop:
                continue
            insert_hop(conn, chain["id"], chain["name"], index, hop, chain["created_at"])
        for row in conn.execute("""SELECT id FROM hosts WHERE chain_id = ?
                                   AND security = 'reality' AND private_key = ''""",
                                (chain["id"],)).fetchall():
            private, public = new_reality_keys()
            conn.execute("UPDATE hosts SET private_key = ?, public_key = ? WHERE id = ?",
                         (private, public, row["id"]))
    notes = free_hop_ports(conn)
    conn.execute("UPDATE nodes SET config_dirty = 1 WHERE api_key <> ''")
    return notes


def free_hop_ports(conn: sqlite3.Connection) -> list[str]:
    """Хопа цепочек не имеют права занимать чужой порт на машине ноды.

    Прежняя цепочка могла попросить порт, который на той же машине держит API-порт другой ноды
    (или хост другой ноды). Пока хопа были просто строкой в описании, это ничем не оборачивалось;
    теперь у каждого хопа свой инбаунд, и Xray на такой ноде падает целиком — вместе со
    здоровыми хостами. Поэтому миграция убирает хопа на первый свободный порт и честит это в
    hops цепочки (иначе окно правки показывало бы порт, которого больше нет). Обычные хосты
    людей миграция не трогает: там порт выбирал человек, и менять его молча — не дело панели.

    Возвращает человеческие строки о том, что было сдвинуто (панель печатает их в лог).
    """
    notes: list[str] = []
    rows = conn.execute(
        """SELECT h.id, h.name, h.chain_id, h.hop_index, h.port, h.node_id, n.address AS node_address
           FROM hosts h JOIN nodes n ON n.id = h.node_id
           WHERE h.chain_id IS NOT NULL ORDER BY h.chain_id, h.hop_index, h.id""").fetchall()
    for row in rows:
        issue = ports.port_conflict(conn, row["node_address"], int(row["port"]), skip_host=row["id"])
        if issue is None:
            continue
        moved = ports.free_port(conn, int(row["node_id"]), int(row["port"]) + 1)
        if moved is None:
            notes.append(f"{issue} — свободного порта для хопа «{row['name']}» не нашлось")
            continue
        conn.execute("UPDATE hosts SET port = ? WHERE id = ?", (moved, row["id"]))
        hops = json.loads(conn.execute("SELECT hops FROM chains WHERE id = ?",
                                       (row["chain_id"],)).fetchone()["hops"])
        hops[int(row["hop_index"])]["port"] = moved
        conn.execute("UPDATE chains SET hops = ? WHERE id = ?",
                     (json.dumps(hops, ensure_ascii=False), row["chain_id"]))
        notes.append(f"цепочка #{row['chain_id']}: {issue} — хоп «{row['name']}» переведён на порт {moved}")
    return notes


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
# что в прежних базах было придумано и больше не нужно
LEGACY_COLUMNS = {"users": ("used_bytes",), "nodes": ("users_count",)}

COLUMNS = {
    "settings": {"passkeyEnabled": "INTEGER NOT NULL DEFAULT 0 CHECK (passkeyEnabled IN (0,1))"},
    "sessions": {"created_at": "INTEGER NOT NULL DEFAULT 0"},
    "nodes": {
        "api_port": "INTEGER NOT NULL DEFAULT 9443",
        "api_key": "TEXT NOT NULL DEFAULT ''",
        "agent_version": "TEXT",
        "seen_at": "INTEGER NOT NULL DEFAULT 0",
        # почему счётчики трафика молчат (нет xray, Xray не поднят, порт не подобран)
        "traffic_error": "TEXT",
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
        # отдельные настройки защиты: у reality это маскирование (dest) и отпечаток
        # клиента, у tls — alpn и отношение к чужому SNI; пустые — значит разумные
        # значения по умолчанию, их знает рендер конфига
        "dest": "TEXT NOT NULL DEFAULT ''",
        "fp": "TEXT NOT NULL DEFAULT ''",
        "alpn": "TEXT NOT NULL DEFAULT ''",
        "reject_unknown_sni": "INTEGER NOT NULL DEFAULT 0",
        # транспортные детали: путь и Host-заголовок у ws, имя сервиса и authority
        # у gRPC; для tcp показывать нечего — они пустые
        "path": "TEXT NOT NULL DEFAULT ''",
        "host_header": "TEXT NOT NULL DEFAULT ''",
        "service_name": "TEXT NOT NULL DEFAULT ''",
        "grpc_authority": "TEXT NOT NULL DEFAULT ''",
        # tls: sni клиента (адрес хоста по умолчанию) и пути к своим сертификатам
        # на самой ноде (пустые — нода выпустит self-signed сама); reality: какие
        # sni он принимает (пусто — адрес хоста)
        "sni": "TEXT NOT NULL DEFAULT ''",
        "cert_file": "TEXT NOT NULL DEFAULT ''",
        "key_file": "TEXT NOT NULL DEFAULT ''",
        "server_names": "TEXT NOT NULL DEFAULT ''",
        # хоп цепочки: цепочка живёт своими строками в hosts, по одной на каждый хоп
        # (-1 — обычный хост, 0 — вход цепочки, 1.. — промежуточные хопа; человек в списке
        # хостов видит только вход, остальные — внутренняя связь нод)
        "hop_index": "INTEGER NOT NULL DEFAULT -1",
        # сертификат хопа с tls выпускает панель (см. src/panel/host_keys.py): она обязана
        # знать и сам сертификат, и его отпечаток, чтобы закрепить его за соседней нодой
        "cert_pem": "TEXT NOT NULL DEFAULT ''",
        "key_pem": "TEXT NOT NULL DEFAULT ''",
        "cert_sha256": "TEXT NOT NULL DEFAULT ''",
        # колонки alpn, min_version, max_version, cipher_suites, reality_min_client,
        # reality_max_client, grpc_multi_mode остались разве что в старых базах:
        # панель ими больше не управляет — разумные значения знает сам Xray
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
    # прежние поля-заглушки: трафик и число подписчиков больше не выдумываются — их
    # сообщает нода (node_traffic, traffic_bytes) или считает сама панель
    for table, columns in LEGACY_COLUMNS.items():
        known = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for column in columns:
            if column in known:
                conn.execute(f"ALTER TABLE {table} DROP COLUMN {column}")
    # порт занят и хопом цепочки: в прежних базах хопа отдельными строками hosts не были,
    # поэтому индекс добавляется отдельно (создать его поверх уже существующего дубликата
    # sqlite не может — тогда держится только проверка слоя выше)
    try:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS hosts_node_port ON hosts (node_id, port)")
    except sqlite3.IntegrityError:
        pass


def init_db(path: Path | None = None) -> list[str]:
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        ensure_columns(conn)
        moved = ensure_chain_hops(conn)
        for note in moved:
            # миграция сдвинула порт хопа — это должен увидеть человек в логе панели,
            # а не обнаружить по неработающей подписке
            print(f"[medusa-panel] {note}", flush=True)
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
    return moved


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
    for name, address, online in [("home", "10.8.0.1", 1), ("vps-fi", "10.8.0.2", 1),
                                  ("vps-de", "10.8.0.3", 0)]:
        cur = conn.execute(
            """INSERT INTO nodes (name, address, online, xray_version, api_port, api_key, created_at)
               VALUES (?,?,?,?,9443,?,?)""",
            (name, address, online, "25.8.3", new_api_key(), now),
        )
        node_ids[name] = cur.lastrowid

    for name, client in [("vasya", "happ"), ("masha", "clash-verge"), ("brother", "clash-meta"),
                         ("old-phone", "clash-verge"), ("tv", "v2rayng")]:
        conn.execute(
            "INSERT INTO users (name, token, status, client, created_at) VALUES (?,?,?,?,?)",
            (name, new_user_token(), "disabled" if name in {"old-phone", "tv"} else "active", client, now),
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

    # порты хопов занимают ноду по-настоящему (UNIQUE (node_id, port)), поэтому в демо
    # ни один порт ни одной ноды не используется дважды — как у живых цепочек
    chains = [
        ("FI-DE", [("vps-fi", "vless", "tcp", "reality", 2053), ("vps-de", "vless", "tcp", "reality", 2053)]),
        ("Home-FI-DE", [("home", "vless", "tcp", "reality", 443), ("vps-fi", "vless", "grpc", "tls", 2083),
                        ("vps-de", "vless", "tcp", "reality", 2084)]),
        ("Home-FI", [("home", "vless", "tcp", "reality", 2054), ("vps-fi", "vless", "tcp", "reality", 2054)]),
    ]
    for name, hops in chains:
        payload = [{"node_id": node_ids[h[0]], "protocol": h[1], "network": h[2], "security": h[3], "port": h[4]} for h in hops]
        cur = conn.execute("INSERT INTO chains (name, hops, created_at) VALUES (?,?,?)",
                           (name, json_column(payload), now))
        # каждый хоп — ряд hosts: вход цепочки виден человеку как её хост, остальные хопа —
        # рабочие инбаунды своих нод, и у каждого свои ключи (panel/chain_hops.py)
        for index, hop in enumerate(payload):
            insert_hop(conn, cur.lastrowid, name, index, hop, now)

    seed_demo_traffic(conn, node_ids, now)


def seed_demo_traffic(conn: sqlite3.Connection, node_ids: dict[str, int], moment: int) -> None:
    """Демонстрационный трафик — той же формы, что сообщает настоящая нода.

    Это не украшение: `node_traffic` — единственное место, откуда панель берёт байты,
    поэтому демо обязано выглядеть как отчёт ноды (метки `u<id>` и `hop<цепочка>-<номер>`),
    иначе интерфейс проверялся бы на данных, которых в жизни не бывает.

    Разложены байты так, как их разложила бы真实 нода: часть подписчиков ходит через
    несколько нод (их трафик — сумма по нодам), а цепочки приносят нодам ещё и транзит,
    который человеку не приписывается. Поэтому сумма полос нод больше, чем сумма трафика
    людей, — и это правильно.
    """
    user_ids = {row["name"]: row["id"] for row in conn.execute("SELECT id, name FROM users")}
    per_user = {
        "vasya": {"home": 16.0, "vps-fi": 26.5},
        "masha": {"home": 38.0, "vps-fi": 45.0, "vps-de": 8.0},
        "brother": {"home": 26.0, "vps-fi": 24.0},
        # отключённый человек остаётся со своей историей: байты были, подписка больше не раздаётся
        "old-phone": {"home": 8.0, "vps-fi": 3.5},
        "tv": {},
    }
    for name, spread in per_user.items():
        user_id = user_ids.get(name)
        if user_id is None:
            continue
        for node, giga in spread.items():
            conn.execute("INSERT INTO node_traffic (node_id, email, user_id, bytes, updated_at) VALUES (?,?,?,?,?)",
                         (node_ids[node], f"u{user_id}", user_id, int(giga * GB), moment))

    # транзит цепочек: метка перехода, а не человека (hop_email — та же функция, что в конфиге)
    transit = {("FI-DE", 1): 4.0, ("Home-FI-DE", 1): 2.0, ("Home-FI", 1): 1.5, ("Home-FI-DE", 2): 6.0}
    for chain_id, chain_name in [(r["id"], r["name"]) for r in conn.execute("SELECT id, name FROM chains")]:
        hops = json.loads(conn.execute("SELECT hops FROM chains WHERE id = ?", (chain_id,)).fetchone()["hops"])
        for index, hop in enumerate(hops):
            if index == 0:
                continue        # вход цепочки — трафик подписчика, он уже посчитан
            giga = transit.get((chain_name, index))
            if not giga:
                continue
            conn.execute("INSERT INTO node_traffic (node_id, email, user_id, bytes, updated_at) VALUES (?,?,?,?,?)",
                         (hop["node_id"], hop_email(chain_id, index), None, int(giga * GB), moment))

    # итог ноды = сумма её меток: панель не хранит трафик ноды отдельно от её же отчёта
    for node_id in node_ids.values():
        total = conn.execute("SELECT COALESCE(SUM(bytes), 0) t FROM node_traffic WHERE node_id = ?",
                             (node_id,)).fetchone()["t"]
        conn.execute("UPDATE nodes SET traffic_bytes = ? WHERE id = ?", (total, node_id))


def json_column(value) -> str:
    return json.dumps(value, ensure_ascii=False)


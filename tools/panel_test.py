"""Проверка Medusa API: .venv/bin/python tools/api_test.py

База берётся временная, сид демо не используется — проверяем то, что делает API.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

tmp = Path(tempfile.mkdtemp(prefix="medusa-test-"))
os.environ["MEDUSA_DB"] = str(tmp / "test.db")
os.environ["MEDUSA_ADMIN_PASSWORD"] = "supersecret1"
os.environ.pop("MEDUSA_DEMO", None)      # демо-данные здесь мешают: тест сам всё создаёт
# авторизация в панели включена по умолчанию: без сессии API закрыт.
# Владелец здесь — admin/supersecret1, тест входит под ним и работает дальше.
os.environ["MEDUSA_ADMIN_USER"] = "admin"
os.environ["MEDUSA_NODE_AUTO"] = "0"     # фоновый опрос нод здесь только мешает

from fastapi.testclient import TestClient  # noqa: E402

from src.panel import deps  # noqa: E402
from src.panel.main import app  # noqa: E402

FAILS = 0


def ok(cond: object, message: str) -> None:
    global FAILS
    print(("PASS  " if cond else "FAIL  ") + message)
    if not cond:
        FAILS += 1


def chain_migration_checks() -> None:
    """Прежняя база поверх новой панели: у цепочки был только хост входа.

    Проверка нужна, потому что цепочка теперь живёт строками hosts на каждый хоп: без
    миграции старая цепочка молча осталась бы одним хостом (её следующий хоп существовал
    только в описании), а её reality-вход уехал бы на ноду с пустым приватным ключом.
    """
    from src.panel.db import connect, init_db

    path = Path(tempfile.mkdtemp(prefix="medusa-oldchain-")) / "old.db"
    init_db(path)
    conn = connect(path)
    # добавляем то, что в прежних базах было придумано вместо настоящих счётчиков:
    # миграция обязана это убрать, а не оставить мёртвыми колонками
    conn.execute("ALTER TABLE users ADD COLUMN used_bytes INTEGER NOT NULL DEFAULT 0")
    conn.execute("ALTER TABLE nodes ADD COLUMN users_count INTEGER NOT NULL DEFAULT 0")
    conn.commit()
    # ключи у нод есть: миграция помечает грязными только те ноды, которым что-то можно отправить
    node_fi = conn.execute("INSERT INTO nodes (name, address, api_key, created_at) VALUES ('fi','127.0.0.1','sk-api-fi',1)").lastrowid
    node_de = conn.execute("INSERT INTO nodes (name, address, api_key, created_at) VALUES ('de','127.0.0.2','sk-api-de',1)").lastrowid
    hops = [{"node_id": node_fi, "protocol": "vless", "network": "tcp", "security": "reality", "port": 2053},
            {"node_id": node_de, "protocol": "trojan", "network": "ws", "security": "tls", "port": 2083}]
    chain_id = conn.execute("INSERT INTO chains (name, hops, created_at) VALUES ('прежняя', ?, 1)",
                            (json.dumps(hops),)).lastrowid
    conn.execute("""INSERT INTO hosts (name, node_id, protocol, port, network, security, chain_id, created_at)
                    VALUES ('прежняя', ?, 'vless', 2053, 'tcp', 'reality', ?, 1)""", (node_fi, chain_id))
    conn.commit()
    conn.close()

    init_db(path)                       # повторный запуск панели поверх прежней базы
    conn = connect(path)
    rows = conn.execute("""SELECT name, hop_index, protocol, port, security, private_key, cert_pem, cert_sha256
                           FROM hosts WHERE chain_id = ? ORDER BY hop_index""", (chain_id,)).fetchall()
    ok(len(rows) == len(hops),
       f"миграция дорисовала хопа прежней цепочки строками hosts: {[r['name'] for r in rows]}")
    ok([r["hop_index"] for r in rows] == list(range(len(hops))),
       "вход прежней цепочки помечен хопом 0 (его человек видит хостом), следующий — хопом 1")
    reality_hop, tls_hop = rows[0], rows[1]
    ok(bool(reality_hop["private_key"]) and len(reality_hop["private_key"]) == 43,
       f"reality-вход прежней цепочки получил пару x25519 ({len(reality_hop['private_key'])} символов): "
       "без неё Xray не принял бы конфиг ноды")
    ok(bool(tls_hop["cert_pem"]) and len(tls_hop["cert_sha256"]) == 64,
       "tls-хопу прежней цепочки панель выпустила сертификат и запомнила его отпечаток "
       "(его она закрепляет за соседней нодой: Xray 26 самоподписанный сертификат не примет)")
    visible = [r["name"] for r in conn.execute(
        "SELECT name FROM hosts WHERE chain_id IS NULL OR hop_index = 0 ORDER BY id").fetchall()]
    ok(visible == ["прежняя"], f"человек по-прежнему видит только вход цепочки: {visible}")
    try:
        conn.execute("""INSERT INTO hosts (name, node_id, protocol, port, network, security, created_at)
                        VALUES ('дубликат порта хопа', ?, 'vless', 2053, 'tcp', 'none', 1)""", (node_fi,))
        ok(False, "порт, занятый хопом прежней цепочки, свободен для нового хоста — индекс не создался")
    except sqlite3.IntegrityError as exc:
        ok("hosts_node_port" in str(exc) or "UNIQUE" in str(exc).upper(),
           f"порт хопа занял ноду и в прежней базе: {exc}")
    dirty = conn.execute("SELECT COUNT(*) c FROM nodes WHERE config_dirty = 1").fetchone()["c"]
    ok(dirty == 2, f"обе ноды прежней цепочки помечены грязными — их конфиги пересоберутся сами: {dirty}")
    legacy = ({row["name"] for row in conn.execute("PRAGMA table_info(users)")}
              & {"used_bytes"}) | ({row["name"] for row in conn.execute("PRAGMA table_info(nodes)")}
                                   & {"users_count"})
    ok(not legacy, f"прежние поля-заглушки ({sorted(legacy) or 'users.used_bytes, nodes.users_count'}) "
                   "из базы убраны: трафик и подписчиков теперь считают, а не хранят по-старому")
    conn.close()


def traffic_checks(client: TestClient) -> None:
    """Как панель раскладывает отчёты нод по людям.

    Отчёт ноды собирается вручную (`NodeStatus`): проверка касается того, что делает
    панель — сопоставление меток, сумма по нодам, каскадные удаления и честное сообщение
    о том, что счётчики не считались. Саму связку «нода сняла счётчики с Xray» проверяют
    `node_test` и `xray_test`, живой трафик — `live_demo`.
    """
    from src.core.contract import NodeStatus, UserTraffic
    from src.panel.db import connect, now_ms
    from src.panel.node_traffic import apply_status, user_traffic_total

    node_a = client.post("/api/nodes", json={"name": "tr-a", "address": "10.9.0.1",
                                             "apiPort": 9501, "apiKey": "sk-api-tra0123456789000000"}).json()
    node_b = client.post("/api/nodes", json={"name": "tr-b", "address": "10.9.0.2",
                                             "apiPort": 9502, "apiKey": "sk-api-trb0123456789000000"}).json()
    vasya = client.post("/api/users", json={"name": "tr-vasya"}).json()
    masha = client.post("/api/users", json={"name": "tr-masha"}).json()
    conn = connect()

    def status(node: str, labels: list[tuple[str, int]], error: str | None = None) -> NodeStatus:
        total = sum(amount for _, amount in labels)
        return NodeStatus(fingerprint=node, agentVersion="0.1.0", uptimeMs=1000, trafficBytes=total,
                          userTraffic=[UserTraffic(email=email, bytes=amount) for email, amount in labels],
                          statsAt=now_ms(), statsPort=39113, statsError=error)

    def node_row(node_id: int) -> dict:
        return next(n for n in client.get("/api/nodes").json() if n["id"] == node_id)

    def user_row(user_id: int) -> dict:
        return next(u for u in client.get("/api/users").json() if u["id"] == user_id)

    apply_status(conn, node_a["id"], status("a", [(f"u{vasya['id']}", 1000), (f"u{masha['id']}", 300),
                                                   ("hop5-1", 200), ("u999", 10)]))
    apply_status(conn, node_b["id"], status("b", [(f"u{vasya['id']}", 500)]))
    ok(user_traffic_total(conn, vasya["id"]) == 1500,
       f"трафик человека — сумма по всем его нодам: tr-vasya {user_traffic_total(conn, vasya['id'])}")
    ok(node_row(node_a["id"])["traffic"] == 1510 and node_row(node_b["id"])["traffic"] == 500,
       "строки нод показывают то, что насчитала каждая нода, включая транзит цепочек")
    ok(user_row(vasya["id"])["used"] == 1500 and user_row(masha["id"])["used"] == 300,
       "список пользователей отдаёт их настоящие байты, а не ноль")
    ok(sum(u["used"] for u in client.get("/api/users").json()) == 1800,
       "ни транзит цепочки (hop5-1), ни метка отсутствующего человека (u999) людям не приписаны")

    apply_status(conn, node_a["id"], status("a", [(f"u{vasya['id']}", 1000), (f"u{masha['id']}", 300),
                                                   ("hop5-1", 200), ("u999", 10)]))
    ok(user_traffic_total(conn, vasya["id"]) == 1500,
       "повтор того же отчёта ноды ничего не удваивает: значения накопленные, а не событийные")

    labels = [(f"u{vasya['id']}", 1000), (f"u{masha['id']}", 300), ("hop5-1", 200), ("u999", 10)]
    apply_status(conn, node_a["id"], status("a", labels, error="Xray не поднят — счётчики не сняты"))
    ok(node_row(node_a["id"])["trafficError"] == "Xray не поднят — счётчики не сняты",
       "причина, по которой счётчики в этом круге молчали, доходит до строки ноды")
    ok(conn.execute("SELECT COUNT(*) c FROM node_traffic WHERE node_id = ?", (node_a["id"],)).fetchone()["c"] == 4,
       "отчёт с ошибкой сохраняет прежние метки: нода рассказывает всё, что насчитала, а не только "
       "то, что удалось снять сейчас")
    apply_status(conn, node_a["id"], status("a", [(f"u{vasya['id']}", 1000)]))
    ok(conn.execute("SELECT COUNT(*) c FROM node_traffic WHERE node_id = ?", (node_a["id"],)).fetchone()["c"] == 1,
       "нода перестала рассказывать про метку — панель убирает её: подтверждать эту цифру нечем")

    client.delete(f"/api/users/{masha['id']}")
    ok(user_traffic_total(conn, vasya["id"]) == 1500 and conn.execute(
        "SELECT COUNT(*) c FROM node_traffic WHERE email = ?", (f"u{masha['id']}",)).fetchone()["c"] == 0,
       "удалённый пользователь уносит свою историю трафика, чужая остаётся")

    client.delete(f"/api/nodes/{node_b['id']}")
    ok(user_traffic_total(conn, vasya["id"]) == 1000,
       f"удаление ноды убирает её часть трафика: tr-vasya снова {user_traffic_total(conn, vasya['id'])}")

    conn.execute("UPDATE users SET status = 'disabled' WHERE id = ?", (vasya["id"],))
    conn.commit()
    ok(node_row(node_a["id"])["users"] == 0,
       "отключённый подписчик перестает считаться обслуживаемым этой нодой")
    conn.close()


def main() -> int:
    with TestClient(app) as client:
        session = client.post("/api/login", json={"username": "admin", "password": "supersecret1"}).json()
        client.headers["Authorization"] = f"Bearer {session['token']}"
        ok(client.get("/api/me").json()["role"] == "owner", "панель под владельцем: права владельца")

        # --- мета и настройки ---
        meta = client.get("/api/meta").json()
        ok(meta.get("version"), f"/api/meta: версия {meta.get('version')}")

        settings = client.get("/api/settings").json()
        ok(settings["panelName"] == "Medusa" and settings["pollInterval"] == 30, f"настройки по умолчанию: {settings['pollInterval']}")
        patched = client.patch("/api/settings", json={"pollInterval": 15, "theme": "dark"}).json()
        ok(patched["pollInterval"] == 15 and patched["theme"] == "dark", "PATCH /api/settings сохранил поля")
        ok(client.patch("/api/settings", json={"pollInterval": 1}).status_code == 422, "настройки не принимают вне диапазона")

        # --- пользователи ---
        created = client.post("/api/users", json={"name": "vasya"}).json()
        ok(len(created["token"]) == 10, f"пользователь создан, токен подписки: {created['token']}")
        ok(client.post("/api/users", json={"name": "vasya"}).status_code == 409, "повтор имени пользователя -> 409")
        ok(client.post("/api/users", json={"name": "bad name!"}).status_code == 422, "имя с пробелами отклонено")
        masha = client.post("/api/users", json={"name": "masha", "client": "clash-verge"}).json()
        brother = client.post("/api/users", json={"name": "brother", "client": "clash-meta"}).json()
        ok(masha["client"] == "clash-verge", "поле client сохранилось")
        ok(client.patch(f"/api/users/{masha['id']}", json={"status": "disabled"}).json()["status"] == "disabled", "отключить пользователя")
        ok(client.delete(f"/api/users/{created['id']}").status_code == 204, "удалить пользователя")
        ok(client.patch("/api/users/999999", json={"status": "active"}).status_code == 404, "несуществующий пользователь -> 404")

        # --- ноды ---
        home = client.post("/api/nodes", json={"name": "home", "address": "10.8.0.1", "xray": "25.8.3",
                                               "apiKey": "sk-api-home00000000000000000"}).json()
        fi = client.post("/api/nodes", json={"name": "vps-fi", "address": "10.8.0.2", "xray": "25.8.3",
                                             "apiKey": "sk-api-fi0000000000000000000"}).json()
        ok(home["online"] is False and home["xray"] == "25.8.3", f"нода создана: {home['name']} {home['address']}")
        ok(client.post("/api/nodes", json={"name": "home", "address": "10.8.0.9",
                                          "apiKey": "sk-api-home00000000000000000"}).status_code == 409, "повтор ноды -> 409")
        ok(client.patch(f"/api/nodes/{home['id']}", json={"online": True}).json()["online"] is True, "онлайн ноды переключается")

        # --- API-ключ: создаёт его нода, панель только хранит и предъявляет ---
        keyed = client.post("/api/nodes", json={"name": "link", "address": "127.0.0.1",
                                                "apiPort": 9443, "apiKey": "sk-api-test123456789000000"}).json()
        ok(keyed["apiPort"] == 9443 and keyed["keySet"] is True, "нода заведена со своим портом API и API-ключом")
        ok(keyed["keyMasked"].startswith("sk-api") and keyed["fingerprint"],
           f"в списке только masked-ключ: {keyed['keyMasked']}")
        ok(all(k not in keyed for k in ("apiKey", "api_key")), "открытый ключ не утекает из POST /api/nodes")
        ok(all(k not in n for n in client.get("/api/nodes").json() for k in ("apiKey", "api_key", "key")),
           "ни одна нода в списке не отдаёт ключ")
        got = client.get(f"/api/nodes/{keyed['id']}/key").json()
        ok(got["key"] == "sk-api-test123456789000000" and got["fingerprint"] == keyed["fingerprint"],
           "ключ достаётся отдельным запросом по id")
        ok(client.post("/api/nodes", json={"name": "nokey", "address": "1.2.3.4"}).status_code == 422,
           "нода без API-ключа -> 422")
        ok(client.post("/api/nodes", json={"name": "shortkey", "address": "1.2.3.4", "apiKey": "short"}).status_code == 422,
           "короткий API-ключ -> 422")
        kept = client.patch(f"/api/nodes/{keyed['id']}", json={"apiKey": None}).json()
        ok(kept["keySet"] is True and kept["fingerprint"] == keyed["fingerprint"],
           "API-ключ нельзя снять: панель без ключа не сможет сделать на ноде ничего")

        # строка из старой базы, где API-ключа просто не было: ключ запрашивать нечего
        legacy = conn_cursor = None
        with sqlite3.connect(os.environ["MEDUSA_DB"]) as raw:
            raw.row_factory = sqlite3.Row
            cur = raw.execute("INSERT INTO nodes (name, address, api_port, api_key, created_at) VALUES (?,?,?,?,?)",
                              ("legacy", "1.2.3.4", 9443, "", 1))
            legacy = cur.lastrowid
        ok(client.get(f"/api/nodes/{legacy}/key").status_code == 409, "у ноды из старой базы /key -> 409")
        ok(client.delete(f"/api/nodes/{legacy}").status_code == 204, "старую ноду убрали")

        dead = client.post("/api/nodes", json={"name": "dead", "address": "127.0.0.1", "apiPort": 1,
                                               "apiKey": "sk-api-dead00000000000000000"}).json()
        report = client.post(f"/api/nodes/{dead['id']}/check", json={}).json()
        ok(report["reachable"] is False and report["ok"] is False and report["error"],
           f"недоступная нода: {report['error']}")
        ok(report["node_row"]["online"] is False, "недоступная нода осталась не в сети")

        # применение конфига к недоступной ноде — человеческий отчёт, а не HTTP-грохот
        failed = client.post(f"/api/nodes/{dead['id']}/apply", json={}).json()
        ok(failed["ok"] is False and failed["error"], f"apply на недоступную ноду: {failed['error']}")
        row = next(n for n in client.get("/api/nodes").json() if n["id"] == dead["id"])
        ok(row["applyError"] and row["configDirty"] is True, "ошибка применения осела в строке ноды")

        # --- хосты ---
        host = client.post("/api/hosts", json={"name": "FI Reality", "node": "vps-fi", "protocol": "vless",
                                               "port": 443, "network": "tcp", "security": "reality",
                                               "address": "fi.example.net", "fp": "edge"}).json()
        ok(host["node"] == "vps-fi" and host["chain"] is None, f"хост создан: {host['name']} на {host['node']}")
        ok(host["address"] == "fi.example.net" and host["publicKey"] and host["fp"] == "edge" and
           host["dest"] == "" and all(k not in host for k in ("private_key", "privateKey")),
           "reality-хост: адрес-домен, публичный ключ и отпечаток клиента есть, приватного нет")
        ip_reality = client.post("/api/hosts", json={"name": "по IP", "node": "vps-fi", "protocol": "vless",
                                                     "port": 444, "network": "tcp", "security": "reality"})
        ok(ip_reality.status_code == 201,
           "reality на ноде с IP-адресом допустим: клиент называет сайт-маску, а не адрес ноды")
        ok(ip_reality.json()["dest"] == "", "маскированный адрес по умолчанию знает рендер, панель его не выдумывает")
        mask_ip = client.post("/api/hosts", json={"name": "маска-IP", "node": "vps-fi", "protocol": "vless",
                                                  "port": 445, "network": "tcp", "security": "reality",
                                                  "dest": "1.2.3.4:443"})
        ok(mask_ip.status_code == 400, f"reality, прячущийся за IP, отвергается: {mask_ip.json()['detail']}")
        snis_ip = client.post("/api/hosts", json={"name": "sni-IP", "node": "vps-fi", "protocol": "vless",
                                                  "port": 446, "network": "tcp", "security": "reality",
                                                  "serverNames": "10.0.0.1"})
        ok(snis_ip.status_code == 400, "список принимаемых SNI тоже обязан быть доменами")
        client.delete(f"/api/hosts/{ip_reality.json()['id']}")
        dirty = next(n for n in client.get("/api/nodes").json() if n["name"] == "vps-fi")
        ok(dirty["configDirty"] is True, "новый хост сделал конфиг ноды несвежим")
        busy = client.post("/api/hosts", json={"name": "Другой", "node": "vps-fi", "protocol": "vmess",
                                               "port": 443, "network": "ws", "security": "tls"})
        ok(busy.status_code == 409, f"занятый порт -> 409: {busy.json()['detail']}")
        bad = client.post("/api/hosts", json={"name": "Странно", "node": "vps-fi", "protocol": "vless",
                                             "port": 8443, "network": "ws", "security": "reality"})
        ok(bad.status_code == 400, f"reality поверх ws -> 400: {bad.json()['detail']}")
        ok(client.post("/api/hosts", json={"name": "Нет", "node": "марс", "protocol": "vless", "port": 1,
                                          "network": "tcp", "security": "none"}).status_code == 400, "несуществующая нода -> 400")

        # --- цепочки: хост создаётся вместе с цепочкой ---
        chain = client.post("/api/chains", json={"name": "FI-DE", "hops": [
            {"node": "vps-fi", "protocol": "vless", "network": "tcp", "security": "reality", "port": 2053},
            {"node": "home", "protocol": "vless", "network": "tcp", "security": "reality", "port": 2053}]}).json()
        hosts = client.get("/api/hosts").json()
        chain_hosts = [h for h in hosts if h["chain"] == chain["id"]]
        ok(len(chain_hosts) == 1 and chain_hosts[0]["port"] == 2053,
           f"хост цепочки подсосался из цепочки: {chain_hosts[0]['name']} :{chain_hosts[0]['port']}")
        same = client.post("/api/chains", json={"name": "плохая", "hops": [
            {"node": "home", "protocol": "vless", "network": "tcp", "security": "reality", "port": 9000},
            {"node": "home", "protocol": "vless", "network": "tcp", "security": "reality", "port": 9001}]})
        ok(same.status_code == 400, f"соседние хопы на одной ноде -> 400: {same.json()['detail']}")
        dup = client.post("/api/chains", json={"name": "FI-DE2", "hops": [
            {"node": "vps-fi", "protocol": "vless", "network": "tcp", "security": "reality", "port": 443},
            {"node": "home", "protocol": "vless", "network": "tcp", "security": "reality", "port": 443}]})
        ok(dup.status_code == 409, f"порт уже занят -> 409: {dup.json()['detail']}")
        renamed = client.patch(f"/api/chains/{chain['id']}", json={"name": "FI-DE-new", "hops": chain["hops"]}).json()
        hosts = client.get("/api/hosts").json()
        ok(any(h["name"] == "FI-DE-new" and h["chain"] == chain["id"] for h in hosts),
           f"переименование цепочки правит и хост ({renamed['name']})")
        chain_host_id = next(h["id"] for h in hosts if h["chain"] == chain["id"])
        ok(client.delete(f"/api/hosts/{chain_host_id}").status_code == 409, "хост цепочки поодиночке не удаляется")
        ok(client.delete(f"/api/chains/{chain['id']}").status_code == 204, "удалить цепочку")
        ok(all(h["chain"] != chain["id"] for h in client.get("/api/hosts").json()), "хост цепочки удалён вместе с ней")

        # --- цепочки в конфиге: инбаунд каждого хопа и переход в следующий ---
        # Hop-ports скрыты от человека, но заняты: на ноде поднимается инбаунд каждого хопа.
        route = client.post("/api/chains", json={"name": "ROUTE-3", "hops": [
            {"node": "vps-fi", "protocol": "vless", "network": "tcp", "security": "reality", "port": 3101},
            {"node": "home", "protocol": "trojan", "network": "tcp", "security": "tls", "port": 3102},
            {"node": "vps-fi", "protocol": "ss", "network": "tcp", "security": "none", "port": 3103},
        ]}).json()
        hosts = client.get("/api/hosts").json()
        ok(len([h for h in hosts if h["chain"] == route["id"]]) == 1,
           "человек видит один хост цепочки — её вход, промежуточные хопа наружу не показываются")
        taken = client.post("/api/hosts", json={"name": "Чужой порт", "node": "home", "protocol": "vless",
                                               "port": 3102, "network": "tcp", "security": "none"})
        ok(taken.status_code == 409,
           f"порт хопа занят, хотя хопа не показываются -> {taken.status_code}: {taken.json()['detail']}")

        def node_config(node_id: int) -> dict:
            """то, что панель отправляет ноде: её же collect() по настоящей базе.

           эндпоинт /api/nodes/<id>/config отдаёт показ для человека (секреты скрыты) —
            сверять пароли хопов по нему было бы подгонкой «скрыто панелью» с «скрыто панелью».
            """
            from src.panel.config_push import collect
            from src.panel.db import connect
            probe = connect()
            try:
                return collect(probe, node_id)["config"]
            finally:
                probe.close()

        cfg_fi, cfg_home = node_config(fi["id"]), node_config(home["id"])
        in_fi = {i["tag"]: i for i in cfg_fi["inbounds"]}
        in_home = {i["tag"]: i for i in cfg_home["inbounds"]}
        out_fi = {o["tag"]: o for o in cfg_fi["outbounds"]}
        out_home = {o["tag"]: o for o in cfg_home["outbounds"]}
        ok(in_fi.get("ROUTE-3", {}).get("port") == 3101 and in_fi["ROUTE-3"]["protocol"] == "vless",
           "вход цепочки — инбаунд первой ноды, тегом по имени цепочки")
        ok(in_home.get("ROUTE-3 hop 2", {}).get("port") == 3102 and in_home["ROUTE-3 hop 2"]["protocol"] == "trojan",
           "промежуточный хоп — инбаунд своей ноды (его порт и протокол), а не выдумка фронтенда")
        ok(in_fi.get("ROUTE-3 hop 3", {}).get("port") == 3103,
           "нода может быть и второй раз в цепочке: её хопы — отдельные инбаунды")
        link1 = out_fi.get("ROUTE-3 -> hop 2") or {}
        ok(link1.get("protocol") == "trojan" and link1["settings"]["servers"][0]["address"] == "10.8.0.1",
           "переход первой ноды идёт на адрес ноды второго хопа (у хопа своего адреса нет)")
        ok(link1["settings"]["servers"][0]["password"] == in_home["ROUTE-3 hop 2"]["settings"]["clients"][0]["password"],
           "пароль перехода и пароль инбаунда следующего хопа выведены из одного смысла: цепочка соберётся")
        pinned = link1["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"]
        ok(len(pinned) == 64 and all(c in "0123456789abcdef" for c in pinned)
           and in_home["ROUTE-3 hop 2"]["streamSettings"]["tlsSettings"]["certificates"],
           "tls-хоп: панель выпускает сертификат сама и закрепляет его отпечаток за соседней нодой "
           "(Xray 26 не принимает самоподписанный сертификат без pinnedPeerCertSha256)")
        link2 = out_home.get("ROUTE-3 -> hop 3") or {}
        ok(link2["settings"]["servers"][0]["method"] == "chacha20-ietf-poly1305"
           and link2["settings"]["servers"][0]["password"] == in_fi["ROUTE-3 hop 3"]["settings"]["users"][0]["password"],
           "shadowsocks-переход: шифр и пароль совпадают с users инбаунда третьего хопа")
        rules_fi = cfg_fi.get("routing", {}).get("rules", [])
        rules_home = cfg_home.get("routing", {}).get("rules", [])
        ok({"inboundTag": ["ROUTE-3"], "outboundTag": "ROUTE-3 -> hop 2"} in rules_fi,
           "трафик, вошедший во вход цепочки, обязан уйти переходом, а не наружу напрямую")
        ok({"inboundTag": ["ROUTE-3 hop 2"], "outboundTag": "ROUTE-3 -> hop 3"} in rules_home
           and {"inboundTag": ["ROUTE-3 hop 3"], "outboundTag": "direct"} not in rules_home,
           "у выхода цепочки правила нет: последний хоп уходит наружу через direct")
        def secrets_of(config: dict) -> list[str]:
            """и приватные ключи reality, и пароли trojan/ss/vmess — и у инбаундов, и у переходов"""
            found = []
            for block in list(config.get("inbounds", [])) + list(config.get("outbounds", [])):
                stream = (block.get("streamSettings") or {}).get("realitySettings") or {}
                if stream.get("privateKey"):
                    found.append(stream["privateKey"])
                settings = block.get("settings") or {}
                for group in (settings.get("servers"), settings.get("clients"), settings.get("users"),
                              settings.get("vnext")):
                    for item in group or []:
                        for user in (item.get("users") or [item]):
                            if user.get("password"):
                                found.append(user["password"])
            return found

        real_secrets = secrets_of(cfg_fi)
        shown = client.get(f"/api/nodes/{fi['id']}/config").json()["config"]
        shown_text = json.dumps(shown, ensure_ascii=False)
        ok(real_secrets and all(secret not in shown_text for secret in real_secrets)
           and shown_text.count("скрыто панелью") >= len(real_secrets),
           f"в окне конфига человек видит тот же JSON, что уедет ноде, но не ключи и не пароли "
           f"переходов цепочки: спрятано {len(real_secrets)} секретов")
        ok(json.dumps(cfg_fi, ensure_ascii=False).count("скрыто панелью") == 0,
           "а то, что действительно уезжает ноде, секретов не прячет: ноде нужен настоящий конфиг")

        moved = client.patch(f"/api/chains/{route['id']}", json={"name": "ROUTE-3", "hops": [
            {"node": "home", "protocol": "vless", "network": "ws", "security": "tls", "port": 3111},
            {"node": "vps-fi", "protocol": "vless", "network": "tcp", "security": "reality", "port": 3112},
        ]}).json()
        in_fi2 = {i["tag"]: i for i in node_config(fi["id"])["inbounds"]}
        in_home2 = {i["tag"]: i for i in node_config(home["id"])["inbounds"]}
        ok(moved["hops"][0]["node"] == "home" and in_home2.get("ROUTE-3", {}).get("port") == 3111
           and in_fi2.get("ROUTE-3 hop 2", {}).get("port") == 3112,
           "правка цепочки пересобирает хопа: вход переехал на другую ноду, прежних инбаундов нет")
        ok("ROUTE-3 hop 3" not in in_fi2 and 3101 not in {i["port"] for i in in_fi2.values()},
           "старые хопа исчезли из конфига, их порты освобождены")
        freed = client.post("/api/hosts", json={"name": "Освободившийся", "node": "vps-fi", "protocol": "vless",
                                               "port": 3101, "network": "tcp", "security": "none"})
        ok(freed.status_code == 201, f"порт освобождённого хопа снова свободен: {freed.json().get('detail', 'ok')}")
        client.delete(f"/api/hosts/{freed.json()['id']}")
        ok(client.delete(f"/api/chains/{route['id']}").status_code == 204, "цепочка удалена")
        ok(not any(tag.startswith("ROUTE-3") for tag in {i["tag"] for i in node_config(fi["id"])["inbounds"]}),
           "удаление цепочки снимает и её инбаунды, и её переходы")

        # --- подписка: страница /sub/<токен> ---
        from src.core.xray_config import REALITY_DEST

        REALITY_MIRROR = REALITY_DEST.split(":")[0]      # default sni reality: сайт-маска
        sub_chain = client.post("/api/chains", json={"name": "SUB-ROUTE", "hops": [
            {"node": "vps-fi", "protocol": "vless", "network": "tcp", "security": "reality", "port": 3011},
            {"node": "home", "protocol": "vless", "network": "tcp", "security": "reality", "port": 3012}]}).json()
        page = client.get(f"/sub/{brother['token']}", headers={"Accept": "text/html"})
        ok(page.status_code == 200 and "text/html" in page.headers.get("content-type", ""),
           "GET /sub/<токен> браузером: HTML-страница без входа администратора")
        ok("brother" in page.text and "активен" in page.text, "на странице подписки есть никнейм и живой статус")
        ok("langbtn" in page.text, "переключатель языка на месте")
        ok("themebtn" in page.text, "переключатель темы на месте")
        ok("FI Reality" in page.text and "SUB-ROUTE" in page.text, "хосты и цепочки доступны подписчику")
        ok(client.get("/sub/nesushchestvuet", headers={"Accept": "text/html"}).status_code == 404, "чужого токена подписки нет -> 404")
        off_page = client.get(f"/sub/{masha['token']}", headers={"Accept": "text/html"})
        ok(off_page.status_code == 200 and "FI Reality" not in off_page.text,
           "отключённому пользователю подписка не раздаётся")
        en_page = client.get(f"/sub/{brother['token']}?lang=en", headers={"Accept": "text/html"})
        ok("Hosts" in en_page.text and "Chains" in en_page.text, "страница подписки на английском по ?lang=en")
        forced = client.get(f"/sub/{brother['token']}", headers={"Accept-Language": "en-US,en;q=0.9", "Accept": "text/html"})
        ok("Хосты" in forced.text, "английский браузер видит русский: язык переключается только кнопкой")
        ok("vless://" in page.text and page.text.count('data-copy="') == 3,
           "кнопка копирования есть у хоста, у входа цепочки и у ссылки подписки")
        ok(page.text.count('data-qr="') == 3, "кнопка QR — у хоста, у входа цепочки и у ссылки подписки")
        ok('<img class="qr"' not in page.text, "QR подписки показывается только по кнопке, а не на странице")
        ok(f'/sub/{brother["token"]}/qr/subscribe' in page.text, "кнопка QR ссылки подписки ведёт на свой эндпоинт")
        import re as _re
        url_box = _re.search(r'class="url" readonly value="([^"]+)"', page.text)
        ok(url_box and url_box.group(1).endswith(f"/sub/{brother['token']}") and not url_box.group(1).endswith("/links"),
           "ссылка подписки на странице — тот же адрес, по которому открыта страница")
        # --- машинный вид подписки: все ссылки одним запросом + QR ---
        import base64 as b64
        as_app = client.get(f"/sub/{brother['token']}", headers={"Accept": "*/*"})
        decoded_app = b64.b64decode(as_app.text).decode("utf-8")
        ok(as_app.status_code == 200 and "text/plain" in as_app.headers["content-type"]
           and decoded_app.count("vless://") == 2,
           "та же ссылка подписки: приложение получает ссылки вместо страницы")
        ok(client.get(f"/sub/{brother['token']}?raw=1", headers={"Accept": "*/*"}).text.startswith("vless://"),
           "та же ссылка с ?raw=1 — без base64")
        as_moz = client.get(f"/sub/{brother['token']}", headers={"User-Agent": "Mozilla/5.0 (Linux; Android)"})
        ok("text/html" in as_moz.headers["content-type"], "приложение с Mozilla-UA получит страницу — у okhttp его нет")
        # Clash и его производные понимают только YAML со proxies:
        clash_resp = client.get(f"/sub/{brother['token']}", headers={"Accept": "*/*", "User-Agent": "clash-verge/v2.4.0"})
        import yaml as _yaml
        clash_doc = _yaml.safe_load(clash_resp.text)
        clash_names = sorted(p["name"] for p in clash_doc["proxies"])
        ok(clash_resp.status_code == 200 and clash_names == ["FI Reality", "SUB-ROUTE"],
           f"Clash-UA получает YAML, а не base64: {clash_names}")
        reality_proxy = next(p for p in clash_doc["proxies"] if p["name"] == "FI Reality")
        ok(reality_proxy["type"] == "vless" and reality_proxy["servername"] == REALITY_MIRROR
           and reality_proxy["reality-opts"]["public-key"] and reality_proxy["reality-opts"]["short-id"],
           f"clash yaml: reality-ключ, short-id и servername на месте: sni = сайт-маска {REALITY_MIRROR}, "
           "а не адрес ноды (Clash сверяет его с настоящим сертификатом маски)")
        ok(client.get(f"/sub/{brother['token']}/links?target=clash").text.startswith("# medusa"),
           "?target=clash отдаёт YAML и на явном /links пути")
        links = client.get(f"/sub/{brother['token']}/links")
        decoded = b64.b64decode(links.text).decode("utf-8")
        ok(links.status_code == 200 and "text/plain" in links.headers["content-type"]
           and decoded.count("vless://") == 2,
           "ссылки подписки: base64 из двух vless-ссылок, как ждёт v2rayN")
        raw_links = client.get(f"/sub/{brother['token']}/links?raw=1")
        ok(raw_links.status_code == 200 and raw_links.text.startswith("vless://"),
           "?raw=1 отдаёт ссылки без base64")
        qr = client.get(f"/sub/{brother['token']}/qr/subscribe")
        ok(qr.status_code == 200 and "image/svg" in qr.headers["content-type"] and b"<svg" in qr.content,
           "QR на ссылку подписки — живой SVG")
        qr_host = client.get(f"/sub/{brother['token']}/qr/host/{host['id']}")
        ok(qr_host.status_code == 200 and b"<svg" in qr_host.content, "QR отдельного хоста собран")
        ok(client.get(f"/sub/{brother['token']}/qr/host/999999").status_code == 404, "QR чужого хоста не выдаётся")
        ok(client.get(f"/sub/{masha['token']}/links").status_code == 404,
           "отключённому пользователю машинные ссылки не раздаются")
        ok(client.get("/sub/nesushchestvuet/links").status_code == 404, "чужого токена на машинных путях тоже нет")
        client.delete(f"/api/chains/{sub_chain['id']}")

        # --- подписка живёт не только с vless: vmess, trojan и shadowsocks ---
        import base64 as _b64
        import json as _json
        from urllib.parse import parse_qs, urlparse

        from src.core.xray_config import SS_CIPHER, ss_password, user_password, user_uuid

        fi_link = next(l for l in client.get(f"/sub/{brother['token']}/links?raw=1").text.splitlines()
                       if l.startswith("vless://"))
        ok(f"sni={REALITY_MIRROR}" in fi_link,
           f"reality-ссылка подписчика называет сайт-маску: {REALITY_MIRROR}")

        vmess_h = client.post("/api/hosts", json={"name": "VMess WS", "node": "home", "protocol": "vmess",
                                                   "port": 9431, "network": "ws", "security": "tls",
                                                   "address": "vm.example.net", "path": "/vmess",
                                                   "hostHeader": "cdn.example.net",
                                                   "sni": "vm.example.net"}).json()
        trojan_h = client.post("/api/hosts", json={"name": "Trojan TLS", "node": "home", "protocol": "trojan",
                                                    "port": 9432, "network": "tcp", "security": "tls",
                                                    "address": "tr.example.net",
                                                    "sni": "tr.example.net"}).json()
        ss_h = client.post("/api/hosts", json={"name": "SS первый", "node": "home", "protocol": "ss",
                                               "port": 9433, "network": "tcp", "security": "none",
                                               "address": "ss.example.net"}).json()
        ss2_h = client.post("/api/hosts", json={"name": "SS второй", "node": "home", "protocol": "ss",
                                                "port": 9434, "network": "tcp", "security": "none",
                                                "address": "ss2.example.net"}).json()

        lines = [l for l in client.get(f"/sub/{brother['token']}/links?raw=1").text.splitlines() if l]
        schemes = {urlparse(l).scheme for l in lines}
        ok({"vless", "vmess", "trojan", "ss"} <= schemes,
           f"ссылка подписки отдаёт все протоколы, а не только vless: {sorted(schemes)}")

        vmess_line = next(l for l in lines if l.startswith("vmess://"))
        vmess_doc = _json.loads(_b64.b64decode(vmess_line.split("://", 1)[1].split("#", 1)[0]))
        ok(vmess_doc["id"] == user_uuid(brother["token"]) and vmess_doc["add"] == "vm.example.net"
           and vmess_doc["port"] == "9431" and vmess_doc["aid"] == "0"
           and vmess_doc["net"] == "ws" and vmess_doc["path"] == "/vmess"
           and vmess_doc["host"] == "cdn.example.net" and vmess_doc["tls"] == "tls"
           and vmess_doc["sni"] == "vm.example.net"
           and vmess_doc["scy"] == vmess_doc["cipher"] == "auto",
           "vmess-ссылка: uuid, шифр, транспорт и sni лежат в её base64-JSON")

        trojan_line = next(l for l in lines if l.startswith("trojan://"))
        trojan_q = parse_qs(urlparse(trojan_line).query)
        ok(trojan_line.startswith(f"trojan://{user_password(brother['token'])}@tr.example.net:9432")
           and trojan_q["security"] == ["tls"] and trojan_q["sni"] == ["tr.example.net"],
           "trojan-ссылка: пароль собран из токена, sni и защита названы явно")

        ss_creds = []
        for h in (ss_h, ss2_h):
            ss_line = next(l for l in lines if l.startswith("ss://") and f"@{h['address']}:{h['port']}" in l)
            cred = ss_line.split("://", 1)[1].split("@", 1)[0]
            ok(cred == f"{SS_CIPHER}:{ss_password(brother['token'], h['id'])}",
               f"ss-ссылка {h['port']}: шифр и пароль этого хоста, как в конфиге Xray")
            ss_creds.append(cred)
        ok(ss_creds[0] != ss_creds[1],
           "на двух ss-хостах пароли разные: пароль shadowsocks — ключ конкретного порта")

        all_links = _b64.b64decode(client.get(f"/sub/{brother['token']}/links").text).decode("utf-8")
        kinds = [l.split("://", 1)[0] for l in all_links.splitlines() if l]
        ok(kinds.count("vmess") == 1 and kinds.count("trojan") == 1 and kinds.count("ss") == 2
           and kinds.count("vless") == 1,
           f"base64-подписка одним вставлением даёт все хосты, как ждёт v2rayNG/Happ/Hiddify: {sorted(kinds)}")

        page_all = client.get(f"/sub/{brother['token']}", headers={"Accept": "text/html"}).text
        ok(page_all.count('data-copy="') == 6 and page_all.count('data-qr="') == 6,
           "кнопки «скопировать» и QR есть у каждого хоста, независимо от протокола")
        ok(client.get(f"/sub/{brother['token']}/qr/host/{ss_h['id']}").status_code == 200,
           "QR собирается и на ss-хост, а не только на vless")

        clash_all = _yaml.safe_load(client.get(
            f"/sub/{brother['token']}",
            headers={"Accept": "*/*", "User-Agent": "clash-verge/v2.4.0"}).text)
        by_name = {p["name"]: p for p in clash_all["proxies"]}
        ok(by_name["VMess WS"]["type"] == "vmess" and by_name["VMess WS"]["cipher"] == "auto"
           and by_name["VMess WS"]["ws-opts"]["path"] == "/vmess"
           and by_name["VMess WS"]["ws-opts"]["headers"]["Host"] == "cdn.example.net"
           and by_name["VMess WS"]["skip-cert-verify"] is True,
           "clash yaml: vmess-прокси со своим шифром и websocket-опциями")
        ok(by_name["Trojan TLS"]["type"] == "trojan"
           and by_name["Trojan TLS"]["password"] == user_password(brother["token"])
           and by_name["Trojan TLS"]["servername"] == "tr.example.net",
           "clash yaml: trojan-прокси с паролем из токена")
        ok(by_name["SS первый"]["type"] == "ss" and by_name["SS первый"]["cipher"] == SS_CIPHER
           and by_name["SS первый"]["password"] == ss_password(brother["token"], ss_h["id"]),
           "clash yaml: shadowsocks-прокси с шифром и паролем этого хоста")
        group = clash_all["proxy-groups"][0]
        ok(group["type"] == "select" and set(group["proxies"]) == set(by_name)
           and clash_all["rules"][0] == f"MATCH,{group['name']}",
           f"clash yaml: группа выбора «{group['name']}» — одиночный Mihomo знает, куда класть трафик")
        ok(len(clash_all["proxies"]) == 5,
           f"clash yaml получает все протоколы: {sorted(by_name)}")

        hy2 = client.post("/api/hosts", json={"name": "Гистерия", "node": "home", "protocol": "hy2",
                                              "port": 9435, "network": "tcp", "security": "none"})
        ok(hy2.status_code == 400 and "Hysteria2" in hy2.json()["detail"],
           f"hy2 панель не заводит: {hy2.json()['detail']}")
        ss_tls = client.post("/api/hosts", json={"name": "ss+tls", "node": "home", "protocol": "ss",
                                                 "port": 9436, "network": "tcp", "security": "tls"})
        ok(ss_tls.status_code == 400, f"ss с tls отвергается: {ss_tls.json()['detail']}")
        vm_reality = client.post("/api/hosts", json={"name": "vmess+reality", "node": "vps-fi",
                                                     "protocol": "vmess", "port": 9437, "network": "tcp",
                                                     "security": "reality", "address": "vm.example.net"})
        ok(vm_reality.status_code == 400,
           f"vmess поверх reality отвергается: ссылка vmess не передаёт reality-ключ")
        for h in (vmess_h, trojan_h, ss_h, ss2_h):
            client.delete(f"/api/hosts/{h['id']}")

        # --- имя ноды можно менять: хосты и цепочки держатся за id, а не за имя ---
        probe = client.post("/api/hosts", json={"name": "проверка имени", "node": "home",
                                                "protocol": "vless", "network": "tcp",
                                                "security": "reality", "port": 9411,
                                                "address": "probe.example.net"}).json()
        renamed = client.patch(f"/api/nodes/{home['id']}", json={"name": "home-renamed"}).json()
        ok(renamed["name"] == "home-renamed", "ноду можно переименовать")
        after = client.get("/api/hosts").json()
        moved = next(h for h in after if h["id"] == probe["id"])
        ok(moved["node"] == "home-renamed", f"хост остался на своей ноде: {moved['node']}")
        client.delete(f"/api/hosts/{probe['id']}")
        # «сохранили как есть» — не значит «поменяли»: связь должно сбрасывать только
        # настоящее изменение адреса, порта или API-ключа
        kept = client.post("/api/nodes", json={"name": "keepme", "address": "127.0.0.1",
                                               "apiPort": 1, "apiKey": "sk-api-keepme01234567890123"}).json()
        with sqlite3.connect(os.environ["MEDUSA_DB"]) as raw:
            raw.row_factory = sqlite3.Row
            raw.execute("UPDATE nodes SET online = 1, seen_at = 555, agent_version = '0.0.1' WHERE id = ?", (kept["id"],))
            raw.commit()
        client.patch(f"/api/nodes/{kept['id']}", json={"name": "keepme2", "address": "127.0.0.1", "apiPort": 1})
        with sqlite3.connect(os.environ["MEDUSA_DB"]) as raw:
            raw.row_factory = sqlite3.Row
            row = raw.execute("SELECT online, seen_at, agent_version FROM nodes WHERE id = ?", (kept["id"],)).fetchone()
        ok(row["online"] == 1 and row["seen_at"] == 555 and row["agent_version"] == "0.0.1",
           "та же адрес/порт/ключ — прежняя связь остаётся подтверждённой")
        client.patch(f"/api/nodes/{kept['id']}", json={"address": "127.0.0.2"})
        with sqlite3.connect(os.environ["MEDUSA_DB"]) as raw:
            raw.row_factory = sqlite3.Row
            row = raw.execute("SELECT online, seen_at, agent_version FROM nodes WHERE id = ?", (kept["id"],)).fetchone()
        ok(row["online"] == 0 and row["seen_at"] == 0 and row["agent_version"] is None,
           "поменяли адрес — панель больше не считает связь подтверждённой")
        client.delete(f"/api/nodes/{kept['id']}")

        clash = client.patch(f"/api/nodes/{fi['id']}", json={"name": "home-renamed"})
        ok(clash.status_code == 409, f"такое имя ноды уже занято -> {clash.json()['detail']}")
        client.patch(f"/api/nodes/{home['id']}", json={"name": "home"})

        # --- правка хоста: PATCH по частям, как и положено правке ---
        fi_host = next(h for h in client.get("/api/hosts").json() if h["name"] == "FI Reality")
        edited = client.patch(f"/api/hosts/{fi_host['id']}", json={
            "name": "FI Reality v2", "port": 9412, "dest": "mask.example.net:443", "fp": "chrome"}).json()
        ok(edited["name"] == "FI Reality v2" and edited["port"] == 9412, "хосту поменяли имя и порт")
        ok(edited["dest"] == "mask.example.net:443" and edited["fp"] == "chrome",
           "reality-настройки хоста сохранены при правке")
        busy = client.post("/api/hosts", json={"name": "занято", "node": "vps-fi", "protocol": "vless",
                                               "port": 9412, "network": "tcp", "security": "none"})
        ok(busy.status_code == 409, "новый хост не лезет на порт, занятый при правке")
        reverted = client.patch(f"/api/hosts/{fi_host['id']}", json={"name": "FI Reality", "port": 443}).json()
        ok(reverted["port"] == 443 and reverted["name"] == "FI Reality", "правку откатывают так же легко, как делают")
        cross = client.patch(f"/api/hosts/{fi_host['id']}", json={"certFile": "/etc/ssl/a.crt"})
        ok(cross.status_code == 400, f"поле tls для reality-хоста отвергается: {cross.json()['detail']}")
        sni_cross = client.patch(f"/api/hosts/{fi_host['id']}", json={"sni": "x.example.net"})
        ok(sni_cross.status_code == 400, f"sni — поле tls, у reality для этого есть serverNames -> {sni_cross.json()['detail']}")
        names = client.patch(f"/api/hosts/{fi_host['id']}", json={"serverNames": "fi.example.net alt.example.net"}).json()
        ok(names["serverNames"] == "fi.example.net alt.example.net", "reality записал список sni")
        fp_none = client.post("/api/hosts", json={"name": "прямой", "node": "vps-fi", "protocol": "vless",
                                                  "port": 9416, "network": "tcp", "security": "none", "fp": "chrome"})
        ok(fp_none.status_code == 400, f"отпечаток без шифрования отвергается: {fp_none.json()['detail']}")
        bad_path = client.patch(f"/api/hosts/{fi_host['id']}", json={"path": "/x"})
        ok(bad_path.status_code == 400, f"путь без websocket отвергается: {bad_path.json()['detail']}")
        ip_addr = client.patch(f"/api/hosts/{fi_host['id']}", json={"address": "1.2.3.4"})
        ok(ip_addr.status_code == 200,
           "reality-хост может иметь и IP-адрес: sni ему даёт сайт маскировки, а не адрес")
        client.patch(f"/api/hosts/{fi_host['id']}", json={"address": "fi.example.net"})
        tls_ws = client.post("/api/hosts", json={"name": "TLS WS", "node": "vps-fi", "protocol": "vless",
                                                 "port": 9413, "network": "ws", "security": "tls",
                                                 "address": "ws.example.net", "path": "/tunnel",
                                                 "hostHeader": "cdn.example.net", "sni": "tls.example.net",
                                                 "fp": "safari"}).json()
        ok(tls_ws["path"] == "/tunnel" and tls_ws["hostHeader"] == "cdn.example.net",
           "транспортные поля websocket сохранены при создании")
        ok(tls_ws["sni"] == "tls.example.net" and tls_ws["fp"] == "safari",
           "tls записал sni и отпечаток")
        half = client.patch(f"/api/hosts/{tls_ws['id']}", json={"certFile": "/etc/ssl/medusa.crt"})
        ok(half.status_code == 400, f"сертификат без ключа отвергается: {half.json()['detail']}")
        pair = client.patch(f"/api/hosts/{tls_ws['id']}", json={"certFile": "/etc/ssl/medusa.crt",
                                                                "keyFile": "/etc/ssl/medusa.key"}).json()
        ok(pair["certFile"] == "/etc/ssl/medusa.crt" and pair["keyFile"] == "/etc/ssl/medusa.key",
           "свой сертификат — оба пути приняты")
        weird = client.patch(f"/api/hosts/{tls_ws['id']}", json={"certFile": "/etc/ssl/medusa.zip",
                                                                 "keyFile": "/etc/ssl/medusa.key"})
        ok(weird.status_code == 400, f"чужое расширение сертификата отвергается: {weird.json()['detail']}")
        cleared = client.patch(f"/api/hosts/{tls_ws['id']}", json={"path": "", "certFile": "", "keyFile": ""}).json()
        ok(cleared["path"] == "" and cleared["certFile"] == "",
           "пустое поле при правке означает «сбросить», а не «оставить»")
        clash_tls_doc = _yaml.safe_load(client.get(f"/sub/{brother['token']}",
                                                   headers={"Accept": "*/*", "User-Agent": "clash"}).text)
        tls_proxy = next(p for p in clash_tls_doc["proxies"] if p["name"] == "TLS WS")
        ok(tls_proxy["skip-cert-verify"] is True and tls_proxy["servername"] == "tls.example.net"
           and "alpn" not in tls_proxy,
           "clash yaml: tls-хост с self-signed не заставит Clash проверять чужой сертификат")
        client.delete(f"/api/hosts/{tls_ws['id']}")
        mini = client.post("/api/chains", json={"name": "MINI", "hops": [
            {"node": "vps-fi", "protocol": "vless", "network": "tcp", "security": "reality", "port": 3011},
            {"node": "home", "protocol": "vless", "network": "tcp", "security": "reality", "port": 3012}]}).json()
        mini_host = next(h for h in client.get("/api/hosts").json() if h["chain"] == mini["id"])
        alone = client.patch(f"/api/hosts/{mini_host['id']}", json={"port": 3099})
        ok(alone.status_code == 409, f"хост цепочки поодиночке не правится -> {alone.json()['detail']}")
        client.delete(f"/api/chains/{mini['id']}")

        # --- удаление ноды уносит связанные хосты ---
        ok(client.delete(f"/api/nodes/{fi['id']}").status_code == 204, "удалить ноду")

        # --- опрос нод по таймеру: тот же поход, что у кнопки, только без человека ---
        from src.panel import poller

        ok(poller.enabled() is False, "MEDUSA_NODE_AUTO=0 выключает опрос нод")
        os.environ.pop("MEDUSA_NODE_AUTO")
        ok(poller.enabled() is True, "без переменной панель опрашивает ноды сама")
        os.environ["MEDUSA_NODE_AUTO"] = "0"

        with sqlite3.connect(os.environ["MEDUSA_DB"]) as raw:
            raw.row_factory = sqlite3.Row
            saved = raw.execute("SELECT pollInterval FROM settings WHERE id = 1").fetchone()[0]
            ok(poller.poll_interval(raw) == saved, f"интервал опроса = настройка панели: {saved} с")
            before = len(poller.pollable(raw))
            raw.execute("""INSERT INTO nodes (name, address, online, api_port, api_key, created_at)
                            VALUES ('nokey', '127.0.0.1', 0, 9443, '', 1)""")
            raw.commit()
            ok(len(poller.pollable(raw)) == before, "ноду без API-ключа опрос не спрашивает")
            nokey_id = raw.execute("SELECT id FROM nodes WHERE name = 'nokey'").fetchone()[0]
        client.delete(f"/api/nodes/{nokey_id}")

        client.patch("/api/settings", json={"pollInterval": 11})
        with sqlite3.connect(os.environ["MEDUSA_DB"]) as raw:
            raw.row_factory = sqlite3.Row
            ok(poller.poll_interval(raw) == 11, "сменили настройку — опрос пойдёт уже с новым интервалом")
        too_small = client.patch("/api/settings", json={"pollInterval": 1})
        ok(too_small.status_code == 422, f"частый опрос дороже самой проверки: {too_small.status_code}")

        node_port = os.getenv("MEDUSA_TEST_NODE_PORT")
        node_key = os.getenv("MEDUSA_TEST_NODE_KEY")
        if node_port and node_key:
            live = client.post("/api/nodes", json={"name": "live", "address": "127.0.0.1",
                                                   "apiPort": int(node_port), "apiKey": node_key}).json()
            rep = client.post(f"/api/nodes/{live['id']}/check", json={}).json()
            ok(rep["ok"] is True and rep["keyOk"] is True, f"панель достучалась до ноды: агент {rep['node']['agentVersion']}")
            ok(rep["node"]["role"] == "medusa-node", f"по ответу видно, что на порту Medusa-нода: {rep['node']['role']}")
            ok(rep["node"]["fingerprint"] == rep["panelFingerprint"], "отпечаток ключа на ноде и в панели совпал")
            ok(rep["node_row"]["online"] is True and rep["node_row"]["agent"],
               f"панель запомнила ноду: {rep['node_row']['agent']}, {rep['node_row']['seenAt']}")

            wrong = client.patch(f"/api/nodes/{live['id']}", json={"apiKey": "sk-api-another0123456789000"}).json()
            bad = client.post(f"/api/nodes/{wrong['id']}/check", json={}).json()
            ok(bad["reachable"] is True and bad["keyOk"] is False and bad["online"] is False,
               "не тот ключ: нода отвечает, но работать с ней нельзя")
            ok("не подходит" in bad["error"], f"нода отвергла чужой ключ: {bad['error']}")
            ok(bad["reachable"] is True and bad["panelFingerprint"] != bad["node"]["fingerprint"],
               "отпечатки ключа панели и ноды разошлись")

            fixed = client.patch(f"/api/nodes/{live['id']}", json={"apiKey": node_key}).json()
            again = client.post(f"/api/nodes/{fixed['id']}/check", json={}).json()
            ok(again["ok"] is True and again["node_row"]["online"] is True, "ключ починили — нода снова в сети")

            again_wrong = client.post(f"/api/nodes/{fixed['id']}/check", json={}).json()
            ok(again_wrong["ok"] is True, "с правильным API-ключом связка снова работает")
        else:
            print("SKIP  связка с живой нодой: MEDUSA_TEST_NODE_PORT / MEDUSA_TEST_NODE_KEY не заданы")
        ok(all(h["node"] != "vps-fi" for h in client.get("/api/hosts").json()), "хосты ноды удалились cascade'ом")

        # --- вход и сессии ---
        ok(client.post("/api/login", json={"username": "admin", "password": "wrongpass1"}).status_code == 400, "неверный пароль отклонён")
        session = client.post("/api/login", json={"username": "admin", "password": "supersecret1"}).json()
        auth = {"Authorization": f"Bearer {session['token']}"}
        ok(session["admin"]["role"] == "owner", f"вход владельца: {session['admin']['username']}")
        me = client.get("/api/me", headers=auth).json()
        ok(me["username"] == "admin", f"/api/me: {me['username']}")
        admins = client.get("/api/admins", headers=auth).json()
        ok(any(a["username"] == "admin" and a["self"] for a in admins), "свой аккаунт помечен в списке админов")
        ok(client.patch("/api/admins", json={}).status_code in (404, 405), "у списка админов нет случайного PATCH")
        new_admin = client.post("/api/admins", json={"username": "mila", "password": "viewerpass1"}, headers=auth).json()
        ok(new_admin["role"] == "admin" and new_admin["self"] is False, f"создан администратор {new_admin['username']} (роль не выбирается)")
        mila = client.post("/api/login", json={"username": "mila", "password": "viewerpass1"}).json()
        ok(client.get("/api/me", headers={"Authorization": f"Bearer {mila['token']}"}).json()["username"] == "mila",
           "администратор тоже может войти")
        admin_write = client.post("/api/users", json={"name": "admin-write"}, headers={"Authorization": f"Bearer {mila['token']}"})
        ok(admin_write.status_code == 201, "администратор может писать в панель")
        owner_try = client.patch(f"/api/admins/{next(a['id'] for a in client.get('/api/admins', headers=auth).json() if a['role'] == 'owner')}",
                                 json={"status": "disabled"}, headers={"Authorization": f"Bearer {mila['token']}"})
        ok(owner_try.status_code == 403, f"администратор не трогает владельца: {owner_try.json()['detail']}")
        ok(client.patch(f"/api/admins/{new_admin['id']}", json={"status": "disabled"}, headers=auth).json()["status"] == "disabled",
           "администратора отключили")
        ok(client.get("/api/me", headers={"Authorization": f"Bearer {mila['token']}"}).status_code == 401,
           "отключённый администратор теряет сессию")
        ok(client.post("/api/login", json={"username": "mila", "password": "viewerpass1"}).status_code == 409,
           "отключённый администратор не может войти")
        owner = next(a for a in admins if a["role"] == "owner")
        ok(client.patch(f"/api/admins/{owner['id']}", json={"status": "disabled"}, headers=auth).status_code == 409, "владельца не отключить")
        ok(client.delete(f"/api/admins/{owner['id']}", headers=auth).status_code == 409, "владельца не удалить")
        changed = client.patch(f"/api/admins/{owner['id']}", json={"password": "anothersecret1"}, headers=auth)
        ok(changed.status_code == 200, "владелец меняет свой пароль")
        ok(client.get("/api/me", headers=auth).status_code == 200, "своя сессия при смене пароля остаётся рабочей")
        fresh = client.post("/api/login", json={"username": "admin", "password": "anothersecret1"}).json()
        auth = {"Authorization": f"Bearer {fresh['token']}"}
        ok(client.get("/api/me", headers=auth).json()["username"] == "admin", "новый пароль работает")
        other_pass = client.patch(f"/api/admins/{new_admin['id']}", json={"password": "hackedsecret1"}, headers=auth)
        ok(other_pass.status_code == 409, f"пароль чужого аккаунта не меняется даже владельцем: {other_pass.json()['detail']}")

        # --- MEDUSA_AUTH=0: разработка без учётки, и она же выключается обратно ---
        os.environ["MEDUSA_AUTH"] = "0"
        ok(client.post("/api/users", json={"name": "anonymous"}).status_code == 201,
           "MEDUSA_AUTH=0: панель открыта без токена — только для своей машины")
        ok(client.get("/api/users").status_code == 200, "MEDUSA_AUTH=0: чтение без токена")
        os.environ.pop("MEDUSA_AUTH")
        anon = {"Authorization": ""}
        no_auth = client.post("/api/users", json={"name": "anonymous2"}, headers=anon)
        ok(no_auth.status_code == 401, f"авторизация включена обратно: без сессии запись закрыта ({no_auth.status_code})")
        with_auth = client.post("/api/users", json={"name": "anonymous2"}, headers=auth)
        ok(with_auth.status_code == 201, f"под владельцем запись проходит ({with_auth.status_code} {with_auth.json()})")
        ok(client.get("/api/users", headers=anon).status_code == 401, "и читать без сессии нельзя")

        meta = client.get("/api/meta").json()
        ok(meta["name"] == "medusa" and meta["version"] == "0.1.0", f"/api/meta отдаёт имя и версию: {meta}")
        page = client.get("/")
        ok(page.status_code == 200 and 'id="view"' in page.text, "статика и API живут рядом")
        ok(client.get("/api/chains").status_code == 200, "список цепочек работает")

    chain_migration_checks()
    traffic_checks(client)

    print(f"\nпровалов: {FAILS}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())

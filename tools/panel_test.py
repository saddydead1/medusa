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
from src.core.version import project_version  # noqa: E402

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
    conn.close()

    # вторая прежняя база: порт хопа прежней цепочки совпадает с API-портом соседней ноды
    # на той же машине. Пока хопа были описанием — безразлично; теперь у хопа свой инбаунд,
    # и на этой машине Xray упал бы целиком (вместе с здоровыми хостами ноды).
    clash = Path(tempfile.mkdtemp(prefix="medusa-clashchain-")) / "clash.db"
    init_db(clash)
    conn = connect(clash)
    node_a = conn.execute("INSERT INTO nodes (name, address, api_port, api_key, created_at) "
                          "VALUES ('nodaa','10.9.1.1',8443,'sk-api-a0123456789012345',1)").lastrowid
    node_b = conn.execute("INSERT INTO nodes (name, address, api_port, api_key, created_at) "
                          "VALUES ('nodab','10.9.1.1',9443,'sk-api-b0123456789012345',1)").lastrowid
    conn.execute("INSERT INTO hosts (name, node_id, protocol, port, network, security, created_at) "
                 "VALUES ('живой хост', ?, 'vless', 7443, 'tcp', 'none', 1)", (node_a,))
    clash_hops = [{"node_id": node_a, "protocol": "vless", "network": "tcp", "security": "none", "port": 8443},
                  {"node_id": node_b, "protocol": "vless", "network": "tcp", "security": "none", "port": 443}]
    clash_chain = conn.execute("INSERT INTO chains (name, hops, created_at) VALUES ('прежняя-столкновение', ?, 1)",
                               (json.dumps(clash_hops),)).lastrowid
    conn.execute("""INSERT INTO hosts (name, node_id, protocol, port, network, security, chain_id, hop_index, created_at)
                    VALUES ('прежняя-столкновение', ?, 'vless', 8443, 'tcp', 'none', ?, 0, 1)""",
                 (node_a, clash_chain))
    conn.commit()
    conn.close()

    notes = init_db(clash)
    conn = connect(clash)
    hop_row = conn.execute("""SELECT h.port, h.name FROM hosts h WHERE h.chain_id = ? ORDER BY h.hop_index""",
                           (clash_chain,)).fetchall()
    moved_port = hop_row[0]["port"]
    ok(moved_port != 8443 and moved_port not in {8443, 9443, 7443},
       f"миграция убрала хопа с занятого порта: {hop_row[0]['name']} переехал на {moved_port}")
    stored = json.loads(conn.execute("SELECT hops FROM chains WHERE id = ?", (clash_chain,)).fetchone()["hops"])
    ok(stored[0]["port"] == moved_port,
       "миграция записала новый порт и в hops цепочки: окно правки показывает то, что есть")
    ok(any("уже занят API-портом" in note for note in notes),
       f"миграция сказала человеку, что она сдвинула и почему: {notes}")
    healthy = conn.execute("SELECT port FROM hosts WHERE chain_id IS NULL").fetchall()
    ok([r["port"] for r in healthy] == [7443],
       "порты обычных хостов миграция не трогает: их выбирал человек")
    conn.close()

    conn = connect(path)
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

def port_and_hop_checks(client: TestClient) -> None:
    """Порт считается занятым по машине ноды, а у хопа цепочки есть свой адрес.

    Первая часть проверяет аварию, которую панель устраивала сама: две ноды на одном адресе
    (одна машина), и хост или хоп цепочки просит порт, который там уже держит API-порт
    соседней ноды. Xray половинки конфига не поднимает — он падает целиком, и у ноды
    останавливается всё, включая вчерашние рабочие хосты.

    Вторая часть — адрес хопа: соседняя нода обязана приходить туда же, куда панель
    отправляет человеку ссылку на вход цепочки.
    """
    from src.panel import ports
    from src.panel.config_push import collect
    from src.panel.db import connect

    # две ноды на одном адресе = одна машина. Это нормальная ситуация (несколько нод в
    # контейнерах на одном хосте), но слушатели у них общие
    mach_a = client.post("/api/nodes", json={"name": "machine-a", "address": "10.9.2.1",
                                             "apiPort": 8443, "apiKey": "sk-api-macha0123456789012"}).json()
    mach_b = client.post("/api/nodes", json={"name": "machine-b", "address": "10.9.2.1",
                                             "apiPort": 9443, "apiKey": "sk-api-machb0123456789012"}).json()
    ok(mach_b.get("apiPort") == 9443, "соседняя нода на том же адресе с другим API-портом — нормально")
    twin = client.post("/api/nodes", json={"name": "machine-c", "address": "10.9.2.1",
                                           "apiPort": 9443, "apiKey": "sk-api-machc0123456789012"})
    ok(twin.status_code == 409 and "API-портом" in twin.json()["detail"],
       f"дважды слушать один порт на одной машине панель не позволяет: {twin.json()['detail']}")

    clash = client.post("/api/hosts", json={"name": "чужой api порт", "node": "machine-b", "protocol": "vless",
                                            "port": 8443, "network": "tcp", "security": "none"})
    ok(clash.status_code == 409 and "API-портом" in clash.json()["detail"],
       f"хост не может занять API-порт соседней ноды на той же машине: {clash.json()['detail']}")

    hop_clash = client.post("/api/chains", json={"name": "на занятом", "hops": [
        {"node": "machine-b", "protocol": "vless", "network": "tcp", "security": "none", "port": 8443},
        {"node": "home", "protocol": "vless", "network": "tcp", "security": "none", "port": 8445}]})
    ok(hop_clash.status_code == 409 and "API-портом" in hop_clash.json()["detail"],
       f"хост цепочки — такой же слушатель на той же машине: {hop_clash.json()['detail']}")

    same_machine = client.post("/api/chains", json={"name": "одна машина", "hops": [
        {"node": "machine-b", "protocol": "vless", "network": "tcp", "security": "none", "port": 8801},
        {"node": "machine-a", "protocol": "vless", "network": "tcp", "security": "none", "port": 8801}]})
    ok(same_machine.status_code == 409,
       f"хопа одной цепочки на одной машине не могут занять один порт: {same_machine.json()['detail']}")

    host_a = client.post("/api/hosts", json={"name": "хост машины a", "node": "machine-a", "protocol": "vless",
                                             "port": 9101, "network": "tcp", "security": "none"}).json()
    api_taken = client.patch(f"/api/nodes/{mach_b['id']}", json={"apiPort": 9101})
    ok(api_taken.status_code == 409 and "9101" in api_taken.json()["detail"],
       f"API-порт ноды не наступает на порт хоста той же машины: {api_taken.json()['detail']}")
    move = client.patch(f"/api/nodes/{mach_b['id']}", json={"address": "10.8.0.1"})
    ok(move.status_code == 409,
       f"переезд ноды на чужую машину проверяется по её хостам тоже: {move.json()['detail']}")

    chain = client.post("/api/chains", json={"name": "Со своим адресом", "hops": [
        {"node": "home", "protocol": "vless", "network": "tcp", "security": "none", "port": 8811,
         "address": "home-public.example.net"},
        {"node": "machine-b", "protocol": "trojan", "network": "tcp", "security": "none", "port": 8812,
         "address": "10.9.2.9"}]}).json()
    ok(chain["hops"][0]["address"] == "home-public.example.net"
       and chain["hops"][1]["address"] == "10.9.2.9",
       f"адрес хопа сохраняется в цепочке: {[h['address'] for h in chain['hops']]}")
    hosts = client.get("/api/hosts").json()
    entry = next(h for h in hosts if h["chain"] == chain["id"])
    ok(entry["address"] == "home-public.example.net",
       f"хост цепочки (её вход) имеет свой адрес, а не пустой: {entry['address']}")

    # конфиг отправляющей ноды: outbound обязан идти на адрес следующего хопа
    home_id = next(n["id"] for n in client.get("/api/nodes").json() if n["name"] == "home")
    probe = connect()
    try:
        cfg_home = collect(probe, home_id)["config"]
    finally:
        probe.close()
    link = next((o for o in cfg_home["outbounds"] if o["tag"].endswith("-> hop 2")), {})
    target = (link.get("settings", {}).get("vnext") or link.get("settings", {}).get("servers") or [{}])[0]
    ok(target.get("address") == "10.9.2.9" and target.get("port") == 8812,
       f"переход соседней ноды идёт на адрес хопа, а не на адрес его ноды: {target}")
    entry_in = next((i for i in cfg_home["inbounds"] if i["tag"] == chain["name"]), {})
    ok(bool(entry_in), f"вход цепочки — инбаунд своей ноды на её порту: {entry_in.get('port')}")

    client.delete(f"/api/chains/{chain['id']}")
    client.delete(f"/api/nodes/{mach_b['id']}")
    client.delete(f"/api/nodes/{mach_a['id']}")


def proxy_setting_checks(client: TestClient) -> None:
    """Прокси ноды: форму принимает панель, наружу отдаёт без пароля, а окно правки
    получает значение целиком — иначе сохранение диалога стирало бы учётку прокси.

    Живой socks5-прокси проверяется отдельно, в блоке со связкой с нодой: здесь же только
    то, что видно по одному HTTP — нормализация, отказ чужой схемы, masked-форма.
    """
    from src.panel.proxy_url import mask_proxy, normalize_proxy

    ok(normalize_proxy("10.0.0.1:1080") == "socks5://10.0.0.1:1080",
       "человек мог написать просто host:port — панель понимает так же")
    ok(normalize_proxy("socks5h://jump.example") == "socks5h://jump.example:1080",
       "без порта берётся разумный 1080")
    ok(normalize_proxy("socks5://[::1]:1080") == "socks5://[::1]:1080", "IPv6-адрес прокси сохраняется")
    for bad, why in (("http://p:3128", "чужая схема"), ("socks5://", "нет адреса"),
                     ("socks5://h:0", "порт вне диапазона"), ("socks5://h:1/p", "лишнее после адреса"),
                     ("socks5://:pw@h:1080", "пароль без имени")):
        try:
            normalize_proxy(bad)
            ok(False, f"{why}: панель должна отвергать {bad!r}")
        except ValueError as err:
            ok(True, f"{why}: {err}")
    ok(mask_proxy("socks5://med:pw@j.example:1080") == "socks5://med:••••@j.example:1080",
       "masked-форма прокси: адрес виден, пароля нет")

    node = client.post("/api/nodes", json={"name": "behind-nat", "address": "10.9.3.1",
                                          "apiKey": "sk-api-behind01234567890123",
                                          "proxy": "jump.example:1080"}).json()
    ok(node["proxy"] == "socks5://jump.example:1080" and node["proxySet"] is True,
       f"нода создана через прокси: {node['proxy']}")
    listed = next(n for n in client.get("/api/nodes").json() if n["id"] == node["id"])
    ok(listed["proxy"] == "socks5://jump.example:1080", "в списке прокси виден как адрес, не как учётка")

    secret = client.post("/api/nodes", json={"name": "behind-auth", "address": "10.9.3.2",
                                            "apiKey": "sk-api-behind02345678901234",
                                            "proxy": "socks5://med:proxysecret@jump.example:1080"}).json()
    ok(secret["proxy"] == "socks5://med:••••@jump.example:1080",
       f"пароль прокси не показывается в ответе создания: {secret['proxy']}")
    ok("proxysecret" not in json.dumps(client.get("/api/nodes").json()),
       "ни в одном списке нод пароля прокси нет")
    full = client.get(f"/api/nodes/{secret['id']}/proxy")
    ok(full.status_code == 200 and full.json()["proxy"] == "socks5://med:proxysecret@jump.example:1080",
       "окну правки прокси отдаётся целиком — отдельным запросом")

    bad = client.patch(f"/api/nodes/{node['id']}", json={"proxy": "https://p:8080"})
    ok(bad.status_code == 422 and "socks5" in bad.json()["detail"],
       f"чужая схема отвергается человеческим текстом: {bad.json()['detail']}")

    moved = client.patch(f"/api/nodes/{node['id']}", json={"proxy": "socks5://backup.example:1080"}).json()
    ok(moved["proxy"] == "socks5://backup.example:1080", "прокси можно сменить")
    cleared = client.patch(f"/api/nodes/{node['id']}", json={"proxy": ""}).json()
    ok(cleared["proxy"] == "" and cleared["proxySet"] is False, "пустая строка — прокси снят, нода ходит напрямую")
    ok(client.get(f"/api/nodes/{node['id']}/proxy").json()["proxy"] == "", "у снятого прокси полный ответ пустой")

    for name in ("behind-nat", "behind-auth"):
        nid = next(n["id"] for n in client.get("/api/nodes").json() if n["name"] == name)
        client.delete(f"/api/nodes/{nid}")


def hop_settings_checks(client: TestClient) -> None:
    """Детали защиты и транспорта у хопа цепочки — свои на каждый хоп.

    Смысл проверки не в том, что поля «сохраняются в json цепочки». Важное другое:
    один и тот же ряд hosts читает и инбаунд самого хопа, и переход соседней ноды,
    поэтому названный человеком путь или маскированный адрес обязан оказаться на обеих
    сторонах перехода — иначе цепочка «настраивается» в окне, а на ноде работает по умолчанию.
    """
    import hashlib

    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    from src.panel.config_push import collect
    from src.panel.db import connect

    for name, address in (("hop-a", "10.9.5.1"), ("hop-b", "10.9.5.2"), ("hop-c", "10.9.5.3")):
        client.post("/api/nodes", json={"name": name, "address": address,
                                       "apiKey": f"sk-api-{name}01234567890000"})
    ids = {n["name"]: n["id"] for n in client.get("/api/nodes").json()}

    created = client.post("/api/chains", json={"name": "hop-settings", "hops": [
        {"node": "hop-a", "protocol": "vless", "network": "ws", "security": "none", "port": 8831,
         "path": "/cdn-live", "hostHeader": "cdn.example.net"},
        {"node": "hop-b", "protocol": "trojan", "network": "ws", "security": "tls", "port": 8832,
         "sni": "named-hop.example.net", "rejectUnknownSni": True, "fp": "chrome",
         "path": "/hop-b-live", "hostHeader": "hopb.example.net"},
        {"node": "hop-c", "protocol": "vless", "network": "grpc", "security": "reality", "port": 8833,
         "dest": "mirror.example.org:443", "serverNames": "mirror.example.org, backup.example.org",
         "serviceName": "medusa-chain", "grpcAuthority": "grpc.example.net", "fp": "edge"},
    ]}).json()
    saved = {hop["node"]: hop for hop in created["hops"]}
    ok(saved["hop-a"]["path"] == "/cdn-live" and saved["hop-a"]["hostHeader"] == "cdn.example.net",
       f"websocket-детали хопа сохранены и вернулись в цепочку: {saved['hop-a']['path']}")
    ok(saved["hop-b"]["sni"] == "named-hop.example.net" and saved["hop-b"]["rejectUnknownSni"] is True,
       f"tls-хоп назвал свой sni и отношение к чужому SNI: {saved['hop-b']['sni']}")
    ok(saved["hop-c"]["dest"] == "mirror.example.org:443"
       and "backup.example.org" in saved["hop-c"]["serverNames"]
       and saved["hop-c"]["serviceName"] == "medusa-chain",
       f"reality-хоп назвал маску, принимаемые имена и имя сервиса gRPC")

    probe = connect()
    try:
        cfg_a = collect(probe, ids["hop-a"])["config"]
        cfg_b = collect(probe, ids["hop-b"])["config"]
        cfg_c = collect(probe, ids["hop-c"])["config"]
    finally:
        probe.close()

    in_a = next(i for i in cfg_a["inbounds"] if i["tag"] == "hop-settings")
    out_a = next(o for o in cfg_a["outbounds"] if o["tag"].endswith("-> hop 2"))
    ws_a = in_a.get("streamSettings", {}).get("wsSettings") or {}
    ws_out = out_a.get("streamSettings", {}).get("wsSettings") or {}
    ok(ws_a.get("path") == "/cdn-live" and ws_a.get("host") == "cdn.example.net",
       f"инбаунд входа цепочки слушает на названных websocket-детях: {ws_a}")
    # переход соседней ноды собирается из деталей Того хопа, куда идёт трафик: у перехода
    # нет своего транспорта, есть только приёмник
    ok(ws_out.get("path") == "/hop-b-live" and ws_out.get("host") == "hopb.example.net",
       f"переход использует websocket-детали хопа-приёмника: {ws_out}")

    tls_out = out_a.get("streamSettings", {}).get("tlsSettings") or {}
    ok(tls_out.get("serverName") == "named-hop.example.net" and tls_out.get("pinnedPeerCertSha256"),
       f"переход идёт на sni хопа и закрепляет его сертификат: {tls_out.get('serverName')}")

    in_b = next(i for i in cfg_b["inbounds"] if i["tag"].endswith("hop 2"))
    tls_in = in_b.get("streamSettings", {}).get("tlsSettings") or {}
    ws_in_b = in_b.get("streamSettings", {}).get("wsSettings") or {}
    ok(tls_in.get("rejectUnknownSni") is True,
       "hoповый tls-инбаунд отвергает чужой SNI, человек просил именно это")
    ok(ws_in_b.get("path") == "/hop-b-live",
       f"hoповый инбаунд слушает тот же путь, по которому приходит сосед: {ws_in_b.get('path')}")
    out_b = next(o for o in cfg_b["outbounds"] if o["tag"].endswith("-> hop 3"))
    stream_b = out_b.get("streamSettings", {})
    reality_b = stream_b.get("realitySettings") or {}
    ok(stream_b.get("grpcSettings", {}).get("serviceName") == "medusa-chain",
       f"переход в grpc-хоп использует имя сервиса этого хопа: {stream_b.get('grpcSettings')}")
    ok(reality_b.get("serverName") == "mirror.example.org" and reality_b.get("fingerprint") == "edge",
       f"переход называет маску reality-хопа и его отпечаток: {reality_b.get('serverName')}")

    in_c = next(i for i in cfg_c["inbounds"] if i["tag"].endswith("hop 3"))
    reality_c = in_c.get("streamSettings", {}).get("realitySettings") or {}
    ok(reality_c.get("dest") == "mirror.example.org:443"
       and reality_c.get("serverNames") == ["mirror.example.org", "backup.example.org"],
       f"reality-хоп принимает названные имена и прячется за названной маской: {reality_c.get('serverNames')}")
    ok(in_c.get("streamSettings", {}).get("grpcSettings", {}).get("serviceName") == "medusa-chain",
       "grpc-хоп слушает на том же имени сервиса, на которое приходит сосед")

    # tls-сертификат хопа обязан называться тем именем, которое назовёт сосед: Xray 26
    # сверяет SNI с сертификатом, и «имя в окне ≠ имя в сертификате» = отказ рукопожатия
    with sqlite3.connect(os.environ["MEDUSA_DB"]) as raw:
        raw.row_factory = sqlite3.Row
        hop_row = raw.execute("SELECT sni, cert_pem, cert_sha256 FROM hosts WHERE security = 'tls' "
                              "AND chain_id IS NOT NULL").fetchone()
    cert = x509.load_pem_x509_certificate(hop_row["cert_pem"].encode())
    names = [c.value for c in cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)]
    ok(names == ["named-hop.example.net"],
       f"сертификат хопа выпущен на его же sni, а не на адрес ноды: CN={names[0]}")
    ok(hop_row["cert_sha256"] == hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest(),
       "отпечаток в базе = отпечаток этого сертификата: сосед закрепляет ровно его")

    patched = client.patch(f"/api/chains/{created['id']}", json={"name": "hop-settings", "hops": [
        {"node": "hop-a", "protocol": "vless", "network": "ws", "security": "none", "port": 8831,
         "path": "/changed"},
        {"node": "hop-b", "protocol": "trojan", "network": "ws", "security": "tls", "port": 8832,
         "sni": "renamed-hop.example.net", "path": "/changed-b"},
        {"node": "hop-c", "protocol": "vless", "network": "grpc", "security": "reality", "port": 8833,
         "dest": "other-mirror.example.org:443"},
    ]})
    ok(patched.status_code == 200, f"цепочка с деталями правится: {patched.status_code}")
    with sqlite3.connect(os.environ["MEDUSA_DB"]) as raw:
        cert2 = x509.load_pem_x509_certificate(raw.execute(
            "SELECT cert_pem FROM hosts WHERE security = 'tls' AND chain_id IS NOT NULL").fetchone()[0].encode())
    renamed = [c.value for c in cert2.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)]
    ok(renamed == ["renamed-hop.example.net"],
       f"сменили sni хопа — сертификат перевыпущен под новое имя: CN={renamed[0]}")
    probe = connect()
    try:
        out_a2 = next(o for o in collect(probe, ids["hop-a"])["config"]["outbounds"]
                      if o["tag"].endswith("-> hop 2"))
        in_b2 = next(i for i in collect(probe, ids["hop-b"])["config"]["inbounds"]
                     if i["tag"].endswith("hop 2"))
    finally:
        probe.close()
    ok(out_a2["streamSettings"]["wsSettings"]["path"] == "/changed-b"
       and out_a2["streamSettings"]["tlsSettings"]["serverName"] == "renamed-hop.example.net",
       "правка деталей хопа дошла до перехода: сосед пересобрался под новый путь и новый sni")
    ok(in_b2["streamSettings"]["wsSettings"]["path"] == "/changed-b",
       "правка деталей хопа дошла и до его же инбаунда: путь на ноде тот же, что у соседа")

    bad_cases = (
        ("путь при tcp", {"protocol": "vless", "network": "tcp", "security": "none", "port": 8841,
                          "path": "/x"}, "настройки websocket"),
        ("маска reality = IP", {"protocol": "vless", "network": "tcp", "security": "reality",
                                "port": 8842, "dest": "10.9.9.9:443"}, "обязан быть доменом"),
        ("свой сертификат хопу", {"protocol": "vless", "network": "tcp", "security": "tls",
                                  "port": 8843, "certFile": "/etc/ssl/x.crt", "keyFile": "/etc/ssl/x.key"},
         "сертификат хопа цепочки выпускает панель"),
        ("отпечаток без шифрования", {"protocol": "vless", "network": "tcp", "security": "none",
                                      "port": 8844, "fp": "chrome"}, "только при шифровании"),
        ("sni у reality-хопа", {"protocol": "vless", "network": "tcp", "security": "reality",
                                "port": 8845, "sni": "x.example.net"}, "настройки tls"),
        ("имя сервиса при tcp", {"protocol": "vless", "network": "tcp", "security": "none",
                                 "port": 8846, "serviceName": "medusa"}, "настройки gRPC"),
    )
    tail = {"node": "hop-b", "protocol": "vless", "network": "tcp", "security": "none", "port": 8847}
    for label, hop, expected in bad_cases:
        response = client.post("/api/chains", json={"name": "hop-bad", "hops": [
            {"node": "hop-a", **hop}, tail]})
        detail = response.json().get("detail", "")
        ok(response.status_code == 400 and expected in detail,
           f"{label}: {response.status_code} {detail}")

    client.delete(f"/api/chains/{created['id']}")
    for name in ("hop-a", "hop-b", "hop-c"):
        client.delete(f"/api/nodes/{ids[name]}")


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
        # приложение клиента — статистика на «Обзоре»: своё название должно сохраняться,
        # а пустая строка обязана означать «приложения нет» (тогда подписчик в «прочих»)
        relabeled = client.patch(f"/api/users/{brother['id']}",
                                 json={"client": "Foxv2ray", "name": "brother2"}).json()
        ok(relabeled["client"] == "Foxv2ray" and relabeled["name"] == "brother2",
           f"правка пользователя сохраняет имя и своё название приложения: {relabeled['name']}/{relabeled['client']}")
        cleared = client.patch(f"/api/users/{brother['id']}", json={"client": ""}).json()
        ok(cleared["client"] in (None, ""), f"приложение снимается пустой строкой: {cleared['client']!r}")
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

        # --- IPv6 на ноде: галочка, её границы и следует из неё или нет ---
        nov6 = client.post("/api/nodes", json={"name": "nov6", "address": "10.8.0.7",
                                               "apiKey": "sk-api-nov60000000000000000000",
                                               "ipv6Disabled": True}).json()
        ok(nov6["ipv6Disabled"] is True, "нода заведена с выключенным IPv6")
        ok(client.post("/api/nodes", json={"name": "v6node", "address": "2001:db8::7",
                                           "apiKey": "sk-api-v6node0000000000000000",
                                           "ipv6Disabled": True}).status_code == 400,
           "нельзя выключить IPv6 на ноде, чей адрес сам IPv6 (по нему ходит и панель, и подписчики)")
        v6host = client.post("/api/hosts", json={"name": "v6-host", "node": "nov6", "protocol": "vless",
                                                 "port": 8443, "address": "2001:db8::7"})
        ok(v6host.status_code == 400, f"хост с IPv6-адресом на ноде без IPv6 отвергнут: {v6host.json()['detail']}")
        v6hop = client.post("/api/chains", json={"name": "v6-chain", "hops": [
            {"node": "nov6", "protocol": "vless", "port": 8444, "address": "2001:db8::7"},
            {"node": "home", "protocol": "vless", "port": 8445, "address": "10.8.0.1"}]})
        ok(v6hop.status_code == 400, f"hop цепочки с IPv6-адресом на такой ноде отвергнут: {v6hop.json()['detail']}")
        back = client.patch(f"/api/nodes/{nov6['id']}", json={"ipv6Disabled": False}).json()
        ok(back["ipv6Disabled"] is False, "галочка снимается")
        with_v6 = client.post("/api/hosts", json={"name": "v6-ok", "node": "nov6", "protocol": "vless",
                                                  "port": 8443, "address": "2001:db8::7"})
        ok(with_v6.status_code == 201, "а при включённом IPv6 такой хост легален")
        denied = client.patch(f"/api/nodes/{nov6['id']}", json={"ipv6Disabled": True})
        ok(denied.status_code == 409, f"выключить IPv6, если у ноды уже есть хост с IPv6-адресом: {denied.json()['detail']}")
        ok(client.delete(f"/api/hosts/{with_v6.json()['id']}").status_code == 204, "хост убрали")
        ok(client.patch(f"/api/nodes/{nov6['id']}", json={"ipv6Disabled": True}).json()["ipv6Disabled"] is True,
           "теперь IPv6 выключается: мешающего хоста больше нет")
        ok(client.delete(f"/api/nodes/{nov6['id']}").status_code == 204, "тестовую ноду убрали")

        # --- API-ключ: создаёт его нода, панель только хранит и предъявляет ---
        keyed = client.post("/api/nodes", json={"name": "link", "address": "127.0.0.1",
                                                "apiPort": 19443, "apiKey": "sk-api-test123456789000000"}).json()
        ok(keyed["apiPort"] == 19443 and keyed["keySet"] is True,
           "нода заведена со своим портом API и API-ключом (порт не наступает на живую ноду теста)")
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

        # --- hysteria2 в цепочке: инбаунд хопа и переход в него ---
        hy2route = client.post("/api/chains", json={"name": "HY2-ROUTE", "hops": [
            {"node": "vps-fi", "protocol": "vless", "network": "tcp", "security": "reality", "port": 3121},
            {"node": "home", "protocol": "hy2", "network": "tcp", "security": "tls", "port": 3122,
             "sni": "hy2.hop.example.net"},
        ]}).json()
        cfg_fi3, cfg_home3 = node_config(fi["id"]), node_config(home["id"])
        hop_in = {i["tag"]: i for i in cfg_home3["inbounds"]}.get("HY2-ROUTE hop 2") or {}
        hop_out = {o["tag"]: o for o in cfg_fi3["outbounds"]}.get("HY2-ROUTE -> hop 2") or {}
        ok(hop_in.get("protocol") == "hysteria" and hop_in.get("settings", {}).get("version") == 2,
           "hy2-хоп: инбаунд своей ноды — hysteria2 (в Xray этот протокол называется hysteria "
           "и требует version 2)")
        ok(hop_out.get("protocol") == "hysteria" and hop_out.get("settings", {}).get("version") == 2
           and hop_out["settings"].get("address") == "10.8.0.1" and hop_out["settings"].get("port") == 3122,
           "переход в hy2-хоп: форма settings своя (address/port), адрес — адрес самого хопа")
        ok(hop_out["streamSettings"]["network"] == "hysteria"
           and hop_out["streamSettings"]["hysteriaSettings"]["auth"] == hop_in["settings"]["users"][0]["auth"],
           "auth перехода и auth инбаунда hy2-хопа выведены из одной цепочки: переход соберётся")
        pinned_hy2 = hop_out["streamSettings"]["tlsSettings"].get("pinnedPeerCertSha256", "")
        ok(len(pinned_hy2) == 64 and hop_in["streamSettings"]["tlsSettings"].get("certificates"),
           "сертификат hy2-хопа выпускает панель и закрепляет его отпечаток за соседней нодой")
        ok({"inboundTag": ["HY2-ROUTE"], "outboundTag": "HY2-ROUTE -> hop 2"} in cfg_fi3["routing"]["rules"],
           "вход hy2-цепочки уходит переходом, а не наружу напрямую")
        bad_hops = client.post("/api/chains", json={"name": "HY2-плохая", "hops": [
            {"node": "vps-fi", "protocol": "vless", "network": "tcp", "security": "none", "port": 3131},
            {"node": "home", "protocol": "hy2", "network": "ws", "security": "tls", "port": 3132}]})
        ok(bad_hops.status_code == 400 and "QUIC" in bad_hops.json()["detail"],
           f"hy2 поверх ws в цепочке отвергается: {bad_hops.json()['detail']}")
        bad_sec = client.post("/api/chains", json={"name": "HY2-без tls", "hops": [
            {"node": "vps-fi", "protocol": "vless", "network": "tcp", "security": "none", "port": 3133},
            {"node": "home", "protocol": "hy2", "network": "tcp", "security": "none", "port": 3134}]})
        ok(bad_sec.status_code == 400 and "tls" in bad_sec.json()["detail"],
           f"hy2-хоп без tls отвергается: {bad_sec.json()['detail']}")
        client.delete(f"/api/chains/{hy2route['id']}")
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

        from src.core.xray_config import SS_CIPHER, hy2_auth, ss_password, user_password, user_uuid

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

        # hysteria2: хост, его границы, ссылка и clash-прокси
        hy2_h = client.post("/api/hosts", json={"name": "Hysteria2", "node": "home", "protocol": "hy2",
                                                "port": 9435, "network": "tcp", "security": "tls",
                                                "address": "hy2.example.net",
                                                "sni": "hy2.example.net"}).json()
        ok(hy2_h["protocol"] == "hy2" and hy2_h["security"] == "tls",
           "hy2-хост заведён: панель умеет hysteria2 (в Xray — протокол hysteria v2)")
        for name, payload in (
            ("hy2+ws", {"name": "hy2 ws", "node": "home", "protocol": "hy2", "port": 9438,
                        "network": "ws", "security": "tls"}),
            ("hy2 без защиты", {"name": "hy2 none", "node": "home", "protocol": "hy2", "port": 9439,
                                "network": "tcp", "security": "none"}),
            ("hy2 + отпечаток", {"name": "hy2 fp", "node": "home", "protocol": "hy2", "port": 9440,
                                 "network": "tcp", "security": "tls", "fp": "chrome"}),
        ):
            bad = client.post("/api/hosts", json=payload)
            ok(bad.status_code == 400, f"{name} отвергается: {bad.json()['detail']}")
        hy2_lines = [l for l in client.get(f"/sub/{brother['token']}/links?raw=1").text.splitlines()
                     if l.startswith("hy2://")]
        ok(len(hy2_lines) == 1, f"hy2-ссылка появилась в подписке: {hy2_lines}")
        u = urlparse(hy2_lines[0])
        ok(u.netloc.rsplit("@", 1)[0] == hy2_auth(brother["token"], hy2_h["id"])
           and u.hostname == "hy2.example.net" and u.port == 9435,
           "hy2-ссылка: ключ человека собран из его токена и этого хоста, адрес — адрес хоста")
        ok(parse_qs(u.query).get("sni") == ["hy2.example.net"] and parse_qs(u.query).get("insecure") == ["1"],
           "hy2-ссылка называет sni и insecure: сертификат хосту выпускает нода, self-signed")
        hy2_clash = _yaml.safe_load(client.get(
            f"/sub/{brother['token']}",
            headers={"Accept": "*/*", "User-Agent": "clash-verge/v2.4.0"}).text)
        hy2_proxy = next(p for p in hy2_clash["proxies"] if p["name"] == "Hysteria2")
        ok(hy2_proxy["type"] == "hysteria2"
           and hy2_proxy["password"] == hy2_auth(brother["token"], hy2_h["id"])
           and hy2_proxy["sni"] == "hy2.example.net" and hy2_proxy["skip-cert-verify"] is True,
           "clash yaml: hysteria2-прокси с паролем из токена (проверяется живым Mihomo в live_demo)")
        shown = client.get(f"/api/nodes/{home['id']}/config").json()["config"]
        shown_hy2 = next(i for i in shown["inbounds"] if i["tag"] == "Hysteria2")
        ok(shown_hy2["protocol"] == "hysteria" and shown_hy2["settings"]["version"] == 2
           and all(c["auth"] == "скрыто панелью" for c in shown_hy2["settings"]["users"])
           and shown_hy2["streamSettings"]["network"] == "hysteria"
           and shown_hy2["streamSettings"]["hysteriaSettings"]["masquerade"]["type"] == "404",
           "окно «Конфиг Xray»: hy2 показан как hysteria v2 с masquerade, auth подписчиков скрыты")
        client.delete(f"/api/hosts/{hy2_h['id']}")
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
        # порты двух нод на одном адресе не должны наступать друг на друга: панель
        # иначе толкает два разных конфига одному и тому же агенту
        kept = client.post("/api/nodes", json={"name": "keepme", "address": "127.0.0.1",
                                               "apiPort": 19411, "apiKey": "sk-api-keepme01234567890123"}).json()
        with sqlite3.connect(os.environ["MEDUSA_DB"]) as raw:
            raw.row_factory = sqlite3.Row
            raw.execute("UPDATE nodes SET online = 1, seen_at = 555, agent_version = '0.0.1' WHERE id = ?", (kept["id"],))
            raw.commit()
        client.patch(f"/api/nodes/{kept['id']}", json={"name": "keepme2", "address": "127.0.0.1", "apiPort": 19411})
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

            # --- socks5: панель доходит до ноды через прокси ---
            # Это не украшение: нода может сидеть за NAT или быть доступна только через
            # прыжок. Проверка обязана видеть, что поход прошёл именно через прокси, и что
            # отказ прокси панель называет отказом прокси, а не «нода не ответила».
            sys.path.insert(0, str(ROOT / "tools"))
            from socks5 import Socks5Proxy

            plain = Socks5Proxy()
            plain.start()
            via = client.patch(f"/api/nodes/{fixed['id']}", json={"proxy": plain.url()}).json()
            ok(via["proxy"] == plain.url() and via["proxySet"] is True,
               f"нода сохранена через прокси: {via['proxy']}")
            through = client.post(f"/api/nodes/{via['id']}/check", json={}).json()
            ok(through["ok"] is True and through["proxy"] == plain.url(),
               f"связка через socks5: {through['via']}")
            ok(any(c.endswith(f":{node_port}") for c in plain.connections),
               f"прокси правда переключал соединения к ноде: {plain.connections}")

            plain.fail_next = True
            broken = client.post(f"/api/nodes/{via['id']}/check", json={}).json()
            ok(broken["ok"] is False and broken["reachable"] is False,
               f"если socks5 не пустил, нода не в сети: {broken['error']}")
            ok("прокси" in broken["error"], f"виноватый назван прямо: {broken['error']}")

            guarded = Socks5Proxy(username="medusa", password="sockssecret")
            guarded.start()
            secret_node = client.patch(f"/api/nodes/{via['id']}",
                                       json={"proxy": guarded.url()}).json()
            ok(secret_node["proxy"] == "socks5://medusa:••••@127.0.0.1:%d" % guarded.port,
               f"пароль прокси скрыт в ответе панели: {secret_node['proxy']}")
            guarded_check = client.post(f"/api/nodes/{via['id']}/check", json={}).json()
            ok(guarded_check["ok"] is True and guarded.connections,
               f"socks5 с паролем работает: {guarded_check['via']}")
            ok("sockssecret" not in json.dumps(client.get("/api/nodes").json()),
               "пароль прокси не утекает в список нод")

            # конфиг ноде доставляется тем же путём: доставка конфига и опрос ноды должны
            # ходить туда же, куда ходит кнопка «Проверить связь», а не мимо прокси
            before_push = len(guarded.connections)
            pushed = client.post(f"/api/nodes/{via['id']}/apply", json={}).json()
            ok(len(guarded.connections) > before_push,
               f"применение конфига прошло через тот же socks5: {pushed.get('error') or 'конфиг доставлен'}")

            direct = client.patch(f"/api/nodes/{via['id']}", json={"proxy": ""}).json()
            ok(direct["proxy"] == "" and direct["proxySet"] is False, "прокси снят — панель снова ходит напрямую")
            back = client.post(f"/api/nodes/{via['id']}/check", json={}).json()
            ok(back["ok"] is True and back["proxy"] is None, "без прокси связка снова полная")
            plain.stop()
            guarded.stop()
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

        # --- метрики сервера: на «Обзоре» основной раздел, а не все монтирования ---
        sysinfo = client.get("/api/system").json()
        mounts = [d["mount"] for d in sysinfo["disks"]]
        ok(len(sysinfo["disks"]) <= 2 and ("/" in mounts or len(mounts) == 1),
           f"блок «Сервер» показывает основной диск (плюс диск базы панели, только если он на другом устройстве): {mounts}")
        ok(all(d["total"] > 0 and 0 <= d["percent"] <= 100 and d["free"] <= d["total"] for d in sysinfo["disks"]),
           "диск с честной ёмкостью и процентом")
        ok(sysinfo["cpu"]["cores"] and sysinfo["memory"]["total"], "ЦП и память живые")

        meta = client.get("/api/meta").json()
        # версия проверяется та же, что лежит в pyproject.toml: иначе правка версии
        # ловила бы тест на ровном месте
        ok(meta["name"] == "medusa" and meta["version"] == project_version(),
           f"/api/meta отдаёт имя и версию проекта: {meta}")
        page = client.get("/")
        ok(page.status_code == 200 and 'id="view"' in page.text, "статика и API живут рядом")
        ok(client.get("/api/chains").status_code == 200, "список цепочек работает")

    chain_migration_checks()
    port_and_hop_checks(client)
    proxy_setting_checks(client)
    hop_settings_checks(client)
    traffic_checks(client)

    print(f"\nпровалов: {FAILS}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())

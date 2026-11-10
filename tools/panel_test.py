"""Проверка Medusa API: .venv/bin/python tools/api_test.py

База берётся временная, сид демо не используется — проверяем то, что делает API.
"""
from __future__ import annotations

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
        ok(ip_reality.status_code == 400, f"reality на IP-адресе отвергается: {ip_reality.json()['detail']}")
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

        # --- подписка: страница /sub/<токен> ---
        sub_chain = client.post("/api/chains", json={"name": "SUB-ROUTE", "hops": [
            {"node": "vps-fi", "protocol": "vless", "network": "tcp", "security": "reality", "port": 3011},
            {"node": "home", "protocol": "vless", "network": "tcp", "security": "reality", "port": 3012}]}).json()
        page = client.get(f"/sub/{brother['token']}")
        ok(page.status_code == 200 and "text/html" in page.headers.get("content-type", ""),
           "GET /sub/<токен>: HTML-страница без входа администратора")
        ok("brother" in page.text and "активен" in page.text, "на странице подписки есть никнейм и живой статус")
        ok("langbtn" in page.text, "переключатель языка на месте")
        ok("FI Reality" in page.text and "SUB-ROUTE" in page.text, "хосты и цепочки доступны подписчику")
        ok(client.get("/sub/nesushchestvuet").status_code == 404, "чужого токена подписки нет -> 404")
        off_page = client.get(f"/sub/{masha['token']}")
        ok(off_page.status_code == 200 and "FI Reality" not in off_page.text,
           "отключённому пользователю подписка не раздаётся")
        en_page = client.get(f"/sub/{brother['token']}?lang=en")
        ok("Hosts" in en_page.text and "Chains" in en_page.text, "страница подписки на английском по ?lang=en")
        forced = client.get(f"/sub/{brother['token']}", headers={"Accept-Language": "en-US,en;q=0.9"})
        ok("Хосты" in forced.text, "английский браузер видит русский: язык переключается только кнопкой")
        ok("vless://" in page.text and page.text.count('data-copy="') == 2,
           "кнопка копирования ссылки есть у vless-хоста и у входа цепочки")
        client.delete(f"/api/chains/{sub_chain['id']}")

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
        cross = client.patch(f"/api/hosts/{fi_host['id']}", json={"minVersion": "1.3"})
        ok(cross.status_code == 400, f"поле tls для reality-хоста отвергается: {cross.json()['detail']}")
        sni_cross = client.patch(f"/api/hosts/{fi_host['id']}", json={"sni": "x.example.net"})
        ok(sni_cross.status_code == 400, f"sni — поле tls, у reality для этого есть serverNames -> {sni_cross.json()['detail']}")
        names = client.patch(f"/api/hosts/{fi_host['id']}", json={
            "serverNames": "fi.example.net alt.example.net", "realityMinClient": "24.7.10"}).json()
        ok(names["serverNames"] == "fi.example.net alt.example.net" and names["realityMinClient"] == "24.7.10",
           "reality записал список sni и минимальную версию клиента")
        fp_none = client.post("/api/hosts", json={"name": "прямой", "node": "vps-fi", "protocol": "vless",
                                                  "port": 9416, "network": "tcp", "security": "none", "fp": "chrome"})
        ok(fp_none.status_code == 400, f"отпечаток без шифрования отвергается: {fp_none.json()['detail']}")
        bad_path = client.patch(f"/api/hosts/{fi_host['id']}", json={"path": "/x"})
        ok(bad_path.status_code == 400, f"путь без websocket отвергается: {bad_path.json()['detail']}")
        ip_addr = client.patch(f"/api/hosts/{fi_host['id']}", json={"address": "1.2.3.4"})
        ok(ip_addr.status_code == 400, "reality-хосту нельзя подставить IP вместо домена")
        tls_ws = client.post("/api/hosts", json={"name": "TLS WS", "node": "vps-fi", "protocol": "vless",
                                                 "port": 9413, "network": "ws", "security": "tls",
                                                 "address": "ws.example.net", "path": "/tunnel",
                                                 "hostHeader": "cdn.example.net", "sni": "tls.example.net",
                                                 "minVersion": "1.2", "maxVersion": "1.3",
                                                 "cipherSuites": "chacha20-ietf-poly1305", "fp": "safari"}).json()
        ok(tls_ws["path"] == "/tunnel" and tls_ws["hostHeader"] == "cdn.example.net",
           "транспортные поля websocket сохранены при создании")
        ok(tls_ws["sni"] == "tls.example.net" and tls_ws["minVersion"] == "1.2" and
           tls_ws["maxVersion"] == "1.3" and tls_ws["cipherSuites"] == "chacha20-ietf-poly1305" and
           tls_ws["fp"] == "safari", "tls записал sni, версии, шифры и отпечаток")
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

    print(f"\nпровалов: {FAILS}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())

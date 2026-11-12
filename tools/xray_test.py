"""Сквозная проверка Xray-слоя: панель собрала конфиг -> нода применила -> Xray принял.

Настоящего Xray на тестовой машине может не быть, поэтому на его место ставится
заглушка: она печатает версию, принимает любой конфиг на `-test` и «слушает» в
режиме запуска. Это честно по отношению к тому, что проверяется: связка панели и
ноды, ревизии, файл конфига, сертификаты, перезапуск процесса. Форма вызова при этом
та же, что у настоящего Xray: `xray -test -config <файл>` и `xray -config <файл>`.

Что проверяется конкретно:
* хосты заводятся с адресом подключения, отдельным от адреса ноды;
* reality-хост получает пару x25519: приватный ключ едет в конфиг, публичный — наружу;
* конфиг ноды собирается из её хостов и активных пользователей, reality-клиенты
  идут с паролем и коротким id, tls-хосты — с выпущенным сертификатом;
* vmess, trojan и shadowsocks подымаются сами: у vmess согласуемый шифр, у trojan пароль
  из токена, у shadowsocks подписчики лежат в `users` со своим шифром и своим на каждый
  хост паролем; hy2 и бессмысленные комбинации (ss+tls, vmess+reality) не заводятся;
* применение поднимает ревизию на обеих сторонах и не роняет панель при отказе ноды;
* отключённый пользователь исчезает из клиентов конфига.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

tmp = Path(tempfile.mkdtemp(prefix="medusa-xray-"))
os.environ["MEDUSA_DB"] = str(tmp / "panel.db")
os.environ["MEDUSA_ADMIN_USER"] = "admin"
os.environ["MEDUSA_ADMIN_PASSWORD"] = "supersecret1"
os.environ.pop("MEDUSA_DEMO", None)   # демо-пользователь «vasya» нам бы мешал: он же наш
os.environ["MEDUSA_NODE_AUTO"] = "0"     # фоновый опрос здесь только мешает

NODE_KEY = "sk-api-xraytest0000000000000"
STUB_LOG = tmp / "stub.log"
STATE = tmp / "node" / "state.json"
COUNTERS = tmp / "counters.json"      # что «отдаёт» счётчики заглушка Xray
API_LOG = tmp / "stub-api.log"
# вторая нода нужна для цепочек: хоп живёт на своей ноде, и её конфиг обязан прийти на неё
NODE_KEY2 = "sk-api-xraytest2000000000000"
STUB_LOG2 = tmp / "stub2.log"
STATE2 = tmp / "node2" / "state.json"
COUNTERS2 = tmp / "counters2.json"
API_LOG2 = tmp / "stub2-api.log"

FAILS = 0


def ok(cond: object, message: str) -> None:
    global FAILS
    print(("PASS  " if cond else "FAIL  ") + message)
    if not cond:
        FAILS += 1


STUB = """#!/usr/bin/env bash
args=" $* "
case "$args" in
  *" version "*) echo "Xray 25.8.3 (stub)"; exit 0 ;;
  *"-test"*)     echo "configuration accepted"; exit 0 ;;
  *" api "*)
    # вызов пишется в отдельный лог: проверка «сколько раз Xray стартовал» читает другой
    echo "$args" >> "$XRAY_STUB_API_LOG"
    if [ -f "$XRAY_STUB_COUNTERS" ]; then cat "$XRAY_STUB_COUNTERS"; else echo '{"stat": []}'; fi
    # Xray по -reset обнуляет счётчики после чтения — заглушка делает так же, иначе
    # проверка накопления трафика превратилась бы в подгонку цифр
    case "$args" in *" -reset "*) echo '{"stat": []}' > "$XRAY_STUB_COUNTERS" ;; esac
    exit 0 ;;
esac
echo "$args" >> "$XRAY_STUB_LOG"
exec sleep 300
"""


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def wait_rows(client, node_id: int, cond, seconds: float = 25) -> dict | None:
    """Ждёт, пока фоновая доставка не приведёт строку ноды к нужному состоянию."""
    deadline = time.time() + seconds
    row = None
    while time.time() < deadline:
        row = next((n for n in client.get("/api/nodes").json() if n["id"] == node_id), None)
        if row and cond(row):
            return row
        time.sleep(0.3)
    return row


def wait_cfg(cfg_path: Path, cond, seconds: float = 25) -> dict | None:
    deadline = time.time() + seconds
    cfg = None
    while time.time() < deadline:
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            if cond(cfg):
                return cfg
        except (OSError, json.JSONDecodeError):
            pass
        time.sleep(0.3)
    return cfg


def clients_at(cfg: dict, port: int) -> list:
    inbound = next(i for i in cfg["inbounds"] if i["port"] == port)
    # у shadowsocks клиенты живут в users: так Xray различает нескольких подписчиков
    # одного порта — по их ключам
    return inbound["settings"].get("users") or inbound["settings"]["clients"]


def inbound_at(cfg: dict, port: int) -> dict:
    return next(i for i in cfg["inbounds"] if i["port"] == port)


def main() -> int:
    stub = tmp / "xray-stub"
    stub.write_text(STUB, encoding="utf-8")
    stub.chmod(0o755)
    STUB_LOG.touch()
    API_LOG.touch()
    COUNTERS.write_text('{"stat": []}', encoding="utf-8")

    STUB_LOG2.touch()
    API_LOG2.touch()
    COUNTERS2.write_text('{"stat": []}', encoding="utf-8")
    node_port = free_port()
    node2_port = free_port()
    node_proc = subprocess.Popen(
        [str(ROOT / ".venv/bin/python"), "-m", "uvicorn", "src.node.main:app",
         "--host", "127.0.0.1", "--port", str(node_port)],
        cwd=ROOT,
        env={**os.environ, "MEDUSA_NODE_STATE": str(STATE), "MEDUSA_NODE_API_KEY": NODE_KEY,
             "MEDUSA_XRAY_BIN": str(stub), "XRAY_STUB_LOG": str(STUB_LOG), "XRAY_STUB_API_LOG": str(API_LOG),
             "XRAY_STUB_COUNTERS": str(COUNTERS)},
    )

    node2_proc = subprocess.Popen(
        [str(ROOT / ".venv/bin/python"), "-m", "uvicorn", "src.node.main:app",
         "--host", "127.0.0.1", "--port", str(node2_port)],
        cwd=ROOT,
        env={**os.environ, "MEDUSA_NODE_STATE": str(STATE2), "MEDUSA_NODE_API_KEY": NODE_KEY2,
             "MEDUSA_XRAY_BIN": str(stub), "XRAY_STUB_LOG": str(STUB_LOG2), "XRAY_STUB_API_LOG": str(API_LOG2),
             "XRAY_STUB_COUNTERS": str(COUNTERS2)},
    )

    import httpx

    from src.core.xray_config import (SS_CIPHER, VMESS_CIPHER, hop_password, hop_uuid,
                                      reality_short_id, ss_password, user_password, user_uuid)
    from src.panel.main import app
    from fastapi.testclient import TestClient

    try:
        for _ in range(80):
            try:
                if httpx.get(f"http://127.0.0.1:{node_port}/node/health", timeout=1).is_success:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
        else:
            raise SystemExit("тестовая нода не поднялась")
        for _ in range(80):
            try:
                if httpx.get(f"http://127.0.0.1:{node2_port}/node/health", timeout=1).is_success:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
        else:
            raise SystemExit("вторая тестовая нода не поднялась")

        with TestClient(app) as client:
            token = client.post("/api/login", json={"username": "admin", "password": "supersecret1"}).json()["token"]
            client.headers["Authorization"] = f"Bearer {token}"

            node = client.post("/api/nodes", json={"name": "stub", "address": "127.0.0.1",
                                                   "apiPort": node_port, "apiKey": NODE_KEY}).json()
            ok(node["keySet"] and node["configDirty"], "нода создана и сразу помечена: конфиг не отправлен")

            reality = client.post("/api/hosts", json={"name": "R443", "node": "stub", "protocol": "vless",
                                                      "port": 443, "network": "tcp", "security": "reality",
                                                      "address": "vpn.example.net",
                                                      "dest": "mask.example.net:443", "fp": "firefox",
                                                      "serverNames": "vpn.example.net, backup.example.net"}).json()
            ok(reality["address"] == "vpn.example.net", f"адрес подключения хоста сохранён: {reality['address']}")
            ok(len(reality["publicKey"] or "") >= 40, f"reality-хост получил публичный ключ: {reality['publicKey'][:12]}…")
            ok(all(k not in reality for k in ("private_key", "privateKey", "apiKey")),
               "приватный ключ reality из панели наружу не утекает")
            ok(reality["dest"] == "mask.example.net:443" and reality["fp"] == "firefox",
               "маскированный адрес и отпечаток клиента сохранены у хоста")
            ok(reality["serverNames"] == "vpn.example.net, backup.example.net",
               "reality записал список sni")
            tls = client.post("/api/hosts", json={"name": "T8443", "node": "stub", "protocol": "vless",
                                                  "port": 8443, "network": "ws", "security": "tls",
                                                  "address": "127.0.0.1",
                                                  "sni": "tls.example.net", "rejectUnknownSni": True,
                                                  "fp": "safari",
                                                  "path": "/tun8443", "hostHeader": "cdn.example.net"}).json()
            ok(tls["sni"] == "tls.example.net" and tls["rejectUnknownSni"] is True,
               "tls-хост записал sni и «отвергать чужой SNI»")
            ok(tls["fp"] == "safari", "tls-хост записал отпечаток клиента")
            ok(tls["path"] == "/tun8443" and tls["hostHeader"] == "cdn.example.net",
               "websocket-хост записал путь и Host-заголовок")
            crossed = client.post("/api/hosts", json={"name": "кривой", "node": "stub", "protocol": "vless",
                                                      "port": 3099, "network": "tcp", "security": "tls",
                                                      "address": "127.0.0.1", "dest": "mask.example.net:443"})
            ok(crossed.status_code == 400, f"поле чужой защиты отвергается: {crossed.json()['detail']}")
            plain = client.post("/api/hosts", json={"name": "N3011", "node": "stub", "protocol": "vless",
                                                    "port": 3011, "network": "tcp", "security": "none"}).json()
            ok(plain["address"] == "", "хост без своего адреса — значит подключаться к адресу ноды")
            grpc = client.post("/api/hosts", json={"name": "G3077", "node": "stub", "protocol": "vless",
                                                   "port": 3077, "network": "grpc", "security": "none",
                                                   "serviceName": "medusa-grpc",
                                                   "grpcAuthority": "cdn.example.net"}).json()
            ok(grpc["serviceName"] == "medusa-grpc", "gRPC-хост записал имя сервиса")
            ws_cross = client.post("/api/hosts", json={"name": "кривой-ws", "node": "stub", "protocol": "vless",
                                                       "port": 3088, "network": "tcp", "security": "none",
                                                       "path": "/x"})
            ok(ws_cross.status_code == 400, f"путь без websocket отвергается: {ws_cross.json()['detail']}")

            # --- прочие протоколы, которые панель обязана уметь поднимать сама ----
            vmess = client.post("/api/hosts", json={"name": "V2083", "node": "stub", "protocol": "vmess",
                                                    "port": 2083, "network": "ws", "security": "tls",
                                                    "address": "vm.example.net", "sni": "vm.example.net",
                                                    "path": "/vmess", "hostHeader": "cdn.example.net"}).json()
            ok(vmess["protocol"] == "vmess", "vmess-хост заведён")
            trojan = client.post("/api/hosts", json={"name": "TR2095", "node": "stub", "protocol": "trojan",
                                                     "port": 2095, "network": "tcp", "security": "tls",
                                                     "address": "tr.example.net", "sni": "tr.example.net"}).json()
            trojan_reality = client.post("/api/hosts", json={"name": "TR2096", "node": "stub", "protocol": "trojan",
                                                             "port": 2096, "network": "tcp", "security": "reality",
                                                             "address": "tr-real.example.net"}).json()
            sock = client.post("/api/hosts", json={"name": "S3055", "node": "stub", "protocol": "ss",
                                                   "port": 3055, "network": "tcp", "security": "none",
                                                   "address": "ss.example.net"}).json()
            hy2 = client.post("/api/hosts", json={"name": "HY2", "node": "stub", "protocol": "hy2",
                                                  "port": 3056, "network": "tcp", "security": "none"})
            ok(hy2.status_code == 400, f"hy2 панель не заводит: {hy2.json()['detail']}")
            ss_tls = client.post("/api/hosts", json={"name": "ss+tls", "node": "stub", "protocol": "ss",
                                                     "port": 3057, "network": "tcp", "security": "tls"})
            ok(ss_tls.status_code == 400, f"ss с чужой защитой отвергается: {ss_tls.json()['detail']}")
            vm_reality = client.post("/api/hosts", json={"name": "vmess+reality", "node": "stub", "protocol": "vmess",
                                                         "port": 3058, "network": "tcp", "security": "reality",
                                                         "address": "vm.example.net"})
            ok(vm_reality.status_code == 400, f"vmess+reality отвергается: {vm_reality.json()['detail']}")
            ss_ws = client.post("/api/hosts", json={"name": "ss-ws", "node": "stub", "protocol": "ss",
                                                    "port": 3059, "network": "ws", "security": "none"})
            ok(ss_ws.status_code == 400, f"ss поверх ws отвергается: {ss_ws.json()['detail']}")

            vasya = client.post("/api/users", json={"name": "vasya"}).json()

            cfg_path = STATE.parent / "xray" / "config.json"
            # панель доставляет конфиг сама: ни одной кнопки «применить» в тесте нет.
            # ждём именно конечного состояния: все восемь хостов и один клиент в reality
            wait_cfg(cfg_path, lambda c: len(c["inbounds"]) == 8 and len(clients_at(c, 443)) == 1)
            row = wait_rows(client, node["id"], lambda r: not r["configDirty"] and r["appliedRev"] >= 1)
            ok(row is not None and row["applyError"] is None,
               f"панель сама доставила конфиг после правок: ревизия {row['appliedRev'] if row else '—'}")

            # заглушка-«Xray» должна реально запуститься (одна строка запуска в её логе)
            started = ""
            for _ in range(40):
                started = STUB_LOG.read_text(encoding="utf-8")
                if started.strip():
                    break
                time.sleep(0.25)
            ok("-config config.json" in started, f"Xray запущен панельным конфигом: {started.strip()}")

            cfg_path = STATE.parent / "xray" / "config.json"
            ok(cfg_path.exists(), f"рабочий конфиг ноды записан: {cfg_path}")
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            # инбаунд сервиса счётчиков — не хост: его нет ни в списке хостов панели,
            # ни в подписке; но он слушает на машине ноды, поэтому проверяем его отдельно
            host_inbounds = [i for i in cfg["inbounds"] if i["tag"] != "api"]
            stats_in = next(i for i in cfg["inbounds"] if i["tag"] == "api")
            by_port = {i["port"]: i for i in host_inbounds}
            ok({i["tag"] for i in host_inbounds} == {"R443", "T8443", "N3011", "G3077",
                                                     "V2083", "TR2095", "TR2096", "S3055"},
               f"теги инбаундов — имена хостов, как их видит человек: {sorted(i['tag'] for i in host_inbounds)}")
            ok(sorted(by_port) == [443, 2083, 2095, 2096, 3011, 3055, 3077, 8443],
               f"инбаунды по портам хостов: {sorted(by_port)}")
            ok(stats_in["listen"] == "127.0.0.1" and stats_in["port"] > 0
               and stats_in["port"] not in by_port and stats_in["protocol"] == "dokodemo-door",
               f"сервис счётчиков — петлюбочный ({stats_in['listen']}:{stats_in['port']}) и не наступил "
               "на порты хостов: панель писала туда 0, порт подобрала нода")
            ok(cfg.get("stats") is not None and cfg.get("api", {}).get("tag") == "api"
               and cfg["policy"]["levels"]["0"]["statsUserUplink"] and cfg["policy"]["levels"]["0"]["statsUserDownlink"],
               "Xray разрешил считать трафик подписчиков: stats + policy счётчики + api сервис")
            ok(any(o["tag"] == "api" and o["protocol"] == "blackhole" for o in cfg["outbounds"])
               and any(r.get("outboundTag") == "api" for r in cfg["routing"]["rules"]),
               "ответ сервиса счётчиков не уходит наружу: для него отдельный blackhole и правило")
            labels = {c.get("email") for i in host_inbounds
                      for c in (i["settings"].get("clients") or i["settings"].get("users") or [])}
            ok(all(label and label.startswith("u") for label in labels) and len(labels) == 1,
               f"у подписчика в конфиге есть метка, по которой и считается его трафик: {sorted(labels)}")

            r = by_port[443]
            ok(r["streamSettings"]["security"] == "reality" and r["streamSettings"]["realitySettings"]["privateKey"],
               "reality-инбаунд с приватным ключом из панели")
            ok(r["streamSettings"]["realitySettings"]["serverNames"] == ["vpn.example.net", "backup.example.net"],
               "serverNames — список sni хоста, а не только адрес подключения")
            ok("minClientVer" not in r["streamSettings"]["realitySettings"],
               "версию клиента панель не цензурирует: это формальность рукопожатия, а не защита")
            ok(r["streamSettings"]["fingerprint"] == "firefox",
               "отпечаток клиента ушёл в конфиг и reality-инбаунда")
            ok(r["streamSettings"]["realitySettings"]["dest"] == "mask.example.net:443",
               "маскированный адрес хоста ушёл в reality dest")
            ok(r["settings"]["decryption"] == "none", "vless-инбаунд: decryption=none")
            client0 = r["settings"]["clients"][0]
            ok(uuid.UUID(client0["id"]) == uuid.UUID(user_uuid(vasya["token"])),
               "reality-подписчик узнаётся по uuid из токена")
            ok(r["streamSettings"]["realitySettings"]["shortIds"] == [reality_short_id(vasya["token"])],
               "короткий id подписчика лежит у инбаунда")

            t = by_port[8443]
            tls_cfg = t["streamSettings"]["tlsSettings"]
            ok(tls_cfg["serverName"] == "tls.example.net" and tls_cfg["rejectUnknownSni"] is True and
               "alpn" not in tls_cfg and "minVersion" not in tls_cfg and "cipherSuites" not in tls_cfg,
               "sni и rejectUnknownSNI доехали, а версии/шифры/alpn панель не называет вовсе")
            ok(t["streamSettings"]["fingerprint"] == "safari",
               "отпечаток клиента работает и у tls, не только у reality")
            ok(t["streamSettings"]["wsSettings"]["path"] == "/tun8443" and
               t["streamSettings"]["wsSettings"]["host"] == "cdn.example.net",
               "путь и Host-заголовок websocket доехали до конфига")
            g = by_port[3077]
            ok(g["streamSettings"]["grpcSettings"] == {"serviceName": "medusa-grpc", "authority": "cdn.example.net"},
               "имя сервиса и authority gRPC доехали до конфига")
            cert = cfg_path.parent / t["streamSettings"]["tlsSettings"]["certificates"][0]["certificateFile"]
            key = cfg_path.parent / t["streamSettings"]["tlsSettings"]["certificates"][0]["keyFile"]
            ok(cert.exists() and key.exists(), f"tls-хост получил выпущенный сертификат: {cert.name}")
            ok(cert.stat().st_size > 200 and (key.stat().st_mode & 0o077) == 0,
               "закрытый сертификат лежит под 0600")

            p = by_port[3011]
            ok(uuid.UUID(p["settings"]["clients"][0]["id"]) == uuid.UUID(user_uuid(vasya["token"])),
               "vless без защиты получает uuid, собранный из токена пользователя")

            # --- vmess, trojan и shadowsocks: панель поднимает их сама, без заглушек ---
            v = by_port[2083]
            ok(v["protocol"] == "vmess" and v["settings"]["clients"][0]["security"] == VMESS_CIPHER,
               f"vmess-инбаунд с согласуемым шифром {VMESS_CIPHER} и alterId без устаревшего режима")
            ok(uuid.UUID(v["settings"]["clients"][0]["id"]) == uuid.UUID(user_uuid(vasya["token"])),
               "vmess-подписчик узнаётся по тому же uuid, что и vless")
            ok(v["streamSettings"]["wsSettings"]["path"] == "/vmess"
               and v["streamSettings"]["tlsSettings"]["serverName"] == "vm.example.net",
               "vmess поверх websocket+tls доехал со своим путём и sni")

            tr = by_port[2095]
            ok(tr["protocol"] == "trojan"
               and [c["password"] for c in tr["settings"]["clients"]] == [user_password(vasya["token"])],
               "trojan-инбаунд: пароль подписчика собран из его токена")
            ok(tr["streamSettings"]["tlsSettings"]["certificates"][0]["certificateFile"].endswith(
                   f"host-{trojan['id']}.crt"),
               "trojan-хост получил свой сертификат, а не чужой")

            trr = by_port[2096]
            ok(trr["protocol"] == "trojan" and trr["settings"]["clients"][0]["password"]
               and trr["streamSettings"]["realitySettings"]["privateKey"]
               and trr["streamSettings"]["realitySettings"]["shortIds"] == [reality_short_id(vasya["token"])],
               "trojan поверх reality: пароль у клиента, короткий id — у инбаунда")

            s = by_port[3055]
            ok(s["protocol"] == "shadowsocks" and "clients" not in s["settings"],
               "ss-хост панели — это shadowsocks-инбаунд Xray с подписчиками в users")
            ok([c["password"] for c in clients_at(cfg, 3055)] == [ss_password(vasya["token"], sock["id"])]
               and clients_at(cfg, 3055)[0]["method"] == SS_CIPHER,
               f"ss-пароль выведен из токена и привязан к хосту, шифр {SS_CIPHER}")

            status = httpx.get(f"http://127.0.0.1:{node_port}/node/status",
                               headers={"Authorization": f"Bearer {NODE_KEY}"}, timeout=5).json()
            ok(status["appliedRev"] >= 1 and status["desiredRev"] == status["appliedRev"] and not status["lastError"],
               f"нода сама подтвердила ревизию: {status['appliedRev']}")
            ok(status["xrayVersion"] == "25.8.3", f"версия Xray дошла до панели: {status['xrayVersion']}")

            # правка пользователей тоже улетает сама: новый пользователь появляется в конфиге
            masha = client.post("/api/users", json={"name": "masha"}).json()
            cfg = wait_cfg(cfg_path, lambda c: len(clients_at(c, 443)) == 2)
            ok(len(clients_at(cfg, 443)) == 2,
               "оба активных пользователя оказались в reality-инбаунде без всяких кнопок")
            client.patch(f"/api/users/{masha['id']}", json={"status": "disabled"})
            cfg = wait_cfg(cfg_path, lambda c: len(clients_at(c, 443)) == 1)
            ok(len(clients_at(cfg, 443)) == 1,
               "отключённый пользователь убран из конфига")

            # повторное применение при неизменном конфиге не дёргает ноду
            wait_rows(client, node["id"], lambda r: not r["configDirty"])
            before = next(n for n in client.get("/api/nodes").json() if n["id"] == node["id"])
            again = client.post(f"/api/nodes/{node['id']}/apply", json={}).json()
            after = next(n for n in client.get("/api/nodes").json() if n["id"] == node["id"])
            ok(again["ok"] is True and again.get("skipped") is True and after["appliedRev"] == before["appliedRev"],
               "повторный apply при том же конфиге не трогает ноду")

            # отказ ноды — это отчёт, а не грохот панели
            gone = client.post("/api/nodes", json={"name": "gone", "address": "127.0.0.1",
                                                   "apiPort": 1, "apiKey": "sk-api-gone00000000000000000"}).json()
            failed = client.post(f"/api/nodes/{gone['id']}/apply", json={}).json()
            ok(failed["ok"] is False and "не" in failed["error"],
               f"недоступная нода честно вернула ошибку: {failed['error']}")
            row = next(n for n in client.get("/api/nodes").json() if n["id"] == gone["id"])
            ok(row["applyError"] and row["configDirty"] is True, "ошибка применения записана в строку ноды")

            client.delete(f"/api/hosts/{plain['id']}")
            cfg = wait_cfg(cfg_path, lambda c: len([i for i in c["inbounds"] if i["tag"] != "api"]) == 7)
            ok(len([i for i in cfg["inbounds"] if i["tag"] != "api"]) == 7,
               "удалённый хост исчез из конфига (счётчики на месте — они не хост)")

            # два хоста с одним именем на одной ноде — порт уникален, а тег нет:
            # второй получает имя с id, теги в конфиге не должны сталкиваться
            dup = client.post("/api/hosts", json={"name": "R443", "node": "stub", "protocol": "vless",
                                                   "port": free_port(), "network": "tcp", "security": "none",
                                                   "address": "127.0.0.1"}).json()
            cfg = wait_cfg(cfg_path, lambda c: len([i for i in c["inbounds"] if i["tag"] != "api"]) == 8)
            tags = [i["tag"] for i in cfg["inbounds"] if i["tag"] != "api"]
            ok(len(set(tags)) == 8 and "R443" in tags and any(tag == f"R443-{dup['id']}" for tag in tags),
               f"одноимённые хосты получили разные теги: {sorted(tags)}")

            # --- цепочки: каждый хоп доезжает до своей ноды и скрепляется переходом ---
            node2 = client.post("/api/nodes", json={"name": "stub2", "address": "127.0.0.1",
                                                    "apiPort": node2_port, "apiKey": NODE_KEY2}).json()
            cfg2_path = STATE2.parent / "xray" / "config.json"
            h1, h2, h3 = free_port(), free_port(), free_port()
            route = client.post("/api/chains", json={"name": "XRAY-CHAIN", "hops": [
                {"node": "stub", "protocol": "vless", "network": "tcp", "security": "reality", "port": h1,
                 "dest": "mirror.example.org:443", "serverNames": "mirror.example.org, backup.example.org"},
                {"node": "stub2", "protocol": "trojan", "network": "ws", "security": "tls", "port": h2,
                 "address": "hop2.internal.example", "sni": "hop2-tls.internal.example",
                 "path": "/xray-hop2", "hostHeader": "cdn.hop2.example", "rejectUnknownSni": True,
                 "fp": "edge"},
                {"node": "stub", "protocol": "vmess", "network": "tcp", "security": "none", "port": h3},
            ]}).json()
            cfg = wait_cfg(cfg_path, lambda c: any(i["tag"] == "XRAY-CHAIN" for i in c["inbounds"])
                and any(i["tag"] == "XRAY-CHAIN hop 3" for i in c["inbounds"]))
            cfg2 = wait_cfg(cfg2_path, lambda c: any(i["tag"] == "XRAY-CHAIN hop 2" for i in c["inbounds"]))
            hop1 = next(i for i in cfg["inbounds"] if i["tag"] == "XRAY-CHAIN")
            hop2 = next(i for i in cfg2["inbounds"] if i["tag"] == "XRAY-CHAIN hop 2")
            hop3 = next(i for i in cfg["inbounds"] if i["tag"] == "XRAY-CHAIN hop 3")
            ok(hop1["port"] == h1 and hop2["port"] == h2 and hop3["port"] == h3,
               f"инбаунды хопа поднялись на своих нодах: {h1} и {h3} на первой, {h2} на второй")
            out12 = next(o for o in cfg["outbounds"] if o["tag"] == "XRAY-CHAIN -> hop 2")
            out23 = next(o for o in cfg2["outbounds"] if o["tag"] == "XRAY-CHAIN -> hop 3")
            ok(out12["settings"]["servers"][0]["password"] == hop2["settings"]["clients"][0]["password"]
               == hop_password(route["id"], 1),
               "переход trojan и инбаунд второго хопа сошлись на одном пароле, выведенном из цепочки")
            ok(out23["settings"]["vnext"][0]["users"][0]["id"] == hop3["settings"]["clients"][0]["id"]
               == hop_uuid(route["id"], 2),
               "переход vmess и инбаунд третьего хопа сошлись на одном uuid перехода")
            ok(out12["settings"]["servers"][0]["address"] == "hop2.internal.example",
               f"у хопа есть свой адрес — переход соседней ноды идёт на него, а не на адрес ноды: "
               f"{out12['settings']['servers'][0]['address']}")
            ok(out23["settings"]["vnext"][0]["address"] == "127.0.0.1",
               "а hop без своего адреса по-прежнему берёт адрес своей ноды: переход туда и ведёт")
            ok(hop1["settings"]["clients"][0]["id"] == user_uuid(vasya["token"]),
               "подпись входа цепочки — подпись подписчика")
            rules1 = cfg.get("routing", {}).get("rules", [])
            ok({"inboundTag": ["XRAY-CHAIN"], "outboundTag": "XRAY-CHAIN -> hop 2"} in rules1
               and {"inboundTag": ["XRAY-CHAIN hop 3"], "outboundTag": "direct"} not in rules1,
               "маршрут по inboundTag: вход цепочки уходит переходом, выход цепочки — наружу")

            hop_cert = cfg2_path.parent / hop2["streamSettings"]["tlsSettings"]["certificates"][0]["certificateFile"]
            hop_key = cfg2_path.parent / hop2["streamSettings"]["tlsSettings"]["certificates"][0]["keyFile"]
            ok(hop_cert.exists() and hop_key.exists() and (hop_key.stat().st_mode & 0o077) == 0,
               f"панель привезла сертификат хопа ноде-приёмнику: {hop_cert.name}, закрытый ключ под 0600")
            from cryptography import x509
            from cryptography.hazmat.primitives.serialization import Encoding
            der = x509.load_pem_x509_certificate(hop_cert.read_bytes()).public_bytes(Encoding.DER)
            ok(hashlib.sha256(der).hexdigest() == out12["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"],
               "отпечаток сертификата хопа совпал с тем, что закреплено на отправляющей ноде: "
               "tls-хоп цепочки собирается без allowInsecure")
            hop_cert_name = x509.load_pem_x509_certificate(hop_cert.read_bytes()).subject
            ok(any(name.value.lower() == "hop2-tls.internal.example" for name in hop_cert_name),
               f"сертификат хопа выпущен на его же sni, а не на адрес ноды: {hop_cert_name} — "
               "соседняя нода называет в SNI то же имя, что стоит в сертификате")
            ok(out12["streamSettings"]["tlsSettings"]["serverName"] == "hop2-tls.internal.example",
               "переход в SNI ставит sni хопа-приёмника: адрес, на который идут, и имя, которое"
              " называют, — разные вещи и обе берутся у хопа")

            # детали транспорта и защиты хопа доезжают до обеих сторон перехода:
            # инбаунд хопа слушает на них, соседний переход собирается по ним же
            ws_in = hop2["streamSettings"].get("wsSettings") or {}
            ws_out = out12["streamSettings"].get("wsSettings") or {}
            ok(ws_in.get("path") == "/xray-hop2" and ws_in.get("host") == "cdn.hop2.example",
               f"hoповый инбаунд поднялся на названном пути и Host-заголовке: {ws_in}")
            ok(ws_out.get("path") == "/xray-hop2" and ws_out.get("host") == "cdn.hop2.example",
               f"переход соседней ноды использует тот же путь и Host: {ws_out}")
            ok(hop2["streamSettings"]["tlsSettings"].get("rejectUnknownSni") is True,
               "hoповый tls-инбаунд отвергает чужой SNI — человек именно это просил")
            ok(out12["streamSettings"].get("fingerprint") == "edge",
               "отпечаток хопа достался переходу: обе стороны выглядят одинаково")
            reality1 = hop1["streamSettings"].get("realitySettings") or {}
            ok(reality1.get("dest") == "mirror.example.org:443"
               and reality1.get("serverNames") == ["mirror.example.org", "backup.example.org"],
               f"reality-хоп прячется за названной маской и принимает названные имена: "
               f"{reality1.get('serverNames')}")

            client.delete(f"/api/chains/{route['id']}")
            cfg = wait_cfg(cfg_path, lambda c: all(not i["tag"].startswith("XRAY-CHAIN") for i in c["inbounds"]))
            cfg2 = wait_cfg(cfg2_path, lambda c: all(not i["tag"].startswith("XRAY-CHAIN") for i in c["inbounds"]))
            ok(all(not o["tag"].startswith("XRAY-CHAIN") for o in cfg["outbounds"] + cfg2["outbounds"]),
               "удаление цепочки сняло и инбаунды хопа, и переходы на обеих нодах")

            # панель подтвердит ревизию чуть позже, чем файл конфига сменился: ждём оба факта
            final = wait_rows(client, node["id"], lambda r: not r["configDirty"]) or \
                next(n for n in client.get("/api/nodes").json() if n["id"] == node["id"])
            started_lines = [x for x in STUB_LOG.read_text(encoding="utf-8").splitlines() if x.strip()]
            ok(len(started_lines) == final["appliedRev"],
               f"каждое настоящее применение перезапускало Xray: стартов {len(started_lines)}, ревизий {final['appliedRev']}")

            # --- трафик: насчитал Xray -> нода скопила -> панель разложила по людям ---
            # Заглушка отвечает ровно теми счётчиками, что ей подложили, и обнуляет их
            # после чтения (`-reset`), как это делает настоящий Xray. Живой трафик на
            # настоящем Xray проверяется в tools/live_demo.py.
            def counters(stat: list[dict]) -> None:
                COUNTERS.write_text(json.dumps({"stat": stat}), encoding="utf-8")

            def node_row(node_id: int) -> dict:
                return next(n for n in client.get("/api/nodes").json() if n["id"] == node_id)

            def user_row(name: str) -> dict:
                return next(u for u in client.get("/api/users").json() if u["name"] == name)

            vasya = user_row("vasya")
            counters([{"name": f"user>>>u{vasya['id']}>>>traffic>>>uplink", "value": 1000},
                     {"name": f"user>>>u{vasya['id']}>>>traffic>>>downlink", "value": 2000},
                     {"name": "user>>>hop77-1>>>traffic>>>downlink", "value": 500},
                     {"name": "user>>>u999>>>traffic>>>uplink", "value": 10}])
            report = client.post(f"/api/nodes/{node['id']}/check").json()
            traffic = report.get("traffic") or {}
            ok(report["ok"] and traffic.get("bytes") == 3510 and not traffic.get("error"),
               f"панель забрала счётчики у ноды одним походом: {traffic}")
            row = node_row(node["id"])
            ok(row["traffic"] == 3510 and row["trafficError"] is None,
               f"строка ноды показывает её накопленный трафик: {row['traffic']} байт")
            users = client.get("/api/users").json()
            ok(user_row("vasya")["used"] == 3000,
               f"трафик подписчика опознан по метке u<id>: vasya {user_row('vasya')['used']}")
            ok(sum(u["used"] for u in users) == 3000,
               "транзит цепочки (hop77-1) и метка человека, которого в панели нет (u999), "
               "остались трафиком ноды и не приписаны никому")

            # повторный поход при пустых счётчиках: Xray обнулил их после чтения, а цифры
            # панели обязаны остаться — накопленное не теряется между опросами
            again = client.post(f"/api/nodes/{node['id']}/check").json()
            ok(again["traffic"]["bytes"] == 3510 and node_row(node["id"])["traffic"] == 3510
               and user_row("vasya")["used"] == 3000,
               f"повторная проверка не удваивает байты: {again['traffic']['bytes']}")

            counters([{"name": f"user>>>u{vasya['id']}>>>traffic>>>uplink", "value": 500}])
            third = client.post(f"/api/nodes/{node['id']}/check").json()
            ok(third["traffic"]["bytes"] == 4010 and user_row("vasya")["used"] == 3500,
               f"новые байты прибавляются к прежним, а не заменяют их: "
               f"{third['traffic']['bytes']} / vasya {user_row('vasya')['used']}")

            quick = client.post(f"/api/nodes/{node['id']}/check").json()
            ok(quick["traffic"]["bytes"] == 4010 and quick["traffic"]["labels"] == 3,
               "второй поход подряд ничего не удваивает: Xray обнулил счётчики после чтения, "
               "но накопленное нодой остаётся")
            calls = API_LOG.read_text(encoding="utf-8").splitlines()
            ok(calls and all("api statsquery" in line and "-pattern=user>>>" in line and "-reset" in line
                             and f"--server=127.0.0.1:{stats_in['port']}" in line for line in calls),
               f"нода звала Xray за счётчиками по его же CLI, на подобранный ею петлюбочный порт: {calls[-1].strip()}")
            status = httpx.get(f"http://127.0.0.1:{node_port}/node/status",
                               headers={"Authorization": f"Bearer {NODE_KEY}"}, timeout=5).json()
            ok(status["trafficBytes"] == 4010 and status["statsPort"] == stats_in["port"]
               and {item["email"] for item in status["userTraffic"]} == {f"u{vasya['id']}", "hop77-1", "u999"},
               f"нода отдаёт панелью то, что посчитала сама: {status['trafficBytes']} байт, "
               f"{len(status['userTraffic'])} меток")
    finally:
        node2_proc.terminate()
        try:
            node2_proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            node2_proc.kill()
        node_proc.terminate()
        try:
            node_proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            node_proc.kill()
        subprocess.run(["pkill", "-f", str(stub)], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\nпровалов: {FAILS}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())

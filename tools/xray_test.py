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
* применение поднимает ревизию на обеих сторонах и не роняет панель при отказе ноды;
* отключённый пользователь исчезает из клиентов конфига.
"""
from __future__ import annotations

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
    return next(i for i in cfg["inbounds"] if i["port"] == port)["settings"]["clients"]


def main() -> int:
    stub = tmp / "xray-stub"
    stub.write_text(STUB, encoding="utf-8")
    stub.chmod(0o755)
    STUB_LOG.touch()

    node_port = free_port()
    node_proc = subprocess.Popen(
        [str(ROOT / ".venv/bin/python"), "-m", "uvicorn", "src.node.main:app",
         "--host", "127.0.0.1", "--port", str(node_port)],
        cwd=ROOT,
        env={**os.environ, "MEDUSA_NODE_STATE": str(STATE), "MEDUSA_NODE_API_KEY": NODE_KEY,
             "MEDUSA_XRAY_BIN": str(stub), "XRAY_STUB_LOG": str(STUB_LOG)},
    )

    import httpx

    from src.core.xray_config import reality_short_id, user_password, user_uuid
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

        with TestClient(app) as client:
            token = client.post("/api/login", json={"username": "admin", "password": "supersecret1"}).json()["token"]
            client.headers["Authorization"] = f"Bearer {token}"

            node = client.post("/api/nodes", json={"name": "stub", "address": "127.0.0.1",
                                                   "apiPort": node_port, "apiKey": NODE_KEY}).json()
            ok(node["keySet"] and node["configDirty"], "нода создана и сразу помечена: конфиг не отправлен")

            reality = client.post("/api/hosts", json={"name": "R443", "node": "stub", "protocol": "vless",
                                                      "port": 443, "network": "tcp", "security": "reality",
                                                      "address": "vpn.example.net",
                                                      "dest": "mask.example.net:443", "fp": "firefox"}).json()
            ok(reality["address"] == "vpn.example.net", f"адрес подключения хоста сохранён: {reality['address']}")
            ok(len(reality["publicKey"] or "") >= 40, f"reality-хост получил публичный ключ: {reality['publicKey'][:12]}…")
            ok(all(k not in reality for k in ("private_key", "privateKey", "apiKey")),
               "приватный ключ reality из панели наружу не утекает")
            ok(reality["dest"] == "mask.example.net:443" and reality["fp"] == "firefox",
               "маскированный адрес и отпечаток клиента сохранены у хоста")
            tls = client.post("/api/hosts", json={"name": "T8443", "node": "stub", "protocol": "vless",
                                                  "port": 8443, "network": "ws", "security": "tls",
                                                  "address": "127.0.0.1",
                                                  "alpn": "h2", "rejectUnknownSni": True,
                                                  "path": "/tun8443", "hostHeader": "cdn.example.net"}).json()
            ok(tls["alpn"] == "h2" and tls["rejectUnknownSni"] is True,
               "tls-хост записал alpn и «отвергать чужой SNI»")
            ok(tls["path"] == "/tun8443" and tls["hostHeader"] == "cdn.example.net",
               "websocket-хост записал путь и Host-заголовок")
            crossed = client.post("/api/hosts", json={"name": "кривой", "node": "stub", "protocol": "vless",
                                                      "port": 3099, "network": "tcp", "security": "tls",
                                                      "address": "127.0.0.1", "fp": "chrome"})
            ok(crossed.status_code == 400, f"поле чужой защиты отвергается: {crossed.json()['detail']}")
            plain = client.post("/api/hosts", json={"name": "N3011", "node": "stub", "protocol": "vless",
                                                    "port": 3011, "network": "tcp", "security": "none"}).json()
            ok(plain["address"] == "", "хост без своего адреса — значит подключаться к адресу ноды")
            grpc = client.post("/api/hosts", json={"name": "G3077", "node": "stub", "protocol": "vless",
                                                   "port": 3077, "network": "grpc", "security": "none",
                                                   "serviceName": "medusa-grpc"}).json()
            ok(grpc["serviceName"] == "medusa-grpc", "gRPC-хост записал имя сервиса")
            ws_cross = client.post("/api/hosts", json={"name": "кривой-ws", "node": "stub", "protocol": "vless",
                                                       "port": 3088, "network": "tcp", "security": "none",
                                                       "path": "/x"})
            ok(ws_cross.status_code == 400, f"путь без websocket отвергается: {ws_cross.json()['detail']}")

            vasya = client.post("/api/users", json={"name": "vasya"}).json()

            cfg_path = STATE.parent / "xray" / "config.json"
            # панель доставляет конфиг сама: ни одной кнопки «применить» в тесте нет.
            # ждём именно конечного состояния: три хоста и один клиент в reality
            wait_cfg(cfg_path, lambda c: len(c["inbounds"]) == 4 and len(clients_at(c, 443)) == 1)
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
            by_port = {i["port"]: i for i in cfg["inbounds"]}
            ok({i["tag"] for i in cfg["inbounds"]} == {"R443", "T8443", "N3011", "G3077"},
               f"теги инбаундов — имена хостов, как их видит человек: {sorted(i['tag'] for i in cfg['inbounds'])}")
            ok(sorted(by_port) == [443, 3011, 3077, 8443], f"инбаунды по портам хостов: {sorted(by_port)}")

            r = by_port[443]
            ok(r["streamSettings"]["security"] == "reality" and r["streamSettings"]["realitySettings"]["privateKey"],
               "reality-инбаунд с приватным ключом из панели")
            ok(r["streamSettings"]["realitySettings"]["serverNames"] == ["vpn.example.net"],
               "serverNames берут адрес подключения, а не адрес ноды")
            ok(r["streamSettings"]["realitySettings"]["dest"] == "mask.example.net:443",
               "маскированный адрес хоста ушёл в reality dest")
            ok(r["settings"]["decryption"] == "none", "vless-инбаунд: decryption=none")
            client0 = r["settings"]["clients"][0]
            ok(uuid.UUID(client0["id"]) == uuid.UUID(user_uuid(vasya["token"])),
               "reality-подписчик узнаётся по uuid из токена")
            ok(r["streamSettings"]["realitySettings"]["shortIds"] == [reality_short_id(vasya["token"])],
               "короткий id подписчика лежит у инбаунда")

            t = by_port[8443]
            ok(t["streamSettings"]["tlsSettings"]["alpn"] == ["h2"] and
               t["streamSettings"]["tlsSettings"]["rejectUnknownSni"] is True,
               "alpn и rejectUnknownSNI доехали до tls-инбаунда")
            ok(t["streamSettings"]["wsSettings"]["path"] == "/tun8443" and
               t["streamSettings"]["wsSettings"]["host"] == "cdn.example.net",
               "путь и Host-заголовок websocket доехали до конфига")
            g = by_port[3077]
            ok(g["streamSettings"]["grpcSettings"]["serviceName"] == "medusa-grpc",
               "имя сервиса gRPC доехало до конфига")
            cert = cfg_path.parent / t["streamSettings"]["tlsSettings"]["certificates"][0]["certificateFile"]
            key = cfg_path.parent / t["streamSettings"]["tlsSettings"]["certificates"][0]["keyFile"]
            ok(cert.exists() and key.exists(), f"tls-хост получил выпущенный сертификат: {cert.name}")
            ok(cert.stat().st_size > 200 and (key.stat().st_mode & 0o077) == 0,
               "закрытый сертификат лежит под 0600")

            p = by_port[3011]
            ok(uuid.UUID(p["settings"]["clients"][0]["id"]) == uuid.UUID(user_uuid(vasya["token"])),
               "vless без защиты получает uuid, собранный из токена пользователя")

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
            cfg = wait_cfg(cfg_path, lambda c: len(c["inbounds"]) == 3)
            ok(len(cfg["inbounds"]) == 3, "удалённый хост исчез из конфига")

            # два хоста с одним именем на одной ноде — порт уникален, а тег нет:
            # второй получает имя с id, теги в конфиге не должны сталкиваться
            dup = client.post("/api/hosts", json={"name": "R443", "node": "stub", "protocol": "vless",
                                                   "port": free_port(), "network": "tcp", "security": "none",
                                                   "address": "127.0.0.1"}).json()
            cfg = wait_cfg(cfg_path, lambda c: len(c["inbounds"]) == 4)
            tags = [i["tag"] for i in cfg["inbounds"]]
            ok(len(set(tags)) == 4 and "R443" in tags and any(tag == f"R443-{dup['id']}" for tag in tags),
               f"одноимённые хосты получили разные теги: {sorted(tags)}")

            # панель подтвердит ревизию чуть позже, чем файл конфига сменился: ждём оба факта
            final = wait_rows(client, node["id"], lambda r: not r["configDirty"]) or \
                next(n for n in client.get("/api/nodes").json() if n["id"] == node["id"])
            started_lines = [x for x in STUB_LOG.read_text(encoding="utf-8").splitlines() if x.strip()]
            ok(len(started_lines) == final["appliedRev"],
               f"каждое настоящее применение перезапускало Xray: стартов {len(started_lines)}, ревизий {final['appliedRev']}")
    finally:
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

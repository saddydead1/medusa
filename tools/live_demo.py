#!/usr/bin/env python
"""Живая проверка: настоящий Xray, настоящая нода, настоящая панель, настоящее подключение.

Отличается от xray_test.py тем, что вместо заглушки берётся настоящий бинарник Xray
(по умолчанию `bin/xray`, если его нет — `xray` из PATH), а в конце к поднявшемуся
сервису подключается настоящий Xray-клиент через локальный SOCKS-порт: если внешняя
запрос прошла через туннель — значит VPN работает по-настоящему.

Что проверяется:
* панель поднимает ноду и три хоста (vless без защиты, reality, vless+tls поверх ws);
* панель сама доставляет конфиг, настоящий `xray` его принимает и поднимает порты;
* подписчик подключается по всем трём протоколам и ходит наружу через туннель;
* наружу печатаются готовые vless://-ссылки со страницы подписки — их можно вставить
  в любой клиент (v2rayN, nekobox, Shadowrocket) и подключаться к этой машине.

Запуск:  .venv/bin/python tools/live_demo.py [--keep]
Флаг --keep оставляет панель и ноду висеть: панель доступна в браузере по напечатанному
адресу, вход — напечатанным логином. Ctrl+C останавливает всё.
"""
from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

XRAY_BIN = os.getenv("MEDUSA_XRAY_BIN") or str(ROOT / "bin" / "xray")
if not Path(XRAY_BIN).exists() or not os.access(XRAY_BIN, os.X_OK):
    XRAY_BIN = "xray"

tmp = Path(tempfile.mkdtemp(prefix="medusa-live-"))
os.environ["MEDUSA_DB"] = str(tmp / "panel.db")
os.environ["MEDUSA_ADMIN_USER"] = "medusa"
os.environ["MEDUSA_ADMIN_PASSWORD"] = "livecheck123"
os.environ.pop("MEDUSA_DEMO", None)
os.environ["MEDUSA_NODE_AUTO"] = "0"

NODE_KEY = "sk-api-livecheck00000000000000"
STATE = tmp / "node" / "state.json"
CFG_PATH = STATE.parent / "xray" / "config.json"
XRAY_LOG = STATE.parent / "xray" / "xray.log"

FAILS = 0


def ok(cond: object, message: str) -> None:
    global FAILS
    print(("PASS  " if cond else "FAIL  ") + message)
    if not cond:
        FAILS += 1


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def spawn(cmd: list[str], env: dict[str, str], log: Path) -> subprocess.Popen:
    handle = log.open("w", encoding="utf-8")
    return subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT)


def wait_http(url: str, seconds: float = 30.0) -> bool:
    import httpx

    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=1).is_success:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    return False


def main() -> int:
    import httpx

    from src.core.xray_config import reality_short_id, user_uuid

    if not shutil.which(XRAY_BIN) and not Path(XRAY_BIN).is_absolute():
        print("Нужен настоящий Xray: скачайте его в bin/xray или задайте MEDUSA_XRAY_BIN")
        return 2
    print(f"Xray: {XRAY_BIN}")

    panel_port, node_port = free_port(), free_port()
    hosts_ports = {name: free_port() for name in ("plain", "reality", "tls", "ws", "grpc")}

    node_proc = spawn(
        [str(ROOT / ".venv/bin/python"), "-m", "uvicorn", "src.node.main:app",
         "--host", "127.0.0.1", "--port", str(node_port), "--log-level", "warning"],
        {**os.environ, "MEDUSA_NODE_STATE": str(STATE), "MEDUSA_NODE_API_KEY": NODE_KEY,
         "MEDUSA_XRAY_BIN": XRAY_BIN},
        tmp / "node.log",
    )
    panel_proc = spawn(
        [str(ROOT / ".venv/bin/python"), "-m", "uvicorn", "src.panel.main:app",
         "--host", "127.0.0.1", "--port", str(panel_port), "--log-level", "warning"],
        os.environ,
        tmp / "panel.log",
    )
    panel_url = f"http://127.0.0.1:{panel_port}"

    try:
        if not wait_http(f"http://127.0.0.1:{node_port}/node/health"):
            print("нода не поднялась:\n" + (tmp / "node.log").read_text(encoding="utf-8"))
            return 2
        if not wait_http(f"{panel_url}/api/meta"):
            print("панель не поднялась:\n" + (tmp / "panel.log").read_text(encoding="utf-8"))
            return 2
        print(f"панель: {panel_url} (вход: medusa / livecheck123)")

        api = httpx.Client(base_url=panel_url, timeout=20)
        token = api.post("/api/login", json={"username": "medusa", "password": "livecheck123"}).json()["token"]
        api.headers["Authorization"] = f"Bearer {token}"

        node = api.post("/api/nodes", json={"name": "demo", "address": "127.0.0.1",
                                            "apiPort": node_port, "apiKey": NODE_KEY}).json()
        plain = api.post("/api/hosts", json={"name": "plain", "node": "demo", "protocol": "vless",
                                             "port": hosts_ports["plain"], "network": "tcp", "security": "none"}).json()
        reality = api.post("/api/hosts", json={"name": "reality", "node": "demo", "protocol": "vless",
                                               "port": hosts_ports["reality"], "network": "tcp", "security": "reality",
                                               "address": "localhost"}).json()
        tls = api.post("/api/hosts", json={"name": "wss", "node": "demo", "protocol": "vless",
                                           "port": hosts_ports["tls"], "network": "ws", "security": "tls",
                                           "address": "localhost"}).json()
        ws = api.post("/api/hosts", json={"name": "ws", "node": "demo", "protocol": "vless",
                                          "port": hosts_ports["ws"], "network": "ws", "security": "none",
                                          "path": "/medusa-tunnel", "hostHeader": "cdn.example.net"}).json()
        grpc = api.post("/api/hosts", json={"name": "grpc", "node": "demo", "protocol": "vless",
                                            "port": hosts_ports["grpc"], "network": "grpc", "security": "none",
                                            "serviceName": "medusa-live", "grpcAuthority": "grpc.example.net"}).json()
        user = api.post("/api/users", json={"name": "petya"}).json()
        print("заведены: нода demo, хосты plain/reality/wss/ws/grpc, пользователь petya")

        # панель применяет конфиг сама; ждём подтверждения от ноды
        applied = None
        deadline = time.time() + 40
        while time.time() < deadline:
            row = next(n for n in api.get("/api/nodes").json() if n["id"] == node["id"])
            if not row["configDirty"] and row["appliedRev"] >= 1:
                applied = row
                break
            time.sleep(0.4)
        ok(applied is not None and not applied["applyError"],
           f"панель сама доставила конфиг настоящей ноде: ревизия {applied['appliedRev'] if applied else '—'}"
           + ("" if not applied or not applied["applyError"] else f" / {applied['applyError']}"))
        if applied is None:
            print("DEBUG row:", json.dumps(row, ensure_ascii=False))
        if applied is None or applied["applyError"]:
            print("panel.log:\n" + (tmp / "panel.log").read_text(encoding="utf-8")[-2500:])
            if XRAY_LOG.exists():
                print("xray.log:\n" + XRAY_LOG.read_text(encoding="utf-8")[-2000:])
            return 2

        # порты хостов действительно слушают
        for label in ("plain", "reality", "tls", "ws", "grpc"):
            port = hosts_ports[label]
            with socket.socket() as probe:
                probe.settimeout(5)
                ok(probe.connect_ex(("127.0.0.1", port)) == 0, f"порт {label} ({port}) слушается Xray")

        # транспортные детали доехали до живого конфига Xray дословно
        cfg = json.loads(CFG_PATH.read_text(encoding="utf-8"))
        by_port = {i["port"]: i for i in cfg["inbounds"]}
        wss = by_port[hosts_ports["ws"]]["streamSettings"]
        ok(wss["wsSettings"]["path"] == "/medusa-tunnel" and wss["wsSettings"]["host"] == "cdn.example.net",
           "живой конфиг Xray: путь и Host-заголовок websocket")
        gr = by_port[hosts_ports["grpc"]]["streamSettings"]["grpcSettings"]
        ok(gr["serviceName"] == "medusa-live" and gr["authority"] == "grpc.example.net",
           "живой конфиг Xray: имя сервиса и authority gRPC")

        # ---- настоящий клиент: SOCKS-туннель и внешний запрос наружу ----
        def client_json(proxy_port: int, outbound: dict) -> Path:
            cfg = {"log": {"loglevel": "warning"},
                   "inbounds": [{"port": proxy_port, "protocol": "socks", "settings": {}}],
                   "outbounds": [outbound]}
            path = tmp / f"client-{proxy_port}.json"
            path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
            return path

        def through(label: str, proxy_port: int, outbound: dict) -> None:
            cfg_path = client_json(proxy_port, outbound)
            log = tmp / f"client-{label}.log"
            proc = spawn([XRAY_BIN, "-config", str(cfg_path)], os.environ, log)
            try:
                code = 0
                deadline = time.time() + 30
                while time.time() < deadline:
                    res = subprocess.run(["curl", "-sS", "-x", f"socks5h://127.0.0.1:{proxy_port}",
                                          "--max-time", "10", "-o", os.devnull, "-w", "%{http_code}",
                                          "https://www.gstatic.com/generate_204"],
                                         capture_output=True, text=True)
                    if res.stdout.strip() in ("204", "200"):
                        code = int(res.stdout.strip())
                        break
                    time.sleep(1.0)
                ok(code in (204, 200),
                   f"{label}: внешний запрос прошёл через туннель (HTTP {code})")
                if code == 0:
                    print(f"  клиент {label}: " + log.read_text(encoding="utf-8")[-1200:])
                    if XRAY_LOG.exists():
                        print(f"  сервер xray.log: " + XRAY_LOG.read_text(encoding="utf-8")[-1200:])
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()

        short_id = reality_short_id(user["token"])

        through("plain", 12711, {
            "tag": "direct", "protocol": "vless",
            "settings": {"vnext": [{"address": "127.0.0.1", "port": hosts_ports["plain"],
                                    "users": [{"id": user_uuid(user["token"]), "encryption": "none"}]}]},
            "streamSettings": {"network": "tcp"}})

        through("reality", 12712, {
            "tag": "direct", "protocol": "vless",
            "settings": {"vnext": [{"address": "127.0.0.1", "port": hosts_ports["reality"],
                                    "users": [{"id": user_uuid(user["token"]), "encryption": "none"}]}]},
            "streamSettings": {"network": "tcp", "security": "reality",
                               "realitySettings": {"publicKey": reality["publicKey"], "fingerprint": "chrome",
                                                   "serverName": "localhost", "shortId": short_id, "spiderX": "/"}}})

        # Xray 26 выкинул allowInsecure: самозакрытый сертификат ноды клиенту
        # называется по отпечатку — pinnedPeerCertSha256 (SHA-256 от DER сертификата)
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        cert_file = CFG_PATH.parent / f"certs/host-{tls['id']}.crt"
        der = x509.load_pem_x509_certificate(cert_file.read_bytes()).public_bytes(Encoding.DER)
        pin = hashlib.sha256(der).hexdigest()
        through("tls", 12713, {
            "tag": "direct", "protocol": "vless",
            "settings": {"vnext": [{"address": "127.0.0.1", "port": hosts_ports["tls"],
                                    "users": [{"id": user_uuid(user["token"]), "encryption": "none"}]}]},
            "streamSettings": {"network": "ws", "security": "tls",
                               "wsSettings": {"path": "/"},
                               "tlsSettings": {"serverName": "localhost", "pinnedPeerCertSha256": pin}}})

        # то, что увидит подписчик: ссылки прямо со страницы подписки панели
        page = api.get(f"/sub/{user['token']}", headers={"Accept": "text/html"}).text
        links = list(dict.fromkeys(link.replace("&amp;", "&") for link in re.findall(r"vless://[^\s\"<]+", page)))
        ok(len(links) >= 1, f"страница подписки отдаёт vless://-ссылки: {len(links)}")
        print("\nссылки подписки petya (можно вставить в клиент и подключаться к этой машине):")
        for link in links:
            print("  " + link)
        netloc = urllib.parse.urlparse(links[0]).netloc if links else "?"
        print(f"  (внутри ссылки адрес подключения: {netloc})")

        # машинный вид: одно вставление ссылки в приложение — все хосты разом
        machine = api.get(f"/sub/{user['token']}/links?raw=1").text.splitlines()
        ok(len(machine) == 5 and all(l.startswith("vless://") for l in machine),
           "ссылка подписки одним запросом отдаёт все пять хостов")
        # та же ссылка без Accept: text/html — приложение получит ссылки, а не страницу
        import base64 as b64
        negotiated = b64.b64decode(api.get(f"/sub/{user['token']}", headers={"Accept": "*/*"}).text).decode("utf-8")
        ok(negotiated.count("vless://") == 5,
           "та же ссылка подписки: клиент без Accept: text/html получает ссылки вместо страницы")
        qr = api.get(f"/sub/{user['token']}/qr/subscribe")
        ok(qr.status_code == 200 and qr.headers["content-type"].startswith("image/svg"),
           "QR ссылки подписки рисуется прямо на странице")

        if "--keep" in sys.argv:
            print(f"\nпанель живёт: {panel_url}, вход medusa / livecheck123. Ctrl+C — остановить.")
            signal.signal(signal.SIGINT, lambda *_: None)
            while panel_proc.poll() is None:
                time.sleep(1)
    finally:
        for proc in (node_proc, panel_proc):
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
        subprocess.run(["pkill", "-f", str(tmp)], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\nпровалов: {FAILS}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python
"""Живая проверка: настоящий Xray, настоящая нода, настоящая панель, настоящее подключение.

Отличается от xray_test.py тем, что вместо заглушки берётся настоящий бинарник Xray
(по умолчанию `bin/xray`, если его нет — `xray` из PATH), а в конце к поднявшемуся
сервису подключается настоящий Xray-клиент через локальный SOCKS-порт: если внешняя
запрос прошла через туннель — значит VPN работает по-настоящему.

Что проверяется:
* панель поднимает ноду и хосты vless (plain/reality/tls+ws/ws/grpc), vmess, trojan
  (tls и reality) и shadowsocks;
* панель сама доставляет конфиг, настоящий `xray` его принимает и поднимает порты;
* клиентский конфиг для каждой проверки собирается **из ссылки подписки**, а не из
  внутреннего знания теста: если в ссылке чего-то не хватает (uuid, пароль, шифр, sni,
  pbk, shortId, путь ws), туннель не поднимется и проверка это поймает;
* два разных подписчика ходят через один и тот же порт vmess/trojan/shadowsocks —
  то есть панель умеет различать людей на одном инбаунде;
* наружу печатаются готовые ссылки со страницы подписки: их можно вставить в v2rayN,
  v2rayNG, Happ, Hiddify, Clash Verge или Mihomo и подключаться к этой машине.

Запуск:  .venv/bin/python tools/live_demo.py [--keep]
Флаг --keep оставляет панель и ноду висеть: панель доступна в браузере по напечатанному
адресу, вход — напечатанным логином. Ctrl+C останавливает всё.
"""
from __future__ import annotations

import base64
import hashlib
import json
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
import urllib.request
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
# вторая нода: цепочка — это два узла, и без настоящего второго узла проверять нечего
NODE_KEY2 = "sk-api-livecheck2000000000000"
STATE2 = tmp / "node2" / "state.json"
CFG2_PATH = STATE2.parent / "xray" / "config.json"
XRAY2_LOG = STATE2.parent / "xray" / "xray.log"

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


def port_alive(port: int, tries: int = 30) -> bool:
    """Слушает ли Xray этот порт: последнее применение могло его ещё не поднять."""
    for _ in range(tries):
        with socket.socket() as probe:
            probe.settimeout(3)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.5)
    return False


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


# ----- ссылки подписки обратно в клиентский конфиг Xray -----------------------
# Тест намеренно разбирает именно ссылку: подписчик ведь получает только её, и
# если ссылка неполная, проверка обязана провалиться, а не подменить её «знанием».

def split_link(link: str) -> tuple[str, str, dict[str, str], str]:
    """(схема, адрес пользователя@хост:порт, параметры запроса, имя из фрагмента).

    Фрагмент (#имя) отсекается до разбора параметров: он только для показа,
    а в query он попадает как хвост последнего значения и ломает его.
    """
    scheme, _, rest = link.partition("://")
    body, _, frag = rest.partition("#")
    target, sep, qs = body.partition("?")
    params = dict(urllib.parse.parse_qsl(qs, keep_blank_values=True)) if sep else {}
    return scheme, target, params, urllib.parse.unquote(frag)


def netloc_of(target: str) -> tuple[str, int]:
    """Хост и порт из `кред@хост:порт`: кред отрезается, иначе адрес испорчен.
    IPv6 остаётся в скобках: `[::1]:443` -> (`[::1]`, 443)."""
    netloc = target.rsplit("@", 1)[-1]
    host, _, port = netloc.rpartition(":")
    return host, int(port)


def stream_of(params: dict[str, str], pin: str | None) -> dict:
    stream: dict = {"network": params.get("type", "tcp")}
    if stream["network"] == "ws":
        ws: dict = {}
        if params.get("path"):
            ws["path"] = params["path"]
        if params.get("host"):
            ws["host"] = params["host"]
        if ws:
            stream["wsSettings"] = ws
    elif stream["network"] == "grpc" and params.get("serviceName"):
        stream["grpcSettings"] = {"serviceName": params["serviceName"]}
    security = params.get("security", "none")
    if security == "tls":
        tls: dict = {"serverName": params.get("sni", "")}
        if pin:
            # Xray 26 выкинул allowInsecure: самозакрытый сертификат ноды клиенту
            # называется отпечатком pinnedPeerCertSha256 (SHA-256 от DER)
            tls["pinnedPeerCertSha256"] = pin
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "publicKey": params.get("pbk", ""),
            "fingerprint": params.get("fp", "chrome"),
            "serverName": params.get("sni", ""),
            "shortId": params.get("sid", ""),
            "spiderX": params.get("spx", "/"),
        }
    return stream


def outbound_from_link(link: str, pin: str | None = None) -> dict:
    """Outbound Xray-клиента, собранный из одной ссылки подписки."""
    scheme, target, params, _ = split_link(link)
    if scheme == "vmess":
        doc = json.loads(base64.b64decode(target.split("#", 1)[0]))
        address, port = doc["add"], int(doc["port"])
        cipher = doc.get("scy") or doc.get("cipher") or "auto"
        stream: dict = {"network": doc.get("net", "tcp")}
        if stream["network"] == "ws":
            ws: dict = {}
            if doc.get("path"):
                ws["path"] = doc["path"]
            if doc.get("host"):
                ws["host"] = doc["host"]
            if ws:
                stream["wsSettings"] = ws
        if doc.get("tls") == "tls":
            stream["security"] = "tls"
            tls: dict = {"serverName": doc.get("sni", "")}
            if pin:
                tls["pinnedPeerCertSha256"] = pin
            stream["tlsSettings"] = tls
        return {"tag": "direct", "protocol": "vmess",
                "settings": {"vnext": [{"address": address, "port": port,
                                        "users": [{"id": doc["id"], "alterId": int(doc.get("aid", 0)),
                                                  "security": cipher}]}]},
                "streamSettings": stream}

    address, port = netloc_of(target)
    credential = urllib.parse.unquote(target.split("@", 1)[0])
    if scheme == "vless":
        return {"tag": "direct", "protocol": "vless",
                "settings": {"vnext": [{"address": address, "port": port,
                                        "users": [{"id": credential, "encryption": params.get("encryption", "none")}]}]},
                "streamSettings": stream_of(params, pin)}
    if scheme == "trojan":
        return {"tag": "direct", "protocol": "trojan",
                "settings": {"servers": [{"address": address, "port": port, "password": credential}]},
                "streamSettings": stream_of(params, pin)}
    if scheme == "ss":
        method, _, password = credential.partition(":")
        return {"tag": "direct", "protocol": "shadowsocks",
                "settings": {"servers": [{"address": address, "port": port,
                                          "method": method, "password": password}]},
                "streamSettings": stream_of(params, pin)}
    raise ValueError(f"неизвестная схема ссылки: {scheme}")


def main() -> int:
    import httpx

    from src.core.xray_config import reality_short_id, user_uuid

    if not shutil.which(XRAY_BIN) and not Path(XRAY_BIN).is_absolute():
        print("Нужен настоящий Xray: скачайте его в bin/xray или задайте MEDUSA_XRAY_BIN")
        return 2
    print(f"Xray: {XRAY_BIN}")

    panel_port, node_port = free_port(), free_port()
    host_names = ("plain", "reality", "wss", "ws", "grpc", "vmess", "trojan", "treal", "ss")
    hosts_ports = {name: free_port() for name in host_names}
    socks_ports = {name: free_port() for name in host_names}

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

        api.post("/api/nodes", json={"name": "demo", "address": "127.0.0.1",
                                     "apiPort": node_port, "apiKey": NODE_KEY})
        made = {}
        made["plain"] = api.post("/api/hosts", json={"name": "plain", "node": "demo", "protocol": "vless",
                                                     "port": hosts_ports["plain"], "network": "tcp",
                                                     "security": "none"}).json()
        made["reality"] = api.post("/api/hosts", json={"name": "reality", "node": "demo", "protocol": "vless",
                                                       "port": hosts_ports["reality"], "network": "tcp",
                                                       "security": "reality", "address": "localhost"}).json()
        made["wss"] = api.post("/api/hosts", json={"name": "wss", "node": "demo", "protocol": "vless",
                                                   "port": hosts_ports["wss"], "network": "ws",
                                                   "security": "tls", "address": "localhost"}).json()
        made["ws"] = api.post("/api/hosts", json={"name": "ws", "node": "demo", "protocol": "vless",
                                                  "port": hosts_ports["ws"], "network": "ws",
                                                  "security": "none", "path": "/medusa-tunnel",
                                                  "hostHeader": "cdn.example.net"}).json()
        made["grpc"] = api.post("/api/hosts", json={"name": "grpc", "node": "demo", "protocol": "vless",
                                                    "port": hosts_ports["grpc"], "network": "grpc",
                                                    "security": "none", "serviceName": "medusa-live",
                                                    "grpcAuthority": "grpc.example.net"}).json()
        # --- прочие протоколы: vmess, trojan (tls и reality) и shadowsocks ---
        made["vmess"] = api.post("/api/hosts", json={"name": "vmess", "node": "demo", "protocol": "vmess",
                                                     "port": hosts_ports["vmess"], "network": "ws",
                                                     "security": "tls", "address": "localhost",
                                                     "path": "/vmess-live", "hostHeader": "cdn.example.net"}).json()
        made["trojan"] = api.post("/api/hosts", json={"name": "trojan", "node": "demo", "protocol": "trojan",
                                                      "port": hosts_ports["trojan"], "network": "tcp",
                                                      "security": "tls", "address": "localhost"}).json()
        made["treal"] = api.post("/api/hosts", json={"name": "trojan-reality", "node": "demo", "protocol": "trojan",
                                                     "port": hosts_ports["treal"], "network": "tcp",
                                                     "security": "reality", "address": "localhost"}).json()
        made["ss"] = api.post("/api/hosts", json={"name": "ss", "node": "demo", "protocol": "ss",
                                                  "port": hosts_ports["ss"], "network": "tcp",
                                                  "security": "none"}).json()
        petya = api.post("/api/users", json={"name": "petya"}).json()
        masha = api.post("/api/users", json={"name": "masha", "client": "happ"}).json()
        print("заведены: нода demo, девять хостов (vless×5, vmess, trojan×2, ss), два пользователя")

        # панель применяет конфиг сама; ждём, пока доставка успокоится: каждое
        # создание хоста — отдельная ревизия, и Xray на ноде перезапускается на каждую
        def settled(seconds: float = 90.0) -> dict | None:
            stable_rev, deadline = None, time.time() + seconds
            row = None
            while time.time() < deadline:
                row = next(n for n in api.get("/api/nodes").json() if n["name"] == "demo")
                clean = (not row["configDirty"] and row["appliedRev"] >= 1
                         and row["configRev"] == row["appliedRev"] and not row["applyError"])
                if clean and stable_rev == row["appliedRev"]:
                    return row                      # две подряд одинаковые спокойные строки
                stable_rev = row["appliedRev"] if clean else None
                time.sleep(0.6)
            return row

        applied = settled()
        ok(applied is not None and not applied["applyError"],
           f"панель сама доставила конфиг настоящей ноде: ревизия {applied['appliedRev'] if applied else '—'}"
           + ("" if not applied or not applied["applyError"] else f" / {applied['applyError']}"))
        if applied is None or applied["applyError"]:
            print("panel.log:\n" + (tmp / "panel.log").read_text(encoding="utf-8")[-2500:])
            if XRAY_LOG.exists():
                print("xray.log:\n" + XRAY_LOG.read_text(encoding="utf-8")[-2000:])
            return 2

        # порты хостов действительно слушают
        ports_dead = []
        for label in host_names:
            port = hosts_ports[label]
            alive = port_alive(port)
            ok(alive, f"порт {label} ({port}) слушается Xray")
            if not alive:
                ports_dead.append(label)
        if ports_dead:
            # без лога Xray такая проверка — слепая: нода честно пишет, почему не поднялась
            print("  node.log: " + (tmp / "node.log").read_text(encoding="utf-8")[-1500:])
            if XRAY_LOG.exists():
                print("  xray.log: " + XRAY_LOG.read_text(encoding="utf-8")[-2500:])
            print("  конфиг ноды: " + json.dumps(json.loads(CFG_PATH.read_text(encoding="utf-8")),
                                                 ensure_ascii=False)[:1500])
            return 2

        # транспортные и протокольные детали доехали до живого конфига Xray дословно
        cfg = json.loads(CFG_PATH.read_text(encoding="utf-8"))
        by_port = {i["port"]: i for i in cfg["inbounds"]}
        wss = by_port[hosts_ports["ws"]]["streamSettings"]
        ok(wss["wsSettings"]["path"] == "/medusa-tunnel" and wss["wsSettings"]["host"] == "cdn.example.net",
           "живой конфиг Xray: путь и Host-заголовок websocket")
        gr = by_port[hosts_ports["grpc"]]["streamSettings"]["grpcSettings"]
        ok(gr["serviceName"] == "medusa-live" and gr["authority"] == "grpc.example.net",
           "живой конфиг Xray: имя сервиса и authority gRPC")
        vm = by_port[hosts_ports["vmess"]]
        ok(vm["protocol"] == "vmess" and all(c["security"] == "auto" for c in vm["settings"]["clients"])
           and len(vm["settings"]["clients"]) == 2,
           "живой конфиг Xray: vmess-инбаунд с двумя подписчиками и согласуемым шифром")
        tr = by_port[hosts_ports["trojan"]]
        ok(tr["protocol"] == "trojan" and len(tr["settings"]["clients"]) == 2,
           "живой конфиг Xray: trojan-инбаунд с паролями обоих подписчиков")
        ss_in = by_port[hosts_ports["ss"]]
        ok(ss_in["protocol"] == "shadowsocks" and len(ss_in["settings"]["users"]) == 2
           and {u["method"] for u in ss_in["settings"]["users"]} == {"chacha20-ietf-poly1305"},
           "живой конфиг Xray: shadowsocks держит двух подписчиков в users со своим шифром")

        # самозакрытый сертификат ноды клиент называет отпечатком (Xray 26 без allowInsecure)
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        def cert_pin(host_id: int) -> str:
            crt = CFG_PATH.parent / "certs" / f"host-{host_id}.crt"
            der = x509.load_pem_x509_certificate(crt.read_bytes()).public_bytes(Encoding.DER)
            return hashlib.sha256(der).hexdigest()

        pins = {name: cert_pin(made[name]["id"]) for name in ("wss", "vmess", "trojan")}

        # ---- настоящий клиент: SOCKS-туннель и внешний запрос наружу ----
        def client_json(proxy_port: int, outbound: dict) -> Path:
            doc = {"log": {"loglevel": "warning"},
                   "inbounds": [{"port": proxy_port, "protocol": "socks", "settings": {}}],
                   "outbounds": [outbound]}
            path = tmp / f"client-{proxy_port}.json"
            path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            return path

        def through(label: str, proxy_port: int, outbound: dict, who: str = "") -> bool:
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
                   f"{label}{who}: внешний запрос прошёл через туннель (HTTP {code})")
                if code == 0:
                    print(f"  клиент {label}: " + log.read_text(encoding="utf-8")[-1200:])
                    if XRAY_LOG.exists():
                        print(f"  сервер xray.log: " + XRAY_LOG.read_text(encoding="utf-8")[-1200:])
                return code in (204, 200)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()

        # --- проверка по ссылкам подписки: и ровно те поля, что видит подписчик ---
        def links_of(user: dict) -> dict[str, str]:
            """Ссылки подписки одного человека, разложенные по имени хоста."""
            raw = api.get(f"/sub/{user['token']}/links?raw=1").text
            out: dict[str, str] = {}
            for line in raw.splitlines():
                if not line:
                    continue
                name = urllib.parse.unquote(line.partition("#")[2]) or line.split("://", 1)[0]
                out[name] = line
            return out

        petya_links, masha_links = links_of(petya), links_of(masha)
        ok(len(petya_links) == 9 and {"vmess", "trojan", "trojan-reality", "ss"} <= set(petya_links),
           f"машинная ссылка подписки отдаёт все девять хостов: {sorted(petya_links)}")

        short_id = reality_short_id(petya["token"])
        through("plain", socks_ports["plain"], outbound_from_link(petya_links["plain"]))
        through("reality", socks_ports["reality"], outbound_from_link(petya_links["reality"]))
        through("wss", socks_ports["wss"], outbound_from_link(petya_links["wss"], pins["wss"]))
        through("ws", socks_ports["ws"], outbound_from_link(petya_links["ws"]))
        through("grpc", socks_ports["grpc"], outbound_from_link(petya_links["grpc"]))
        through("vmess", socks_ports["vmess"], outbound_from_link(petya_links["vmess"], pins["vmess"]))
        through("trojan", socks_ports["trojan"], outbound_from_link(petya_links["trojan"], pins["trojan"]))
        through("trojan-reality", socks_ports["treal"], outbound_from_link(petya_links["trojan-reality"]))
        through("ss", socks_ports["ss"], outbound_from_link(petya_links["ss"]))

        # второй подписчик через те же порты vmess/trojan/shadowsocks: панель различает людей
        for name in ("vmess", "trojan", "ss"):
            through(name, free_port(), outbound_from_link(masha_links[name], pins.get(name)), " / masha")

        reality_link = petya_links["reality"]
        ok(f"sid={short_id}" in reality_link, "reality-ссылка подписчика несёт его короткий id")

        # то, что увидит подписчик: ссылки прямо со страницы подписки панели
        page = api.get(f"/sub/{petya['token']}", headers={"Accept": "text/html"}).text
        page_links = list(dict.fromkeys(l.replace("&amp;", "&") for l in
                                        re.findall(r"(?:vless|vmess|trojan|ss)://[^\s\"<]+", page)))
        ok(len(page_links) >= 9, f"страница подписки отдаёт ссылки всех хостов: {len(page_links)}")
        print("\nссылки подписки petya (можно вставить в клиент и подключаться к этой машине):")
        for link in page_links:
            print("  " + link)
        first = page_links[0] if page_links else ""
        netloc = urllib.parse.urlparse(first).netloc.rsplit("@", 1)[-1] or "?"
        print(f"  (внутри первой ссылки адрес подключения: {netloc})")

        # машинный вид: одно вставление ссылки в приложение — все хосты разом
        machine = api.get(f"/sub/{petya['token']}/links?raw=1").text.splitlines()
        schemes = {l.split("://", 1)[0] for l in machine if l}
        ok(len(machine) == 9 and schemes == {"vless", "vmess", "trojan", "ss"},
           f"ссылка подписки одним запросом отдаёт все девять хостов: {sorted(schemes)}")
        # та же ссылка без Accept: text/html — приложение получит ссылки, а не страницу
        negotiated = base64.b64decode(api.get(f"/sub/{petya['token']}", headers={"Accept": "*/*"}).text).decode("utf-8")
        ok(len([l for l in negotiated.splitlines() if l]) == 9,
           "та же ссылка подписки: клиент без Accept: text/html получает ссылки вместо страницы")
        # Happ, v2rayNG и прочие читают base64 из переводных ссылок: проверим, что он собирается
        ok(base64.b64decode(api.get(f"/sub/{masha['token']}/links").text).decode("utf-8")
           .count("\n") == 8, "base64-подписка для Happ/v2rayNG: девять ссылок, переводные")
        # Clash и его производные понимают только YAML со списком proxies
        import yaml as _yaml
        clash_doc = _yaml.safe_load(api.get(f"/sub/{petya['token']}",
                                            headers={"Accept": "*/*", "User-Agent": "clash-verge/v2.4.0"}).text)
        kinds = sorted({p["type"] for p in clash_doc["proxies"]})
        ok(len(clash_doc["proxies"]) == 9 and kinds == ["ss", "trojan", "vless", "vmess"],
           f"clash yaml: все девять хостов и все протоколы списком proxies: "
           f"{len(clash_doc['proxies'])} прокси {kinds}")
        by_clash = {p["name"]: p for p in clash_doc["proxies"]}
        ok(by_clash["reality"]["reality-opts"]["public-key"] and by_clash["reality"]["client-fingerprint"] == "chrome"
           and by_clash["ws"]["ws-opts"]["path"] == "/medusa-tunnel",
           "clash yaml: reality-ключи и websocket-детали описаны по-clash-вому")
        ok(by_clash["vmess"]["cipher"] == "auto" and by_clash["vmess"]["ws-opts"]["path"] == "/vmess-live",
           "clash yaml: vmess со своим шифром и путём websocket")
        ok(by_clash["ss"]["cipher"] == "chacha20-ietf-poly1305" and by_clash["ss"]["password"],
           "clash yaml: shadowsocks с шифром и паролем этого хоста")
        ok(by_clash["trojan"]["password"] and by_clash["trojan-reality"]["reality-opts"]["short-id"],
           "clash yaml: trojan с паролем и reality-хост с коротким id")
        group = clash_doc["proxy-groups"][0]
        ok(group["type"] == "select" and set(group["proxies"]) == set(by_clash)
           and clash_doc["rules"][0] == f"MATCH,{group['name']}",
           f"clash yaml: группа выбора «{group['name']}» — одиночный Mihomo знает, куда класть трафик")

        # ===== цепочки: две настоящие ноды, трафик переходит с ноды на ноду =====
        node2_port = free_port()
        node2_proc = spawn(
            [str(ROOT / ".venv/bin/python"), "-m", "uvicorn", "src.node.main:app",
             "--host", "127.0.0.1", "--port", str(node2_port), "--log-level", "warning"],
            {**os.environ, "MEDUSA_NODE_STATE": str(STATE2), "MEDUSA_NODE_API_KEY": NODE_KEY2,
             "MEDUSA_XRAY_BIN": XRAY_BIN},
            tmp / "node2.log",
        )
        ok(wait_http(f"http://127.0.0.1:{node2_port}/node/health"),
           "вторая нода поднялась: цепочка — это два узла, с одним проверять нечего")

        api.post("/api/nodes", json={"name": "demo2", "address": "127.0.0.1",
                                     "apiPort": node2_port, "apiKey": NODE_KEY2})
        chain_hops = {
            # вход reality на demo -> trojan tls на demo2
            "LIVE-2H": [("demo", "vless", "tcp", "reality"), ("demo2", "trojan", "tcp", "tls")],
            # вход websocket на demo -> shadowsocks на demo2 -> выход reality обратно на demo
            "LIVE-3H": [("demo", "vless", "ws", "none"), ("demo2", "ss", "tcp", "none"),
                        ("demo", "vless", "tcp", "reality")],
        }
        chain_ports: dict[str, list[int]] = {}
        for chain_name, hops in chain_hops.items():
            ports = [free_port() for _ in hops]
            chain_ports[chain_name] = ports
            created = api.post("/api/chains", json={"name": chain_name, "hops": [
                {"node": h[0], "protocol": h[1], "network": h[2], "security": h[3], "port": ports[i]}
                for i, h in enumerate(hops)]}).json()
            ok("id" in created, f"цепочка {chain_name} заведена: {len(hops)} хопа, порты {ports}")

        def settled_node(name: str, seconds: float = 120.0) -> dict | None:
            stable, deadline, row = None, time.time() + seconds, None
            while time.time() < deadline:
                row = next((n for n in api.get("/api/nodes").json() if n["name"] == name), None)
                if row is None:
                    time.sleep(0.5)
                    continue
                clean = (not row["configDirty"] and row["appliedRev"] >= 1
                         and row["configRev"] == row["appliedRev"] and not row["applyError"])
                if clean and stable == row["appliedRev"]:
                    return row
                stable = row["appliedRev"] if clean else None
                time.sleep(0.6)
            return row

        row_demo, row_demo2 = settled_node("demo"), settled_node("demo2")
        delivered = bool(row_demo and row_demo2 and not row_demo["applyError"] and not row_demo2["applyError"])
        ok(delivered, f"конфиг с хопам доехал до обеих нод без кнопок: demo ревизия "
                      f"{row_demo['appliedRev'] if row_demo else '—'}, demo2 ревизия "
                      f"{row_demo2['appliedRev'] if row_demo2 else '—'}")
        if not delivered:
            for log_name in ("panel.log", "node.log", "node2.log"):
                print(f"{log_name}:\n" + (tmp / log_name).read_text(encoding="utf-8")[-1200:])
            return 2

        cfg1 = json.loads(CFG_PATH.read_text(encoding="utf-8"))
        cfg2 = json.loads(CFG2_PATH.read_text(encoding="utf-8"))
        tags1 = {i["tag"]: i for i in cfg1["inbounds"]}
        tags2 = {i["tag"]: i for i in cfg2["inbounds"]}
        out1 = {o["tag"]: o for o in cfg1["outbounds"]}
        out2 = {o["tag"]: o for o in cfg2["outbounds"]}
        ok(tags1.get("LIVE-2H", {}).get("protocol") == "vless"
           and tags2.get("LIVE-2H hop 2", {}).get("protocol") == "trojan",
           "хопа цепочки поднялись на своих нодах: вход на demo, приёмник на demo2")
        ok(tags1.get("LIVE-3H hop 3", {}).get("protocol") == "vless"
           and tags2.get("LIVE-3H hop 2", {}).get("protocol") == "shadowsocks",
           "цепочка из трёх хопов возвращается на первую ноду: у неё два отдельных инбаунда")
        ok({tags2["LIVE-2H hop 2"]["port"], tags2["LIVE-3H hop 2"]["port"]}
           <= {i["port"] for i in cfg2["inbounds"]},
           f"нода demo2 приняла хопа цепочек: её инбаунды на "
           f"{tags2['LIVE-2H hop 2']['port']} и {tags2['LIVE-3H hop 2']['port']}")

        hop_tls = tags2["LIVE-2H hop 2"]["streamSettings"]["tlsSettings"]
        hop_cert = CFG2_PATH.parent / hop_tls["certificates"][0]["certificateFile"]
        hop_der = x509.load_pem_x509_certificate(hop_cert.read_bytes()).public_bytes(Encoding.DER)
        pinned = out1["LIVE-2H -> hop 2"]["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"]
        ok(pinned == hashlib.sha256(hop_der).hexdigest(),
           "tls-хоп: сертификат выпустила панель, привезла его ноде-приёмнику, а отправляющая нода "
           "закрепила его отпечаток — Xray 26 иначе такой переход не принял бы")
        ok(out1["LIVE-3H -> hop 2"]["settings"]["servers"][0]["password"]
           == tags2["LIVE-3H hop 2"]["settings"]["users"][0]["password"]
           and out2["LIVE-3H -> hop 3"]["settings"]["vnext"][0]["users"][0]["id"]
           == tags1["LIVE-3H hop 3"]["settings"]["clients"][0]["id"],
           "ключи перехода и инбаунда следующего хопа выведены из одной цепочки: туннель собрался")
        rules1 = {tuple(rule["inboundTag"]): rule["outboundTag"] for rule in cfg1.get("routing", {}).get("rules", [])}
        ok(rules1.get(("LIVE-2H",)) == "LIVE-2H -> hop 2" and rules1.get(("LIVE-3H hop 3",)) is None,
           "правила маршрута на ноде: вход цепочки уходит переходом, выход цепочки — наружу")

        dead = [port for port in sum(chain_ports.values(), []) if not port_alive(port, tries=6)]
        ok(not dead, f"все порты хопа обеих нод слушаются ({sorted(sum(chain_ports.values(), []))})"
           + ("" if not dead else f", мёртвые: {dead}"))

        petya_chain, masha_chain = links_of(petya), links_of(masha)
        ok({"LIVE-2H", "LIVE-3H"} <= set(petya_chain),
           f"вход цепочки — такой же хост подписки: {sorted(k for k in petya_chain if k.startswith('LIVE-'))}")
        ok("pbk=" in petya_chain["LIVE-2H"] and "sid=" in petya_chain["LIVE-2H"],
           "reality-вход цепочки дал подписчику его публичный ключ и короткий id, как обычный reality-хост")
        # туннель через цепочку: если бы демо2 не приняла трафик своего хопа, переход бы не
        # соединился — 204 наружу возможен только через обе ноды
        through("LIVE-2H", free_port(), outbound_from_link(petya_chain["LIVE-2H"]))
        through("LIVE-2H", free_port(), outbound_from_link(masha_chain["LIVE-2H"]), " / masha")
        through("LIVE-3H", free_port(), outbound_from_link(petya_chain["LIVE-3H"]))

        api.delete(f"/api/chains/{next(c['id'] for c in api.get('/api/chains').json() if c['name'] == 'LIVE-2H')}")
        settled_node("demo"), settled_node("demo2")
        cfg1 = json.loads(CFG_PATH.read_text(encoding="utf-8"))
        cfg2 = json.loads(CFG2_PATH.read_text(encoding="utf-8"))
        ok(not any(tag.startswith("LIVE-2H") for tag in [i["tag"] for i in cfg1["inbounds"]])
           and not any(tag.startswith("LIVE-2H") for tag in [i["tag"] for i in cfg2["inbounds"]]),
           "удаление цепочки сняло её инбаунды и переход на обеих нодах")

        # --- Clash/Mihomo берёт подписку целиком и ходит через неё наружу ---
        # Mihomo — тот же движок, что стоит за Clash Verge: если подписку принимает он,
        # её принимают Clash, Clash Verge, flclash и Mihomo proxy-provider.
        clash_bin = os.getenv("MEDUSA_CLASH_BIN") or ""
        if not clash_bin and (ROOT / "bin" / "mihomo").exists():
            clash_bin = str(ROOT / "bin" / "mihomo")
        clash_bin = clash_bin or (shutil.which("mihomo") or "")
        if not clash_bin or not os.access(clash_bin, os.X_OK):
            print("SKIP  mihomo не найден (bin/mihomo или MEDUSA_CLASH_BIN) — живую clash-проверку "
                  "делать нечем, YAML проверен только текстом")
        else:
            mih_dir = tmp / "mihomo"
            mih_dir.mkdir()
            mixed, controller = free_port(), free_port()
            yaml_text = api.get(f"/sub/{petya['token']}?target=clash").text
            # port в тесте свой, чтобы не спорить с живым Clash на машине; всё остальное —
            # дословно та подписка, что отдаёт панель
            cfg_text = yaml_text.replace("mixed-port: 7890", f"mixed-port: {mixed}")
            cfg_text += f"external-controller: 127.0.0.1:{controller}\n"
            (mih_dir / "clash.yaml").write_text(cfg_text, encoding="utf-8")
            tested = subprocess.run([clash_bin, "-t", "-d", str(mih_dir), "-f", str(mih_dir / "clash.yaml")],
                                    capture_output=True, text=True, timeout=60)
            note = (tested.stderr or tested.stdout).strip().splitlines()
            ok(tested.returncode == 0,
               f"mihomo принимает подписку панели как собственный конфиг: {note[-1] if note else 'ok'}")
            if tested.returncode == 0:
                # Reality-хосты Mihomo не пукает живой Xray 26: с версии 26.9.8
                # сервер reality отвергает ClientHello без гибрида X25519MLKEM768,
                # а Mihomo (1.19.34, и master) этого ключа не добавляет — оба фикса
                # в Mihomo закрыты неслитыми. Поэтому здесь reality проверяется как
                # конфиг (он принят и лежит в группе выбора), а его туннель проверяется
                # настоящим Xray-клиентом выше по тексту. Остальные протоколы панель
                # обязана провести через Clash целиком.
                # перечитываем подписку целиком: к этому моменту в ней уже есть
                # вход цепочки LIVE-3H — для Clash он обычный прокси
                live_doc = _yaml.safe_load(yaml_text)
                by_name = {p["name"]: p for p in live_doc["proxies"]}
                live_group = live_doc["proxy-groups"][0]
                reality_names = [n for n, p in by_name.items() if "reality-opts" in p]
                clash_names = [n for n in ("plain", "reality", "wss", "ws", "grpc", "vmess",
                                           "trojan", "trojan-reality", "ss", "LIVE-3H") if n in by_name]
                ok("LIVE-3H" in by_name and by_name["LIVE-3H"]["type"] == "vless"
                   and "LIVE-3H" in live_group["proxies"],
                   "Clash видит вход цепочки обычным прокси в группе выбора: цепочку можно "
                   "выбрать в приложении наравне с прямым хостом")
                ok(sorted(reality_names) == ["reality", "trojan-reality"]
                   and all(by_name[n]["sni"] == by_name[n]["servername"] for n in reality_names),
                   f"clash yaml: reality-хосты названы сайтом-маской обоими полями "
                   f"({by_name['reality']['sni']}): {sorted(reality_names)}")
                print(f"NOTE  через Clash проверяются {len(clash_names) - len(reality_names)} хоста: "
                      f"reality ({', '.join(sorted(reality_names))}) Mihomo {clash_bin} не умеет "
                      f"handshake Xray 26 — см. AGENTS.md, туннель reality проверен Xray-клиентом")
                proc = spawn([clash_bin, "-d", str(mih_dir), "-f", str(mih_dir / "clash.yaml")],
                             os.environ, tmp / "mihomo.log")
                try:
                    for _ in range(40):
                        with socket.socket() as probe:
                            probe.settimeout(2)
                            if probe.connect_ex(("127.0.0.1", mixed)) == 0:
                                break
                        time.sleep(0.4)

                    def select(name: str) -> None:
                        req = urllib.request.Request(
                            f"http://127.0.0.1:{controller}/proxies/"
                            f"{urllib.parse.quote(live_group['name'])}",
                            method="PUT", data=json.dumps({"name": name}).encode(),
                            headers={"Content-Type": "application/json"})
                        urllib.request.urlopen(req, timeout=5).read()

                    for name in clash_names:
                        if name in reality_names:
                            continue
                        select(name)
                        code = 0
                        deadline = time.time() + 25
                        while time.time() < deadline:
                            res = subprocess.run(["curl", "-sS", "-x", f"http://127.0.0.1:{mixed}",
                                                  "--max-time", "8", "-o", os.devnull, "-w", "%{http_code}",
                                                  "https://www.gstatic.com/generate_204"],
                                                 capture_output=True, text=True)
                            if res.stdout.strip() in ("204", "200"):
                                code = int(res.stdout.strip())
                                break
                            time.sleep(0.8)
                        ok(code in (204, 200),
                           f"clash/mihomo {name}: трафик прошёл через подписку панели (HTTP {code})")
                        if code == 0:
                            print("  mihomo.log: " + (tmp / "mihomo.log").read_text(encoding="utf-8")[-700:])
                finally:
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
        qr = api.get(f"/sub/{petya['token']}/qr/subscribe")
        ok(qr.status_code == 200 and qr.headers["content-type"].startswith("image/svg"),
           "QR ссылки подписки рисуется прямо на странице")
        ok(api.get(f"/sub/{petya['token']}/qr/host/{made['ss']['id']}").status_code == 200,
           "QR отдельного хоста собирается и для shadowsocks")

        if "--keep" in sys.argv:
            print(f"\nпанель живёт: {panel_url}, вход medusa / livecheck123. Ctrl+C — остановить.")
            signal.signal(signal.SIGINT, lambda *_: None)
            while panel_proc.poll() is None:
                time.sleep(1)
    finally:
        for proc in (node_proc, node2_proc, panel_proc):
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

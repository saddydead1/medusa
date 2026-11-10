"""Рендер конфига Xray из данных панели.

Панель хранит смысл (пользователи, хосты, защита), нода исполняет байты. Между ними
одна функция: строки базы -> JSON, который понимает `xray run -config`. Здесь нет ни БД,
ни сети, ни ноды — только превращение, поэтому его можно проверить целиком.

Ключи пользователя выводятся из его токена подписки детерминированно:
* `user_uuid` — uuid5 от токена: один и тот же пользователь всегда получает один и
  тот же id в Xray, конфиг от этого стабилен; для vless/vmess (и для reality-подписчиков
  в Xray 26) пользователь — это именно uuid;
* `user_password` — пароль trojan-подписчика;
* `reality_short_id` — короткий id подписчика: внутри одного reality-инбаунда
  подписчиков различают по нему (Xray 26: список `shortIds` у инбаунда, у клиента —
  его собственный `shortId`).

Адрес хоста (`hosts.address`) и адрес ноды — разные вещи: нодовый адрес панель
использует, чтобы достучаться до самой ноды; клиент подключается к адресу хоста.
Пустой адрес хоста означает «подключаться к адресу ноды».

Пока рендерятся vless, vmess и trojan. ss (один пароль на инбаунд) и hy2 — в очереди.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import uuid
from typing import Any

# свой namespace: uuid5 чужого namespace дал бы чужим системам те же id бесплатно
USER_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "medusa.user")

REALITY_PASSWORD_BYTES = 16
# короткий id подписчика: Xray принимает до 8 шестнадцатеричных символов
SHORT_ID_HEX_CHARS = 8

# Xray 26 требует у reality-инбаунда dest — адрес, куда он «притворяется» сайтом,
# если рукопожатие reality не прошло. Панель притворяется Microsoft: живая,
# безобидная и не связана с нашей нодой.
REALITY_DEST = "www.microsoft.com:443"
# Xray 26 по умолчанию не пукает клиентов старше 26.3.27; панель разрешает всё,
# что новее 24.0 — иначе старые клиенты (v2rayN на старом ядре) не подключатся
REALITY_MIN_CLIENT = "24.0.0"

SUPPORTED_PROTOCOLS = ("vless", "vmess", "trojan")


def user_uuid(token: str) -> str:
    return str(uuid.uuid5(USER_NAMESPACE, token))


def user_password(token: str) -> str:
    """Пароль подписчика (reality/trojan): base64url от токена, стабилен между рендерами."""
    digest = hashlib.sha256(f"medusa-user:{token}".encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest[:REALITY_PASSWORD_BYTES]).decode("ascii").rstrip("=")


def reality_short_id(token: str) -> str:
    return hashlib.sha256(f"medusa-shortid:{token}".encode("utf-8")).hexdigest()[:SHORT_ID_HEX_CHARS]


def active_only(users: list[dict]) -> list[dict]:
    return [u for u in users if u["status"] == "active"]


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def cert_paths(host_id: int) -> tuple[str, str]:
    """Соглашение о путях: tls-сертификаты нода держит рядом со своим конфигом."""
    return f"certs/host-{host_id}.crt", f"certs/host-{host_id}.key"


def clients_for(users: list[dict], protocol: str, security: str) -> list[dict]:
    if protocol == "trojan":
        return [{"password": user_password(u["token"])} for u in users]
    return [{"id": user_uuid(u["token"])} for u in users]


def connect_address(host: dict) -> str:
    return host["address"] or host["node_address"]


def stream_settings(host: dict) -> dict[str, Any]:
    address = connect_address(host)
    stream: dict[str, Any] = {"network": host["network"], "security": host["security"]}
    if host["security"] == "tls":
        crt, key = cert_paths(host["id"])
        stream["tlsSettings"] = {
            "serverName": address,
            "certificates": [{"certificateFile": crt, "keyFile": key}],
        }
    elif host["security"] == "reality":
        # Xray 26: серверный reality — это serverNames/shortIds/dest/privateKey;
        # адрес обязан быть доменом (панель это проверяет: IP в SNI не влезает)
        stream["realitySettings"] = {
            "show": False,
            "dest": REALITY_DEST,
            "serverNames": [address],
            "privateKey": host.get("private_key") or "",
            "minClientVer": REALITY_MIN_CLIENT,
            "shortIds": [],
            "spiderX": "/",
        }
    return stream


def inbound(host: dict, users: list[dict]) -> dict[str, Any]:
    users = active_only(users)
    protocol, security = host["protocol"], host["security"]
    clients = clients_for(users, protocol, security)
    entry: dict[str, Any] = {
        "tag": f"medusa-host-{host['id']}",
        "port": host["port"],
        "protocol": protocol,
        "settings": {"clients": clients},
        "streamSettings": stream_settings(host),
    }
    if protocol == "vless":
        entry["settings"]["decryption"] = "none"      # Xray 26 требует явно
    if security == "reality":
        # короткие id живых подписчиков — у инбаунда: клиент приходит со своим shortId
        sids = sorted({reality_short_id(u["token"]) for u in users})
        entry["streamSettings"]["realitySettings"]["shortIds"] = sids or [""]
    return entry


def render_node_config(node: dict, hosts: list[dict], users: list[dict]) -> dict:
    """Один узел = один конфиг. Цепочки сюда пока не попадают: их хопа — про связь
    нод между собой, а не про инбаунд для подписчика."""
    inbounds = [inbound(h, users) for h in hosts if h["protocol"] in SUPPORTED_PROTOCOLS]
    return {
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }

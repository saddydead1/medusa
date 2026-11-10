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
import re
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


def host_tag(host: dict) -> str:
    """Тег инбаунда = имя хоста, как его видит человек.

    Имя не обязано быть уникальным (уникален порт на ноде), поэтому внутри одного
    конфига первому достаётся чистое имя, а совпадающим — имя с id. Пустое имя —
    редкий случай (фронт не пускает), но и ему находится тег.
    """
    name = re.sub(r"[\x00-\x1f\x7f\s]+", " ", str(host.get("name") or "")).strip()
    return name or f"medusa-host-{host['id']}"


def clients_for(users: list[dict], protocol: str, security: str) -> list[dict]:
    if protocol == "trojan":
        return [{"password": user_password(u["token"])} for u in users]
    return [{"id": user_uuid(u["token"])} for u in users]


def connect_address(host: dict) -> str:
    return host["address"] or host["node_address"]


def reality_server_names(host: dict) -> list[str]:
    """Список sni, которые принимает reality: свои алиасы (serverNames через
    запятую), иначе — sni хоста, иначе — адрес хоста (он обязан быть доменом)."""
    raw = (host.get("server_names") or "").replace(",", " ").split()
    names = [n.strip().lower() for n in raw if n.strip()]
    if names:
        return names
    sni = (host.get("sni") or "").strip()
    return [sni or connect_address(host)]


def cert_files(host: dict) -> tuple[str, str]:
    """Файлы сертификатов tls-хоста: свои пути (они абсолютные — нода их не
    переписывает) или генерируемые нодой self-signed рядом с конфигом."""
    cert = (host.get("cert_file") or "").strip()
    key = (host.get("key_file") or "").strip()
    if cert and key:
        return cert, key
    return cert_paths(host["id"])


def stream_settings(host: dict) -> dict[str, Any]:
    address = connect_address(host)
    stream: dict[str, Any] = {"network": host["network"], "security": host["security"]}
    # транспортные детали: путь и Host у websocket; имя сервиса, authority и
    # двунаправленный поток у gRPC; пустое — не пишем вовсе, у Xray свои разумные значения
    if host["network"] == "ws":
        ws: dict[str, Any] = {}
        if host.get("path"):
            ws["path"] = host["path"]
        if host.get("host_header"):
            ws["host"] = host["host_header"]
        if ws:
            stream["wsSettings"] = ws
    elif host["network"] == "grpc":
        grpc: dict[str, Any] = {}
        if host.get("service_name"):
            grpc["serviceName"] = host["service_name"]
        if host.get("grpc_authority"):
            grpc["authority"] = host["grpc_authority"]
        if grpc:
            stream["grpcSettings"] = grpc
    # отпечаток клиента (utls): куда нода притворяется браузером — работает при
    # любой шифрующей защите, поэтому поле общее, а не reality-специальное
    fingerprint = (host.get("fp") or "").strip()
    if fingerprint and host["security"] in ("tls", "reality"):
        stream["fingerprint"] = fingerprint
    if host["security"] == "tls":
        sni = (host.get("sni") or "").strip() or address
        crt, key = cert_files(host)
        tls: dict[str, Any] = {
            "serverName": sni,
            "certificates": [{"certificateFile": crt, "keyFile": key}],
        }
        # версии протокола и наборы шифров панель не называет: у Xray свои
        # разумные договорённости, ломать их пользовательской волей незачем
        if host.get("reject_unknown_sni"):
            tls["rejectUnknownSni"] = True
        stream["tlsSettings"] = tls
    elif host["security"] == "reality":
        # Xray 26: серверный reality — это serverNames/shortIds/dest/privateKey;
        # адрес обязан быть доменом (панель это проверяет: IP в SNI не влезает)
        stream["realitySettings"] = {
            "show": False,
            "dest": host.get("dest") or REALITY_DEST,
            "serverNames": reality_server_names(host),
            "privateKey": host.get("private_key") or "",
            "minClientVer": REALITY_MIN_CLIENT,
            "shortIds": [],
            "spiderX": "/",
        }
    return stream


def inbound(host: dict, users: list[dict], tag: str) -> dict[str, Any]:
    users = active_only(users)
    protocol, security = host["protocol"], host["security"]
    clients = clients_for(users, protocol, security)
    entry: dict[str, Any] = {
        "tag": tag,
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
    hosts = [h for h in hosts if h["protocol"] in SUPPORTED_PROTOCOLS]
    seen: set[str] = set()
    inbounds = []
    for host in hosts:
        tag = host_tag(host)
        if tag in seen:
            tag = f"{tag}-{host['id']}"      # одноимённые хосты на одной ноде: тег остаётся разным
        seen.add(tag)
        inbounds.append(inbound(host, users, tag))
    return {
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }

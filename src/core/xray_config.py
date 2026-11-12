"""Рендер конфига Xray из данных панели.

Панель хранит смысл (пользователи, хосты, защита), нода исполняет байты. Между ними
одна функция: строки базы -> JSON, который понимает `xray run -config`. Здесь нет ни БД,
ни сети, ни ноды — только превращение, поэтому его можно проверить целиком.

Ключи пользователя выводятся из его токена подписки детерминированно:
* `user_uuid` — uuid5 от токена: один и тот же пользователь всегда получает один и
  тот же id в Xray, конфиг от этого стабилен; для vless/vmess (и для reality-подписчиков
  в Xray 26) пользователь — это именно uuid;
* `user_password` — пароль подписчика: у trojan он один на все хосты (так уже
  подключённые люди не обязаны менять ссылку), у shadowsocks — свой на каждый хост:
  пароль ss это и есть ключ шифрования конкретного порта, и на другом порту он обязан
  быть другим;
* `reality_short_id` — короткий id подписчика: внутри одного reality-инбаунда
  подписчиков различают по нему (Xray 26: список `shortIds` у инбаунда, у клиента —
  его собственный `shortId`); работает с любым протоколом, у которого есть reality.

Адрес хоста (`hosts.address`) и адрес ноды — разные вещи: нодовый адрес панель
использует, чтобы достучаться до самой ноды; клиент подключается к адресу хоста.
Пустой адрес хоста означает «подключаться к адресу ноды».

Рендерятся vless, vmess, trojan и shadowsocks. Hysteria2 (hy2) — в очереди: он требует
TLS у инбаунда в обязательном порядке и собственного формата ссылки, которого у панели
пока нет, поэтому хост hy2 панель не создаёт (400), а не создаёт «хост, который не поднимется».
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
# Порога версии клиента (realitySettings.minClientVer) панель не ставит, и это не
# косметика. В reality версия клиента — первые три байта session id в ClientHello,
# формальность рукопожатия: клиенты семейства Clash пишут туда «1.8.2» (столько весит
# формат их ссылок), и любой порог вроде «24.0.0» просто отцепил бы их от ноды, ничего
# не прибавив к защите. Настоящий ценз Xray >= 26.9.8 держит другое: обязательный гибрид
# X25519MLKEM768 в ClientHello (о нём — в AGENTS.md).

SUPPORTED_PROTOCOLS = ("vless", "vmess", "trojan", "ss")

# VMess: alterId у панели всегда 0 (устаревший режим клиенты выкинули), шифр — "auto":
# Xray и клиент сами выбирают то, что понимают оба (aes-128-gcm у старых клиентов,
# chacha20-ietf-poly1305 у новых)
VMESS_CIPHER = "auto"
# Shadowsocks: AEAD-шифр на весь инбаунд. chacha20-ietf-poly1305 понимают v2rayN/v2rayNG,
# Happ, Hiddify, Shadowrocket и Clash — и это разумный дефолт самого Xray
SS_CIPHER = "chacha20-ietf-poly1305"

# Какая защита бывает у какого протокола. Держится и фронтом (какие опции защиты
# показать), и бэкендом (что принять): ссылка подписки обязана уметь описать то, что
# панель собрала в конфиге, а vmess-ссылка reality описать не может.
SECURITY_BY_PROTOCOL = {
    "vless": ("none", "tls", "reality"),
    "vmess": ("none", "tls"),
    "trojan": ("none", "tls", "reality"),
    "ss": ("none",),
}

# Hysteria2 панель пока не поднимает: у него TLS у инбаунда обязателен, нужен
# отдельный hub-obfs и своя форма ссылки, которой у панели нет. Честный отказ лучше
# хоста, который молча не доехал бы ни до конфига, ни до подписчика.
UNSUPPORTED_PROTOCOLS = ("hy2",)
UNSUPPORTED_HINT = ("Hysteria2 панель пока не поднимает: выберите vless, vmess, trojan "
                    "или shadowsocks")


def unsupported_protocol(protocol: str) -> bool:
    return protocol in UNSUPPORTED_PROTOCOLS


def security_issue(protocol: str, security: str) -> str | None:
    """Почему эта защита у этого протокола не бывает — текстом для человека.
    Один и тот же текст звучит и в окне хоста, и в отказе API."""
    if protocol == "ss" and security in ("tls", "reality"):
        return ("у shadowsocks свой шифр внутри протокола: tls или reality к нему панель "
                "не добавляет — нужен tls? берите vless или trojan")
    if protocol == "vmess" and security == "reality":
        return ("vmess поверх reality панель не раздаёт: vmess-ссылка не умеет передавать "
                "reality-ключ и короткий id — берите vless или trojan")
    return None


def user_uuid(token: str) -> str:
    return str(uuid.uuid5(USER_NAMESPACE, token))


def user_password(token: str, salt: str = "") -> str:
    """Пароль подписчика: base64url от токена, стабилен между рендерами.

    `salt` делает пароль разным на разных хостах там, где это нужно (shadowsocks);
    без соли пароль один и тот же — прежние подписки не рассинхронизируются."""
    seed = f"medusa-user:{salt}:{token}" if salt else f"medusa-user:{token}"
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest[:REALITY_PASSWORD_BYTES]).decode("ascii").rstrip("=")


def ss_password(token: str, host_id: int) -> str:
    """Пароль shadowsocks-подписчика на конкретном хосте: он же AEAD-ключ этого порта."""
    return user_password(token, f"ss:{host_id}")


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


def clients_for(users: list[dict], protocol: str, host: dict | None = None) -> list[dict]:
    """Клиенты инбаунда: чем протокол узнаёт человека, тем и описывает.

    Порядок ключей в словарях постоянный — от него зависит отпечаток конфига, а значит
    и «не дёргать ноду при неизменном составе».
    """
    if protocol == "trojan":
        return [{"password": user_password(u["token"])} for u in users]
    if protocol == "ss":
        salt = f"ss:{host['id']}" if host else "ss"
        return [{"password": user_password(u["token"], salt), "method": SS_CIPHER} for u in users]
    clients = []
    for u in users:
        client = {"id": user_uuid(u["token"])}
        if protocol == "vmess":
            client["security"] = VMESS_CIPHER      # Xray: согласуемый шифр vmess-клиента
        clients.append(client)
    return clients


def connect_address(host: dict) -> str:
    return host["address"] or host["node_address"]


def field(host: object, key: str) -> str:
    """Поле хоста строкой: одинаково для словаря рендера и для строки sqlite."""
    try:
        raw = host[key]
    except (KeyError, IndexError, TypeError):
        return ""
    if raw is None:
        return ""
    return raw if isinstance(raw, str) else str(raw)


def reality_dest(host: object) -> str:
    """Адрес-маска reality (`host:port`), за которую нода притворяется."""
    return field(host, "dest").strip() or REALITY_DEST


def reality_sni_list(host: object, address: str) -> list[str]:
    """Имена, которые принимает reality и которые обязан назвать клиент.

    Клиент в reality называет не адрес ноды, а тот домен, за который нода
    притворяется: наружу уходит настоящий сертификат этого сайта, и строгие клиенты
    (Mihomo/Clash) сверяют sni именно с ним. Поэтому по умолчанию это домен маскировки
    (dest), а не адрес хоста.
    """
    names = [n.strip().lower() for n in field(host, "server_names").replace(",", " ").split() if n.strip()]
    if names:
        return names
    mirror = reality_dest(host).split(":")[0].strip().lower()
    return [mirror or address.lower()]


def reality_client_sni(host: object, address: str) -> str:
    """SNI клиента — первое из принимаемых reality имён. IP в SNI клиент подставить
    не умеет, поэтому адрес-маска обязан быть доменом."""
    for name in reality_sni_list(host, address):
        if name and not is_ip(name):
            return name
    return ""


def reality_server_names(host: dict) -> list[str]:
    """Список sni для инбаунда: свои алиасы, иначе домен маскировки (dest)."""
    return reality_sni_list(host, connect_address(host))


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
        # имена берутся из маскировки, потому что клиент сверяет их с настоящим
        # сертификатом сайта-маски
        stream["realitySettings"] = {
            "show": False,
            "dest": reality_dest(host),
            "serverNames": reality_sni_list(host, address),
            "privateKey": host.get("private_key") or "",
            "shortIds": [],
            "spiderX": "/",
        }
    return stream


def inbound(host: dict, users: list[dict], tag: str) -> dict[str, Any]:
    users = active_only(users)
    protocol, security = host["protocol"], host["security"]
    clients = clients_for(users, protocol, host)
    # у shadowsocks клиенты живут в `users` (Xray зовёт это мультипользовательским ss:
    # инбаунд различает людей по их ключам) и шифр называется у каждого клиента свой
    settings: dict[str, Any] = {"users": clients} if protocol == "ss" else {"clients": clients}
    entry: dict[str, Any] = {
        "tag": tag,
        "port": host["port"],
        "protocol": protocol if protocol != "ss" else "shadowsocks",
        "settings": settings,
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

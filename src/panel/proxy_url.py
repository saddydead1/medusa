"""SOCKS5-прокси, через который панель доходит до API ноды.

Настройка на каждую ноду (`nodes.api_proxy`): нода может сидеть за NAT или быть доступна
только через прыжок. Панель умеет только socks5 (и socks5h — с резолвом имени на стороне
прокси): http-прокси ей не нужен, API ноды и так http, а socks5 переключает голый TCP и
подходит к любому адресу ноды.

В базе форма нормализованная: `socks5://[user[:pass]@]host:port` — пустая строка значит
«без прокси». Наружу в списках панель отдаёт masked-форму (пароль скрыт): целиком прокси видит
только тот, кто его вписывает или переносит (`GET /api/nodes/{id}/proxy`), как это уже
устроено с API-ключом ноды.
"""
from __future__ import annotations

from urllib.parse import urlsplit

ALLOWED_SCHEMES = ("socks5", "socks5h")
DEFAULT_PORT = 1080
MASK = "••••"


class ProxySettingError(ValueError):
    """Прокси не подходит человеку: текст идёт в ответ 422 как есть."""


def normalize_proxy(raw: str | None) -> str:
    """Привести ввод к каноничному виду или объяснить, что не так. '' — прокси нет."""
    value = (raw or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = f"socks5://{value}"          # человек мог написать просто host:port
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as err:
        raise ProxySettingError(f"прокси {raw!r}: не читается адрес — ждём socks5://host:port") from err

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ProxySettingError(
            f"прокси {raw!r}: панель умеет только socks5 (или socks5h) — {parts.scheme!r} не подходит")
    host = (parts.hostname or "").strip()
    if not host:
        raise ProxySettingError(f"прокси {raw!r}: нет адреса прокси — ждём socks5://host:port")
    if port is None:
        port = DEFAULT_PORT
    if not 1 <= port <= 65535:
        raise ProxySettingError(f"прокси {raw!r}: порт {port} вне диапазона 1..65535")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ProxySettingError(f"прокси {raw!r}: лишнее после адреса — прокси бывает только host:port")

    user = parts.username or ""
    password = parts.password or ""
    auth = ""
    if user:
        auth = f"{user}:{password}@" if password else f"{user}@"
    if not user and password:
        raise ProxySettingError(f"прокси {raw!r}: пароль без имени пользователя — socks5://user:pass@host:port")
    host = f"[{host}]" if ":" in host else host      # IPv6 в скобках
    return f"{scheme}://{auth}{host}:{port}"


def mask_proxy(url: str) -> str:
    """Форма для списков и ошибок: адрес виден, пароля нет."""
    value = (url or "").strip()
    if not value:
        return ""
    parts = urlsplit(value)
    if not parts.password:
        return value
    host = parts.hostname or ""
    host = f"[{host}]" if ":" in host else host
    port = parts.port or DEFAULT_PORT
    user = parts.username or ""
    auth = f"{user}:{MASK}@" if user else f"{MASK}@"
    return f"{parts.scheme}://{auth}{host}:{port}"

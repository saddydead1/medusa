"""Как панель и рендер конфига понимают «это адрес IPv6».

Нужно одному правилу на весь монолит: если на ноде выключен IPv6 (`nodes.ipv6_disabled`),
IPv6-адрес у её хоста или хопа быть не может — Xray на такой ноде слушает только IPv4, и
человек с IPv6-адресом в ссылке подписки до хоста просто не доедет. Проверять это должны
и эндпоинты хостов/цепочек/нод (чтобы сказать об этом человеку), и рендер (чтобы конфиг
не расходился с тем, что нода слушает).
"""
from __future__ import annotations

import ipaddress

# IPv6 в ссылках и в карточках пишется иногда в скобках ([2001:db8::1]) — как в URL
_BRACKETS = ("[", "]")


def clean_address(text: object) -> str:
    return str(text or "").strip().strip("".join(_BRACKETS))


def is_ipv6_literal(text: object) -> bool:
    """IPv6-адрес (не домен, не IPv4). Пусто и домен — False."""
    raw = clean_address(text)
    if not raw or ":" not in raw:
        return False
    try:
        return isinstance(ipaddress.ip_address(raw), ipaddress.IPv6Address)
    except ValueError:
        return False


def is_ip_literal(text: object) -> bool:
    """Любой литеральный адрес (v4 или v6) — доменом он не является."""
    raw = clean_address(text)
    if not raw:
        return False
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        return False
    return True

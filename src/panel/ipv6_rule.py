"""Правило «у ноды без IPv6 не может быть IPv6-адреса».

Если на ноде выключен IPv6 (`nodes.ipv6_disabled`), её Xray слушает `0.0.0.0` и ходит
наружу по IPv4. Значит хост (или хоп цепочки) с IPv6-адресом на такой ноде — это ссылка,
по которой подписчик никуда не придёт: панель обязана сказать об этом сразу, а не молча
положить инбаунд, который никто не откроет. Тот же разбор делает и рендер конфига
(`src/core/xray_config.apply_ipv6_policy`), чтобы конфиг не расходился с проверкой.
"""
from __future__ import annotations

import sqlite3

from src.core.addresses import is_ipv6_literal


def disabled(node: sqlite3.Row | dict) -> bool:
    value = node["ipv6_disabled"] if isinstance(node, sqlite3.Row) else node.get("ipv6_disabled")
    return bool(value)


def address_conflict(node_name: str, address: str, what: str = "адрес хоста") -> str | None:
    """Тот же разбор, но когда строка ноды уже превратилась в имя и флаг."""
    if not is_ipv6_literal(address):
        return None
    return (f"на ноде «{node_name}» выключен IPv6, а {what} — IPv6-адрес ({address}): "
            "Xray такой ноды слушает только IPv4, и подключиться по этому адресу нельзя")


def host_conflict(node: sqlite3.Row | dict, address: str, what: str = "адрес хоста") -> str | None:
    """Текст человеческой ошибки, если адрес IPv6, а IPv6 на ноде выключен."""
    if not disabled(node):
        return None
    return address_conflict(node["name"], address, what)


def node_conflict(address: str, ipv6_disabled: bool) -> str | None:
    """Нельзя выключить IPv6 на ноде, адрес которой сам IPv6: панель до неё ходит по нему же."""
    if ipv6_disabled and is_ipv6_literal(address):
        return (f"IPv6 на ноде нельзя выключить: её адрес ({address}) — IPv6, "
                "и панель, хосты и подписчики идут к ней по этому адресу")
    return None

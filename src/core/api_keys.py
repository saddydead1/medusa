"""API-ключ ноды: генерация, отпечаток, сравнение.

Ключ создаёт сама нода (или его ей задают через `MEDUSA_NODE_API_KEY`), администратор
переносит его в панель, и дальше панель предъявляет его ноде в
`Authorization: Bearer <ключ>`. Без API-ключа нода добавляться не может: без него
панель не сможет сделать ничего, кроме как проверить, что нода отвечает.

В панели ключ хранится открыто — без него нельзя подписать запрос. Чтобы он не светился
в ответах API и в логах, везде работаем с отпечатком: короткой меткой из sha256 ключа.
Отпечаток позволяет проверить «ключ в панели и ключ на ноде — про одни и те же руки»,
не показывая сам ключ.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

API_KEY_PREFIX = "sk-api-"
API_KEY_BYTES = 32                 # 256 бит энтропии
FINGERPRINT_BYTES = 5              # 10 hex-символов: хватает, чтобы опознать ноду


def new_api_key() -> str:
    return API_KEY_PREFIX + secrets.token_urlsafe(API_KEY_BYTES)


def looks_like_api_key(value: str) -> bool:
    return value.startswith(API_KEY_PREFIX) and len(value) >= 20


def api_key_fingerprint(key: str) -> str:
    """Короткая метка ключа: `a1b2c-3d4e5`. По ней ноду опознать можно, ключ восстановить — нет."""
    short = hashlib.sha256(key.encode("utf-8")).hexdigest()[: FINGERPRINT_BYTES * 2]
    return f"{short[:5]}-{short[5:]}"


def keys_match(key: str, other: str) -> bool:
    """Сравнение за постоянное время — чтобы по длительности ответа не подбирали ключ."""
    return hmac.compare_digest(key, other)


def mask_api_key(key: str) -> str:
    """Для UI и логов: начало ключа и отпечаток, остальное не восстанавливается."""
    head = key[:6] if len(key) > 12 else key[:2]
    return f"{head}…{api_key_fingerprint(key)}"

"""Пароли и сессии администраторов.

Только stdlib: pbkdf2-hmac для паролей, случайные токены для сессий.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

ITERATIONS = 120_000
PREFIX = "pbkdf2_sha256"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return f"{PREFIX}${ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        prefix, iterations, salt_hex, digest_hex = stored.split("$")
        if prefix != PREFIX:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def new_user_token() -> str:
    """Короткий токен подписки: он попадает в ссылку пользователю."""
    return secrets.token_urlsafe(8).replace("-", "x").replace("_", "y")[:10]


def temporary_password() -> str:
    return secrets.token_urlsafe(9)

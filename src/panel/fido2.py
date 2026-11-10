"""FIDO2 / WebAuthn в панели: вход аппаратным ключом (YubiKey и подобные) и сами ключи.

Здесь своя проверка, без готового верификатора протокола. Регламент сознательно
узкий: алгоритмы ES256 и EdDSA, аттестат `none` или `packed`, один тип ceremony —
`webauthn.get` для входа и `webauthn.create` для записи ключа.

Что проверяется обязательно:
* challenge — одноразовый, выданный панелью и живущий 5 минут;
* origin и rpId внутри clientDataJSON — их подделывает чужая страница, не ключ;
* rpIdHash внутри authenticatorData;
* флаг UP (пользователь присутствовал);
* подпись ответа — настоящим открытым ключом credential'а, который панель сохранила
  при записи этого ключа.

Что не проверяется: цепочка сертификатов производителя (AAGUID). Панель не выбирает
производителей ключей и не ведёт список разрешённых: ей важен сам ключ и его подпись.
Это normalный режим rely party «доверяю при первой записи»: ключ записывает тот, кто
уже сидит в панели как владелец или администратор.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
from typing import Any

import cbor2
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from fastapi import HTTPException, Request

from src.panel.db import now_ms

CHALLENGE_BYTES = 32
CHALLENGE_TTL_MS = 5 * 60 * 1000
FLAG_USER_PRESENT = 0x01
FLAG_ATTESTED = 0x40

# только эти два: ES256 (есть у всех FIDO2-ключей) и EdDSA (современные YubiKey)
ALGORITHMS = {-7: "ES256", -8: "EdDSA"}
COSE_KEY_TYPE = 1
COSE_ALG = 3
COSE_CRVE = -1
COSE_X = -2
COSE_Y = -3
KTY_EC2 = 2
KTY_OKP = 1
CRVE_P256 = 1
CURVE_OKP = 6

AUTH_DATA_HEAD = 37          # rpIdHash (32) + флаги (1) + счётчик (4)
AAGUID_BYTES = 16


class FidoError(Exception):
    """Любая неудача ceremony: сообщение идёт человеку, поэтому по-русски."""


# ---------------------------------------------------------------- base64url

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(value: str) -> bytes:
    if not isinstance(value, str):
        raise FidoError("ожидается строка base64url")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as err:
        raise FidoError("не base64url") from err


# ---------------------------------------------------------------- challenge

def new_challenge(conn: sqlite3.Connection, purpose: str, admin_id: int | None = None) -> str:
    conn.execute("DELETE FROM fido_challenges WHERE created_at < ?", (now_ms() - CHALLENGE_TTL_MS,))
    challenge = b64url(secrets.token_bytes(CHALLENGE_BYTES))
    conn.execute(
        "INSERT INTO fido_challenges (challenge, purpose, admin_id, created_at) VALUES (?,?,?,?)",
        (challenge, purpose, admin_id, now_ms()),
    )
    conn.commit()
    return challenge


def take_challenge(conn: sqlite3.Connection, challenge: str, purpose: str) -> sqlite3.Row:
    """Challenge расходуется: второй раз тем же его проверить нельзя (защита от повтора)."""
    row = conn.execute("SELECT * FROM fido_challenges WHERE challenge = ?", (challenge,)).fetchone()
    conn.execute("DELETE FROM fido_challenges WHERE challenge = ?", (challenge,))
    conn.commit()
    if row is None:
        raise FidoError("вызов ноды панели не помнит: начните вход заново")
    if row["purpose"] != purpose:
        raise FidoError("этот вызов был для другого действия")
    if row["created_at"] < now_ms() - CHALLENGE_TTL_MS:
        raise FidoError("вызов протух: начните вход заново")
    return row


# ---------------------------------------------------------------- проис панели

def panel_origin(request: Request) -> str:
    """От origin браузер и делает assertion: панель обязана узнать свой.

    MEDUSA_PANEL_BASE задаёт настоящий адрес (панель за HTTPS-реверсом), иначе берётся
    то, чем панель отвечает прямо сейчас.
    """
    base = os.getenv("MEDUSA_PANEL_BASE")
    if base:
        return base.rstrip("/")
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}"


def rp_id(request: Request) -> str:
    env = os.getenv("MEDUSA_RP_ID")
    if env:
        return env
    host = panel_origin(request).split("://", 1)[-1]
    return host.split(":")[0]


def panel_name(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT panelName FROM settings WHERE id = 1").fetchone()
    return row["panelName"] if row else "Medusa"


def passkey_enabled(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT passkeyEnabled FROM settings WHERE id = 1").fetchone()
    return bool(row and row["passkeyEnabled"])


# ---------------------------------------------------------------- параметры ceremony

def registration_options(conn: sqlite3.Connection, admin: sqlite3.Row, request: Request) -> dict[str, Any]:
    challenge = new_challenge(conn, "register", admin["id"])
    return {
        "rp": {"id": rp_id(request), "name": panel_name(conn)},
        "user": {"id": b64url(str(admin["id"]).encode()), "name": admin["username"],
                 "displayName": admin["username"]},
        "challenge": challenge,
        "pubKeyCredParams": [{"type": "public-key", "alg": alg} for alg in ALGORITHMS],
        "timeout": 120_000,
        "attestation": "none",
        "authenticatorSelection": {"residentKey": "required", "userVerification": "preferred"},
    }


def assertion_options(conn: sqlite3.Connection, request: Request, usernames: list[str] | None = None) -> dict[str, Any]:
    challenge = new_challenge(conn, "login")
    options: dict[str, Any] = {
        "challenge": challenge,
        "rpId": rp_id(request),
        "timeout": 120_000,
        "userVerification": "preferred",
    }
    if usernames:
        marks = []
        for username in usernames:
            rows = conn.execute(
                """SELECT k.cred_id FROM admin_keys k JOIN admins a ON a.id = k.admin_id
                   WHERE a.username = ?""",
                (username,),
            ).fetchall()
            marks.extend({"type": "public-key", "id": r["cred_id"]} for r in rows)
        if marks:
            options["allowCredentials"] = marks
    return options


# ---------------------------------------------------------------- разбор ответа ключа

def _client_data(response: dict[str, Any], purpose: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = unb64url(response["clientDataJSON"])
        data = json.loads(raw)
    except (KeyError, FidoError, json.JSONDecodeError) as err:
        raise FidoError("ответ ключа не читается") from err
    if data.get("type") != purpose:
        raise FidoError(f"ключ отвечает не на то действие: {data.get('type')}")
    return raw, data


def _authenticator_data(raw: bytes, request: Request) -> tuple[bytes, int]:
    if len(raw) < AUTH_DATA_HEAD:
        raise FidoError("данные аутентикатора обрезаны")
    rp_hash, flags, counter = raw[:32], raw[32], int.from_bytes(raw[33:37], "big")
    if rp_hash != hashlib.sha256(rp_id(request).encode()).digest():
        raise FidoError("ключ не для этой панели (rpId не совпал)")
    if not flags & FLAG_USER_PRESENT:
        raise FidoError("ключ не подтвердил присутствие пользователя")
    return raw, counter


def _signing_data(auth_data: bytes, client_raw: bytes) -> bytes:
    return auth_data + hashlib.sha256(client_raw).digest()


def _verify_signature(public_key: Any, signature: bytes, signed: bytes, alg: int) -> None:
    try:
        if alg == -7:
            public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        else:
            public_key.verify(signature, signed)
    except InvalidSignature as err:
        raise FidoError("подпись ключа не подходит") from err


def _cose_public_key(cose: dict[int, Any]) -> tuple[Any, int]:
    kty = cose.get(COSE_KEY_TYPE)
    alg = cose.get(COSE_ALG)
    if kty == KTY_EC2:
        if cose.get(COSE_CRVE) != CRVE_P256:
            raise FidoError("ключ не на P-256")
        point = b"\x04" + cose[COSE_X] + cose[COSE_Y]
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point), alg
    if kty == KTY_OKP:
        return ed25519.Ed25519PublicKey.from_public_bytes(cose[COSE_X]), alg
    raise FidoError("неизвестный тип ключа")


def _attestation(attestation: dict[str, Any], auth_data: bytes, client_raw: bytes, fmt: str) -> dict[str, Any]:
    """Разбирает аттестат и возвращает credential: id, алгоритм, публичный ключ, aaguid."""
    if fmt == "none":
        # ключ говорит «я такой, верить нечем»: подпись проверим потом, на каждом входе
        body = auth_data[AUTH_DATA_HEAD:]
    elif fmt == "packed":
        stmt = attestation.get("attStmt") or {}
        alg = stmt.get("alg")
        sig = stmt.get("sig")
        if not isinstance(sig, bytes) or alg not in ALGORITHMS:
            raise FidoError("packed-аттестат без подписи панель не принимает")
        chain = stmt.get("x5c")
        if chain:
            cert = x509.load_der_x509_certificate(chain[0])
            _verify_signature(cert.public_key(), sig, _signing_data(auth_data, client_raw), alg)
        body = auth_data[AUTH_DATA_HEAD:]
    else:
        raise FidoError(f"аттестат {fmt} панель разбирать не умеет")

    # attested credential data: aaguid + длина id + id + COSE-ключ
    if len(body) < AAGUID_BYTES + 2:
        raise FidoError("в аттестате нет данных о ключе")
    aaguid, cred_len = body[:AAGUID_BYTES], int.from_bytes(body[AAGUID_BYTES:AAGUID_BYTES + 2], "big")
    offset = AAGUID_BYTES + 2
    cred_id = body[offset:offset + cred_len]
    cose = cbor2.loads(body[offset + cred_len:])
    public_key, cose_alg = _cose_public_key(cose)
    if cose_alg not in ALGORITHMS:
        raise FidoError("ключ использует алгоритм, который панель не проверяет")
    return {
        "cred_id": b64url(cred_id),
        "algo": cose_alg,
        "public_key": public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii"),
        "aaguid": "-".join(format_bytes(aaguid)),
        "counter": int.from_bytes(auth_data[33:37], "big"),
    }


def format_bytes(data: bytes) -> list[str]:
    hexed = data.hex()
    return [hexed[0:8], hexed[8:12], hexed[12:16], hexed[16:20], hexed[20:32]]


def _response_fields(response: dict[str, Any]) -> tuple[dict[str, Any], bytes, bytes, str]:
    try:
        inner = response["response"]
        raw_client, raw_att = unb64url(inner["clientDataJSON"]), unb64url(inner.get("attestationObject") or inner["authenticatorData"])
    except (KeyError, FidoError, TypeError) as err:
        raise FidoError("браузер прислал не структуру PublicKeyCredential") from err
    return inner, raw_client, raw_att, str(response.get("id") or "")


# ---------------------------------------------------------------- ceremony

def verify_registration(conn: sqlite3.Connection, admin_id: int, response: dict[str, Any],
                        request: Request, nickname: str = "") -> dict[str, Any]:
    """Записывает ключ администратору. Делает это только тот, кто уже пишет панель."""
    inner, client_raw, att_raw, cred_id = _response_fields(response)
    client = _client_data({"clientDataJSON": inner["clientDataJSON"]}, "webauthn.create")
    challenge_row = take_challenge(conn, client[1]["challenge"], "register")
    if challenge_row["admin_id"] != admin_id:
        raise FidoError("этот вызов был выдан не для этого администратора")
    if client[1].get("origin") != panel_origin(request):
        raise FidoError("ключ записывается с чужого адреса панели")
    try:
        attestation = cbor2.loads(att_raw)
    except Exception as err:
        raise FidoError("аттестат ключа не читается") from err
    if not isinstance(attestation, dict):
        raise FidoError("аттестат ключа — не структура")
    auth_data = attestation.get("authData")
    if not isinstance(auth_data, bytes):
        raise FidoError("в аттестате нет данных аутентикатора")
    auth_data, _ = _authenticator_data(auth_data, request)
    if not auth_data[32] & FLAG_ATTESTED or len(auth_data) <= AUTH_DATA_HEAD:
        raise FidoError("ключ не прислал данных о новом credential'е")
    info = _attestation(attestation, auth_data, client_raw, attestation.get("fmt", "none"))
    if info["algo"] not in ALGORITHMS:
        raise FidoError("ключ использует алгоритм, который панель не проверяет")
    try:
        conn.execute(
            """INSERT INTO admin_keys (admin_id, cred_id, algo, public_key, aaguid, sign_count, nickname, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (admin_id, info["cred_id"], info["algo"], info["public_key"], info["aaguid"],
             info["counter"], nickname.strip()[:32], now_ms()),
        )
    except sqlite3.IntegrityError:
        raise FidoError("такой ключ уже записан") from None
    conn.commit()
    return key_info(conn.execute("SELECT * FROM admin_keys WHERE cred_id = ?", (info["cred_id"],)).fetchone())


def verify_assertion(conn: sqlite3.Connection, response: dict[str, Any], request: Request) -> dict[str, Any]:
    """Вход по ключу: проверяет подпись и возвращает администратора с новым токеном."""
    inner, client_raw, auth_raw, cred_id = _response_fields(response)
    client = _client_data({"clientDataJSON": inner["clientDataJSON"]}, "webauthn.get")
    take_challenge(conn, client[1]["challenge"], "login")
    if client[1].get("origin") != panel_origin(request):
        raise FidoError("ключ отвечает чужой панели")
    auth_data, counter = _authenticator_data(auth_raw, request)
    if not cred_id:
        raise FidoError("ключ не назвал свой идентификатор")
    row = conn.execute("SELECT * FROM admin_keys WHERE cred_id = ?", (cred_id,)).fetchone()
    if row is None:
        raise FidoError("такого ключа панель не записывала")
    admin = conn.execute("SELECT * FROM admins WHERE id = ?", (row["admin_id"],)).fetchone()
    if admin is None or admin["status"] != "active":
        raise FidoError("администратор этого ключа отключён")
    public_key = serialization.load_pem_public_key(row["public_key"].encode("ascii"))
    _verify_signature(public_key, unb64url(inner["signature"]), _signing_data(auth_data, client_raw), row["algo"])
    if row["sign_count"] > 0 and counter <= row["sign_count"]:
        # ключ, который ведёт счётчик, обязан его увеличивать; молчаливые счётчики (0)
        # панель не наказывает: повтор исключает одноразовый вызов, а не счётчик
        raise FidoError("ключ не увеличил счётчик: похоже на повтор ответа")
    conn.execute("UPDATE admin_keys SET sign_count = ? WHERE cred_id = ?", (max(counter, 0), cred_id))
    conn.commit()
    return {"admin": admin, "key": key_info(row)}


def key_info(row: sqlite3.Row) -> dict[str, Any]:
    """Как ключ показывается наружу: самого открытого ключа здесь нет."""
    return {
        "id": row["id"],
        "nickname": row["nickname"] or "аппаратный ключ",
        "algo": ALGORITHMS.get(row["algo"], str(row["algo"])),
        "aaguid": row["aaguid"],
        "counter": row["sign_count"],
        "createdAt": row["created_at"],
    }

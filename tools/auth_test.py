"""Проверка прав, сессий и входа по аппаратному ключу (FIDO2).

Аутентикатор здесь синтетический: панель не знает, что ключ бутафорский — она проверяет
ровно то же, что проверяет против настоящего YubiKey: одноразовый вызов, origin, rpId,
флаг присутствия и подпись ответа открытым ключом credential'а. Подпись настоящая,
ключи настоящие (EC P-256), аттестат `none`.

Панель поднимается на временной базе, с включённой авторизацией (как по умолчанию).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import secrets
import sqlite3
import tempfile
import time

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

ROOT = pathlib.Path(__file__).resolve().parent.parent
os.environ["MEDUSA_DB"] = str(pathlib.Path(tempfile.mkdtemp()) / "auth.db")
os.environ["MEDUSA_ADMIN_USER"] = "vlad"
os.environ["MEDUSA_ADMIN_PASSWORD"] = "vladpassword1"

from src.panel.main import app  # noqa: E402

fails = 0


def ok(condition: bool, message: str) -> None:
    global fails
    print(("PASS  " if condition else "FAIL  ") + message)
    if not condition:
        fails += 1


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class FakeKey:
    """Кусок железа, который честно выполняет WebAuthn-рукопожатие."""

    def __init__(self, rp_id: str) -> None:
        self.rp_id = rp_id
        self.private = ec.generate_private_key(ec.SECP256R1())
        public = self.private.public_key().public_numbers()
        self.cred_id = b"cred-" + secrets.token_bytes(12)
        self.counter = 0
        self.cose = {1: 2, 3: -7, -1: 1, -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big")}

    def _auth_data(self, flags: int, tail: bytes = b"") -> bytes:
        self.counter += 1
        return (hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags])
                + self.counter.to_bytes(4, "big") + tail)

    def _client(self, kind: str, challenge: str, origin: str) -> bytes:
        return json.dumps({"type": kind, "challenge": challenge, "origin": origin,
                           "crossOrigin": False}).encode()

    def register(self, options: dict, origin: str) -> dict:
        aaguid = bytes(16)
        tail = aaguid + len(self.cred_id).to_bytes(2, "big") + self.cred_id + cbor2.dumps(self.cose)
        auth_data = self._auth_data(0x41, tail)                      # UP | AT
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client = self._client("webauthn.create", options["challenge"], origin)
        return {"id": b64(self.cred_id), "rawId": b64(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64(client), "attestationObject": b64(attestation)}}

    def assert_for(self, options: dict, origin: str) -> dict:
        auth_data = self._auth_data(0x01)
        client = self._client("webauthn.get", options["challenge"], origin)
        signature = self.private.sign(auth_data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64(self.cred_id), "rawId": b64(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64(client), "authenticatorData": b64(auth_data),
                             "signature": b64(signature)}}


def main() -> int:
    with TestClient(app) as client:
        origin = "http://testserver"

        # --- без сессии панель закрыта: и на чтение, и на запись ---
        ok(client.get("/api/nodes").status_code == 401, "без сессии список нод не отдаётся")
        ok(client.post("/api/nodes", json={"name": "x", "address": "1.2.3.4", "apiKey": "sk-api-abcdefghijklmn"}).status_code == 401,
           "без сессии ноду не создать")
        ok(client.get("/api/meta").status_code == 200, "версия панели (/api/meta) открыта и до входа")

        # --- вход владельца ---
        login = client.post("/api/login", json={"username": "vlad", "password": "vladpassword1"})
        ok(login.status_code == 200, "владелец вошёл по паролю")
        owner_token = login.json()["token"]
        owner = login.json()["admin"]
        ok(owner["role"] == "owner", f"роль из входа: {owner['role']}")
        client.headers["Authorization"] = f"Bearer {owner_token}"

        ok(client.get("/api/nodes").status_code == 200, "с сессией панель смотрит")
        node = client.post("/api/nodes", json={"name": "authnode", "address": "10.9.9.9", "apiKey": "sk-api-authnode01234567890"})
        ok(node.status_code == 201, "владелец создаёт ноду")
        me = client.get("/api/me").json()
        ok(me["role"] == "owner" and me["expiresAt"], f"/api/me: {me['username']}, сессия до {me['expiresAt']}")

        # --- срок сессии берётся из настройки и действует с нового входа ---
        hours = client.patch("/api/settings", json={"sessionHours": 3}).json()["sessionHours"]
        again = client.post("/api/login", json={"username": "vlad", "password": "vladpassword1"}).json()
        client.headers["Authorization"] = f"Bearer {again['token']}"
        expires_at = client.get("/api/me").json()["expiresAt"]
        expected = time.time() * 1000 + hours * 3_600_000
        ok(abs(expires_at - expected) < 60_000,
           f"новая сессия живёт ровно {hours} ч (настройка действует с нового входа)")

        # --- администратор: может всё в панели, но не чужие аккаунты ---
        client.headers["Authorization"] = f"Bearer {owner_token}"
        admin = client.post("/api/admins", json={"username": "mira", "password": "mirapassword1"}).json()
        ok(admin["role"] == "admin", "владелец завёл администратора: новая учётка всегда администратор")
        atoken = client.post("/api/login", json={"username": "mira", "password": "mirapassword1"}).json()["token"]
        client.headers["Authorization"] = f"Bearer {atoken}"
        ok(client.post("/api/hosts", json={"name": "mirahost", "node": "authnode", "protocol": "vless",
                                           "network": "tcp", "security": "reality", "port": 443,
                                           "address": "mira.example.net"}).status_code == 201,
           "администратор правит панель: хост создан")
        ok(client.patch("/api/settings", json={"pollInterval": 42}).status_code == 200, "администратор меняет настройки панели")
        other = client.patch(f"/api/admins/{owner['id']}", json={"status": "disabled"})
        ok(other.status_code == 403, f"администратор не трогает чужой аккаунт: {other.json()['detail']}")
        ok(client.delete(f"/api/admins/{owner['id']}").status_code == 409, "администратор не удаляет другого")
        owner_edit = client.patch(f"/api/admins/{owner['id']}", json={"password": "newownerpassword1"})
        ok(owner_edit.status_code == 403, "администратор не может сменить пароль владельца")
        own = client.patch(f"/api/admins/{admin['id']}", json={"password": "mirapassword2"})
        ok(own.status_code == 200, "администратор меняет свой пароль")
        ok(client.post("/api/login", json={"username": "mira", "password": "mirapassword2"}).status_code == 200,
           "новый пароль администратора работает")
        ok(client.post("/api/admins", json={"username": "mira2", "password": "mira2password1"}).status_code == 403,
           "администратор не заводит новых администраторов")

        # --- владелец защищён от изменений даже самим владельцем ---
        client.headers["Authorization"] = f"Bearer {owner_token}"
        disabled = client.patch(f"/api/admins/{owner['id']}", json={"status": "disabled"})
        ok(disabled.status_code == 409, f"владельца нельзя отключить: {disabled.json()['detail']}")
        ok(client.delete(f"/api/admins/{owner['id']}").status_code == 409, "владельца нельзя удалить")
        second = client.post("/api/admins", json={"username": "second", "password": "secondpassword1"}).json()
        ok(second["role"] == "admin", "новая учётка не становится владельцем: он в панели единственный")
        ok(client.patch(f"/api/admins/{owner['id']}", json={"password": "vladpassword2"}).status_code == 200,
           "владелец меняет свой пароль")
        ok(client.post("/api/login", json={"username": "vlad", "password": "vladpassword2"}).status_code == 200,
           "новый пароль владельца работает")
        mira_session = client.post("/api/login", json={"username": "mira", "password": "mirapassword2"}).json()["token"]
        client.headers["Authorization"] = f"Bearer {mira_session}"
        off_self = client.patch(f"/api/admins/{admin['id']}", json={"status": "disabled"})
        ok(off_self.status_code == 403, f"администратор не отключает самого себя: {off_self.json()['detail']}")

        # --- сессии: выход выбивает токен, отключение выбивает чужие сессии ---
        client.headers["Authorization"] = f"Bearer {owner_token}"
        ok(client.get("/api/me").status_code == 200, "перед выходом сессия жива")
        ok(client.post("/api/logout").status_code == 200, "выход из аккаунта")
        ok(client.get("/api/me").status_code == 401, "после выхода сессии нет")
        client.headers.pop("Authorization")
        ok(client.post("/api/login", json={"username": "mira", "password": "mirapassword2"}).status_code == 200,
           "чужой выход из панели чужие сессии не трогает")

        owner_token = client.post("/api/login", json={"username": "vlad", "password": "vladpassword2"}).json()["token"]
        mira_live = client.post("/api/login", json={"username": "mira", "password": "mirapassword2"}).json()["token"]
        client.headers["Authorization"] = f"Bearer {mira_live}"
        ok(client.get("/api/nodes").status_code == 200, "живая сессия администратора работает")
        client.headers["Authorization"] = f"Bearer {owner_token}"
        client.patch(f"/api/admins/{admin['id']}", json={"status": "disabled"})
        ok(client.post("/api/login", json={"username": "mira", "password": "mirapassword2"}).status_code == 409,
           "отключённый администратор не входит")
        client.headers["Authorization"] = f"Bearer {mira_live}"
        ok(client.get("/api/nodes").status_code == 401, "отключение выбило и живую сессию этого администратора")
        client.headers["Authorization"] = f"Bearer {owner_token}"
        client.patch(f"/api/admins/{admin['id']}", json={"status": "active"})
        mira_token = client.post("/api/login", json={"username": "mira", "password": "mirapassword2"}).json()["token"]
        with sqlite3.connect(os.environ["MEDUSA_DB"]) as raw:
            raw.execute("UPDATE sessions SET expires_at = 1000 WHERE admin_id = ?", (admin["id"],))
            raw.commit()
        client.headers["Authorization"] = f"Bearer {mira_token}"
        ok(client.get("/api/nodes").status_code == 401, "истёкшая сессия не действует")
        client.headers["Authorization"] = f"Bearer {owner_token}"

        # --- аппаратный ключ: выключен — и его нет ---
        client.headers["Authorization"] = f"Bearer {owner_token}"
        begin = client.post(f"/api/admins/{admin['id']}/keys/begin", json={})
        ok(begin.status_code == 409, f"пока настройка выключена, ключ не записать: {begin.json()['detail']}")
        ok(client.post("/api/fido/begin", json={}).status_code == 409, "и войти по ключу нельзя, пока выключено")
        settings = client.patch("/api/settings", json={"passkeyEnabled": True}).json()
        ok(settings["passkeyEnabled"] is True, "владелец включил вход по аппаратному ключу")

        # --- записываем ключ администратору и входим им ---
        key = FakeKey("testserver")
        options = client.post(f"/api/admins/{admin['id']}/keys/begin", json={}).json()["options"]
        ok(options["rp"]["id"] == "testserver" and options["user"]["name"] == "mira",
           f"вызов записи ключа: rp {options['rp']['id']}, для {options['user']['name']}")
        added = client.post(f"/api/admins/{admin['id']}/keys",
                            json={"response": key.register(options, origin), "nickname": "YubiKey 5"})
        ok(added.status_code == 201, f"ключ записан: {added.json()['nickname']} ({added.json()['algo']})")
        ok("public_key" not in added.json(), "открытый ключ наружу не отдаётся")
        listed = client.get(f"/api/admins/{admin['id']}/keys").json()
        ok(len(listed) == 1 and listed[0]["aaguid"], f"список ключей: {listed[0]['nickname']}, aaguid {listed[0]['aaguid']}")

        client.post("/api/logout")
        client.headers.pop("Authorization")
        login_options = client.post("/api/fido/begin", json={"username": "mira"}).json()["options"]
        offered = [c["id"] for c in login_options.get("allowCredentials", [])]
        ok(offered == [b64(key.cred_id)], f"вызов входа предлагает ключ этого администратора: {offered}")
        logged = client.post("/api/fido/login", json={"response": key.assert_for(login_options, origin)})
        ok(logged.status_code == 200, f"вход по аппаратному ключу: {logged.json()['admin']['username']}")
        client.headers["Authorization"] = f"Bearer {logged.json()['token']}"
        ok(client.get("/api/nodes").status_code == 200, "сессия после входа по ключу работает")
        me_role = client.get("/api/me").json()["role"]
        ok(me_role == "admin", f"роль из входа по ключу: {me_role}")

        # --- подделка ответа ---
        client.post("/api/logout")
        client.headers.pop("Authorization")
        options = client.post("/api/fido/begin", json={}).json()["options"]
        forged = key.assert_for(options, origin)
        forged["response"]["signature"] = b64(bytes(64))
        bad = client.post("/api/fido/login", json={"response": forged})
        ok(bad.status_code == 401, f"подписанное не тем ключом отвергнуто: {bad.json()['detail']}")

        options = client.post("/api/fido/begin", json={}).json()["options"]
        wrong_origin = key.assert_for(options, "http://medusa.evil")
        bad = client.post("/api/fido/login", json={"response": wrong_origin})
        ok(bad.status_code == 401, f"ответ с чужого адреса отвергнут: {bad.json()['detail']}")

        options = client.post("/api/fido/begin", json={}).json()["options"]
        repeat = key.assert_for(options, origin)
        ok(client.post("/api/fido/login", json={"response": repeat}).status_code == 200, "первый вход по ключу прошёл")
        again_bad = client.post("/api/fido/login", json={"response": repeat})
        ok(again_bad.status_code == 401, f"тот же ответ второй раз не принимается: {again_bad.json()['detail']}")

        stranger = FakeKey("testserver")
        options = client.post("/api/fido/begin", json={}).json()["options"]
        bad = client.post("/api/fido/login", json={"response": stranger.assert_for(options, origin)})
        ok(bad.status_code == 401, f"незаписанный ключ отвергнут: {bad.json()['detail']}")

        # --- свою ключевую учётку ведёт всякий вошедший: администратор остаётся администратором ---
        second_token = client.post("/api/login", json={"username": "second", "password": "secondpassword1"}).json()["token"]
        client.headers["Authorization"] = f"Bearer {second_token}"
        second_id_now = next(a["id"] for a in client.get("/api/admins").json() if a["username"] == "second")
        own_begin = client.post(f"/api/admins/{second_id_now}/keys/begin", json={})
        ok(own_begin.status_code == 200, "администратор получает вызов на запись своего ключа")
        second_key = FakeKey("testserver")
        own_add = client.post(f"/api/admins/{second_id_now}/keys",
                              json={"response": second_key.register(own_begin.json()["options"], origin), "nickname": "ключ второго"})
        ok(own_add.status_code == 201, f"и записывает его сам: {own_add.json()['nickname']}")
        other = next(a["id"] for a in client.get("/api/admins").json() if a["username"] == "mira")
        ok(client.post(f"/api/admins/{other}/keys/begin", json={}).status_code == 403, "чужие ключи не доступны")
        client.post("/api/logout")

        # --- ключи: кто их пишет и снимает (владелец заходит заново: выход выше его выбил) ---
        client.post("/api/logout")
        owner_token = client.post("/api/login", json={"username": "vlad", "password": "vladpassword2"}).json()["token"]
        client.headers["Authorization"] = f"Bearer {owner_token}"
        admin_row = client.get("/api/admins").json()
        second_id = next(a["id"] for a in admin_row if a["username"] == "second")
        other_key = FakeKey("testserver")
        options = client.post(f"/api/admins/{second_id}/keys/begin", json={}).json()["options"]
        added = client.post(f"/api/admins/{second_id}/keys",
                            json={"response": other_key.register(options, origin), "nickname": "ключ второго"})
        ok(added.status_code == 201, "владелец записывает ключ чужой учётке")
        atoken = client.post("/api/login", json={"username": "mira", "password": "mirapassword2"}).json()["token"]
        client.headers["Authorization"] = f"Bearer {atoken}"
        sneaky = client.post(f"/api/admins/{second_id}/keys/begin", json={})
        ok(sneaky.status_code == 403, "администратор не записывает ключ чужому аккаунту")
        key_id = next(k["id"] for k in client.get(f"/api/admins/{second_id}/keys").json())
        ok(client.delete(f"/api/admins/{second_id}/keys/{key_id}").status_code == 403,
           "администратор не снимает чужой ключ")
        client.headers["Authorization"] = f"Bearer {owner_token}"
        ok(client.delete(f"/api/admins/{second_id}/keys/{key_id}").status_code == 204, "владелец снимает ключ")

        # --- отключённый администратор теряет возможность войти и ключом ---
        client.headers["Authorization"] = f"Bearer {atoken}"
        ok(client.post("/api/fido/begin", json={"username": "mira"}).status_code == 200,
           "пока администратор активен, вызов входа по его ключу выдаётся")
        client.headers["Authorization"] = f"Bearer {owner_token}"
        client.patch(f"/api/admins/{admin['id']}", json={"status": "disabled"})
        client.headers.pop("Authorization")
        options = client.post("/api/fido/begin", json={"username": "mira"}).json()["options"]
        bad = client.post("/api/fido/login", json={"response": key.assert_for(options, origin)})
        ok(bad.status_code == 401, f"отключённому администратору и ключ не помог: {bad.json()['detail']}")

        client.headers["Authorization"] = f"Bearer {owner_token}"
        client.patch(f"/api/admins/{admin['id']}", json={"status": "active"})

        # --- свой ключ человек снимает сам: владельца для этого не нужно ---
        atoken = client.post("/api/login", json={"username": "mira", "password": "mirapassword2"}).json()["token"]
        client.headers["Authorization"] = f"Bearer {atoken}"
        mine_keys = client.get(f"/api/admins/{admin['id']}/keys").json()
        ok(len(mine_keys) == 1, f"у администратора есть его ключ: {mine_keys[0]['nickname']}")
        removed = client.delete(f"/api/admins/{admin['id']}/keys/{mine_keys[0]['id']}")
        ok(removed.status_code == 204, "свой ключ снимается без участия владельца")
        ok(len(client.get(f"/api/admins/{admin['id']}/keys").json()) == 0, "и после снятия его нет")

        options = client.post(f"/api/admins/{admin['id']}/keys/begin", json={}).json()["options"]
        client.post("/api/logout")
        client.headers["Authorization"] = f"Bearer {owner_token}"
        foreign = FakeKey("testserver")
        owner_add = client.post(f"/api/admins/{admin['id']}/keys",
                                json={"response": foreign.register(options, origin), "nickname": "ключ от владельца"})
        ok(owner_add.status_code == 201, "владелец может записать ключ администратору")
        client.headers["Authorization"] = f"Bearer {client.post('/api/login', json={'username':'mira','password':'mirapassword2'}).json()['token']}"
        ok(client.delete(f"/api/admins/{admin['id']}/keys/{owner_add.json()['id']}").status_code == 204,
           "администратор снимает и тот ключ, что записал ему владелец: это его учётка")

        ok(len(client.get("/api/admins").json()) >= 3, "учётки на месте")

    print(f"\nпровалов: {fails}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())

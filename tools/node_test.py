"""Проверка ноды: отдельный порт и API-ключ, который нода создаёт сама.

Смотрим на ноду как на чужую машину: панель придёт к ней с API-ключом. Проверяется,
что ключ один и тот же между перезапусками, что без ключа внутрь не пустят, что сам
ключ из ноды наружу не светится (наружу идёт только отпечаток) — и что версия Xray
берётся с самого ноды, а не выдумывается.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from src.core.api_keys import api_key_fingerprint  # noqa: E402
from src.node.config import NodeConfig  # noqa: E402
from src.node.main import create_app  # noqa: E402

FAILS = 0


def ok(cond: object, message: str) -> None:
    global FAILS
    print(("PASS  " if cond else "FAIL  ") + message)
    if not cond:
        FAILS += 1


def bearer(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def state_key(path: Path) -> str:
    return json.loads(path.read_text(encoding="utf-8"))["apiKey"]


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="medusa-node-test-"))
    state = tmp / "state.json"

    with TestClient(create_app(NodeConfig(state_path=state))) as client:
        health = client.get("/node/health").json()
        ok(health["status"] == "ok" and health["role"] == "medusa-node",
           f"/node/health отвечает и без ключа (агент {health['agentVersion']})")
        ok(health["fingerprint"] and "-" in health["fingerprint"], f"отпечаток API-ключа виден: {health['fingerprint']}")
        ok("sk-api" not in json.dumps(health), "в витрине ноды нет ни кусочка API-ключа")
        ok("name" not in health, "имени у ноды нет: имя даёт панели человек, ноду опознаёт ключ")

        api_key = state_key(state)
        ok(api_key.startswith("sk-api-") and len(api_key) > 30, f"нода создала свой API-ключ: {api_key[:12]}…")
        ok((state.stat().st_mode & 0o777) == 0o600, "файл состояния ноды доступен только владельцу (0600)")
        ok(api_key_fingerprint(api_key) == health["fingerprint"], "отпечаток совпадает с ключом из состояния")

        no_key = client.get("/node/identity")
        ok(no_key.status_code == 401, "без API-ключа нода представляться не станет")
        ok(no_key.headers.get("www-authenticate", "").startswith("Bearer"), "нода подсказывает способ: Bearer")
        ok(client.get("/node/status").status_code == 401, "/node/status тоже закрыт")

        wrong = client.get("/node/identity", headers=bearer("sk-api-not-the-key-0000000000000"))
        ok(wrong.status_code == 401, "чужой API-ключ нода отвергла")
        ok("не подходит" in wrong.json()["detail"], f"и объяснила почему: {wrong.json()['detail']}")

        who = client.get("/node/identity", headers=bearer(api_key))
        ok(who.status_code == 200, "со своим API-ключом нода назвалась")
        body = who.json()
        ok(body["fingerprint"] == health["fingerprint"], f"отпечаток тот же: {body['fingerprint']}")
        ok("sk-api" not in json.dumps(body), "даже по правильному ключу нода свой ключ не отдаёт")

        status = client.get("/node/status", headers=bearer(api_key))
        ok(status.status_code == 200 and status.json()["appliedRev"] == 0,
           "/node/status по ключу: ревизий ещё нет (применения конфига пока нет)")

        ok(client.get("/").json()["role"] == "medusa-node", "на корне ноды объяснение, что тут живёт")

        # перезапуск: ключ не должен смениться, иначе панель потеряет ноду
        with TestClient(create_app(NodeConfig(state_path=state))) as second:
            again = second.get("/node/health").json()
            ok(again["fingerprint"] == health["fingerprint"], "после перезапуска ноды API-ключ остался прежним")

    # API-ключ можно задать извне (секрет в оркестраторе) — тогда нода берёт его и запоминает
    fixed = "sk-api-fixed-from-orchestrator-0123456789"
    other_state = tmp / "fixed" / "state.json"
    with TestClient(create_app(NodeConfig(state_path=other_state, api_key=fixed))) as client:
        got = client.get("/node/health").json()
        ok(got["fingerprint"] == api_key_fingerprint(fixed), "MEDUSA_NODE_API_KEY перебил создаваемый ключ")
        ok(state_key(other_state) == fixed, "API-ключ извне сохранён в состоянии ноды")

    # версия Xray берётся с бинарника; если его нет — нода говорит null, а не выдумывает
    # имя не должно сталкиваться с рабочим каталогом раннера (`<каталог состояния>/xray`)
    fake = tmp / "fake-xray"
    fake.write_text('#!/bin/sh\nif [ "$1" = version ]; then echo "Xray 25.8.3 (Xray, Penetrates Everything.) abc"; exit 0; fi\nexit 1\n')
    fake.chmod(0o755)
    xray_state = tmp / "xray-state.json"
    with TestClient(create_app(NodeConfig(state_path=xray_state, xray_bin=str(fake)))) as client:
        who = client.get("/node/identity", headers=bearer(state_key(xray_state)))
        ok(who.json()["xrayVersion"] == "25.8.3", f"версия Xray снята с бинарника: {who.json()['xrayVersion']}")

    missing_state = tmp / "noxray-state.json"
    with TestClient(create_app(NodeConfig(state_path=missing_state, xray_bin=str(tmp / "nope")))) as client:
        who = client.get("/node/identity", headers=bearer(state_key(missing_state)))
        ok(who.json()["xrayVersion"] is None, "без Xray нода не придумывает версию, а говорит null")

    print()
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())

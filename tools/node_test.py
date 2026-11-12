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

    # --- трафик: нода снимает счётчики с Xray и копит их у себя ---
    import time

    from src.core.xray_config import render_node_config
    from src.node.traffic import parse_counters

    counters = tmp / "counters.json"
    counters.write_text('{"stat": []}', encoding="utf-8")
    xray2 = tmp / "fake-xray-stats"
    xray2.write_text(f"""#!/usr/bin/env bash
args=" $* "
case "$args" in
  *" version "*) echo "Xray 25.8.3 (Xray, Penetrates Everything.) abc"; exit 0 ;;
  *"-test"*)     echo "configuration accepted"; exit 0 ;;
  *" api "*)     cat {counters}; case "$args" in *" -reset "*) echo '{{"stat": []}}' > {counters} ;; esac; exit 0 ;;
esac
exec sleep 120
""", encoding="utf-8")
    xray2.chmod(0o755)

    traffic_state = tmp / "traffic" / "state.json"
    host = {"id": 1, "name": "plain", "protocol": "vless", "port": 33001, "network": "tcp",
            "security": "none", "address": "127.0.0.1", "node_address": "127.0.0.1",
            "hop_index": -1, "chain_id": None}
    users = [{"id": 7, "name": "vasya", "token": "tok-vasya", "status": "active"}]
    config = render_node_config({"id": 1, "name": "n", "address": "127.0.0.1"}, [host], users)
    key_holder: dict[str, str] = {}

    with TestClient(create_app(NodeConfig(state_path=traffic_state, xray_bin=str(xray2)))) as client:
        key = state_key(traffic_state)
        key_holder["key"] = key
        applied = client.put("/node/config", headers=bearer(key),
                             json={"revision": 1, "config": config, "certs": []}).json()
        ok(applied["ok"], f"конфиг со счётчиками принят ({applied['error']})")
        first = client.get("/node/status", headers=bearer(key)).json()
        stats_port = first["statsPort"]
        ok(stats_port and first["trafficBytes"] == 0 and first["statsError"] is None,
           f"нода подобрала порт счётчиков и честно говорит 0 до всякого трафика: {first}")
        written = json.loads((traffic_state.parent / "xray" / "config.json").read_text(encoding="utf-8"))
        api_in = next(i for i in written["inbounds"] if i["tag"] == "api")
        ok(api_in["port"] == stats_port and api_in["listen"] == "127.0.0.1",
           f"в рабочий конфиг нода вписала тот же петлюбочный порт, что и называет панели: {api_in['port']}")

        counters.write_text(json.dumps({"stat": [
            {"name": "user>>>u7>>>traffic>>>uplink", "value": 1200},
            {"name": "user>>>u7>>>traffic>>>downlink", "value": 3000},
            {"name": "user>>>hop3-1>>>traffic>>>downlink", "value": 400},
            {"name": "user>>>u7>>>traffic>>>uplink"},        # после -reset Xray отдаёт имена без значения
        ]}), encoding="utf-8")
        read = client.get("/node/status", headers=bearer(key)).json()
        ok(read["trafficBytes"] == 4600 and read["statsError"] is None,
           f"счётчики сняты и сложены (uplink+downlink, пустое значение = 0): {read['trafficBytes']}")
        ok({(item["email"], item["bytes"]) for item in read["userTraffic"]}
           == {("u7", 4200), ("hop3-1", 400)},
           f"метки разложены по людям и переходам: {read['userTraffic']}")

        counters.write_text(json.dumps({"stat": [
            {"name": "user>>>u7>>>traffic>>>uplink", "value": 800}]}), encoding="utf-8")
        again = client.get("/node/status", headers=bearer(key)).json()
        ok(again["trafficBytes"] == 5400
           and next(i for i in again["userTraffic"] if i["email"] == "u7")["bytes"] == 5000,
           f"новые байты прибавляются к накопленным нодой, а не заменяют их: "
           f"{again['trafficBytes']} / {again['userTraffic']}")

    # перезапуск ноды: Xray поднялся с прежним конфигом, а накопленное взялось из состояния
    with TestClient(create_app(NodeConfig(state_path=traffic_state, xray_bin=str(xray2)))) as second:
        key = state_key(traffic_state)
        status = second.get("/node/status", headers=bearer(key)).json()
        ok(status["trafficBytes"] == 5400 and status["statsPort"] == stats_port,
           f"после перезапуска ноды её трафик и порт счётчики на месте: {status['trafficBytes']} на {status['statsPort']}")
        ok(json.loads(traffic_state.read_text(encoding="utf-8"))["userTraffic"]["u7"] == 5000,
           "накопленные метки лежат в файле состояния ноды (0600), а не в памяти процесса")

    # Xray без сервиса счётчиков: цифры не исчезают, но появляется честная причина
    broken = tmp / "broken" / "state.json"
    xray_broken = tmp / "fake-xray-broken"
    xray_broken.write_text("""#!/bin/sh
if [ "$1" = version ]; then echo "Xray 25.8.3 x"; exit 0; fi
if [ "$1" = "-test" ]; then echo ok; exit 0; fi
if [ "$1" = api ]; then echo "failed to dial 127.0.0.1:39113" >&2; exit 1; fi
exec sleep 60
""", encoding="utf-8")
    xray_broken.chmod(0o755)
    with TestClient(create_app(NodeConfig(state_path=broken, xray_bin=str(xray_broken)))) as client:
        key = state_key(broken)
        client.put("/node/config", headers=bearer(key),
                   json={"revision": 1, "config": config, "certs": []})
        status = client.get("/node/status", headers=bearer(key)).json()
        ok(status["trafficBytes"] == 0 and "не ответили" in (status["statsError"] or ""),
           f"если Xray не дал счётчики, нода не молчит: {status['statsError']}")

    silent = tmp / "noxray-traffic" / "state.json"
    with TestClient(create_app(NodeConfig(state_path=silent, xray_bin=str(tmp / "nope")))) as client:
        status = client.get("/node/status", headers=bearer(state_key(silent))).json()
        ok(status["trafficBytes"] == 0 and "нет бинарника xray" in (status["statsError"] or ""),
           f"без Xray счётчиков нет, и панель узнаёт об этом: {status['statsError']}")

    ok(parse_counters({"stat": [{"name": "user>>>u1>>>traffic>>>uplink", "value": 5},
                                {"name": "inbound>>>x>>>traffic>>>uplink", "value": 9},
                                {"name": "user>>>u1>>>online", "value": 1},
                                {"name": "мусор"}]}) == {"u1": 5},
       "из ответа Xray берутся только счётчики трафика пользователей: чужие имена и мусор отбрасываются")

    # Xray умер уже после запуска: нода обязана пересказать причину из его же лога.
    # Именно так выглядит занятой порт на машине, где живут две ноды, — и человеку нужно
    # видеть «address already in use», а не «детали в логе на ноде».
    dying = tmp / "dying" / "state.json"
    xray_dies = tmp / "fake-xray-dies"
    xray_dies.write_text("""#!/usr/bin/env bash
if [ "$1" = version ]; then echo "Xray 25.8.3 x"; exit 0; fi
if [ "$1" = "-test" ]; then echo "configuration accepted"; exit 0; fi
echo 'Failed to start: app/proxyman/inbound: failed to listen TCP on 443 > listen tcp 0.0.0.0:443: bind: address already in use' >&2
exit 255
""", encoding="utf-8")
    xray_dies.chmod(0o755)
    with TestClient(create_app(NodeConfig(state_path=dying, xray_bin=str(xray_dies)))) as client:
        key = state_key(dying)
        applied = client.put("/node/config", headers=bearer(key),
                             json={"revision": 1, "config": config, "certs": []}).json()
        ok(applied["ok"], f"конфиг прошёл проверку и процесс запущен ({applied['error']})")
        time.sleep(1.2)
        dead = client.get("/node/status", headers=bearer(key)).json()
        reason = dead["lastError"] or ""
        ok("завершился с кодом 255" in reason and "address already in use" in reason,
           f"нода пересказала причину смерти Xray из его же лога: {reason}")
        again = client.get("/node/status", headers=bearer(key)).json()
        ok("address already in use" in (again["lastError"] or ""),
           "причина не исчезает после первого же ответа: нода не забывает, что её Xray мёртв")

    print()
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())

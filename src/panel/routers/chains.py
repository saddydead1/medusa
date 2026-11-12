"""Цепочки: пользователь видит её как один хост, вход — в первую ноду.

Цепочка живёт в таблице `hosts` своими строками — по одной на каждый хоп (`hop_index`
0..n-1, у обычного хоста -1). Вход цепочки (хоп 0) человек видит в списке хостов как хост
с именем цепочки: к нему он подключается, ему же отдаётся ссылка подписки. Промежуточные
хопа — те же строки hosts, но наружу они не показываются: это внутренняя связь нод, и
правятся они только вместе с цепочкой.

Такой порядок даёт цепочке всё, что есть у обычного хоста: занятый порт учитывается наравне
(UNIQUE (node_id, port)), ключи reality выпускаются при создании, а tls-хосту цепочки панель
выпускает сертификат сама (src/panel/host_keys.py) — иначе соседняя нода не смогла бы ему
доверять.

Логика инбаундов и переходов — в `src/core/xray_config.py` (hop_clients, hop_outbound,
routing по inboundTag); здесь только смысл записи и её границы.
"""
from __future__ import annotations

import json
import sqlite3

from fastapi import APIRouter, Depends

from src.core.xray_config import security_issue, unsupported_protocol, UNSUPPORTED_HINT
from src.core.xray_config import (is_ip, reality_client_sni, security_issue, unsupported_protocol,
                                 UNSUPPORTED_HINT)
from src.panel import config_push
from src.panel import ports
from src.panel.chain_hops import insert_hop
from src.panel.db import get_conn, now_ms
from src.panel.deps import bad_request, conflict, fetch_one, writer
from src.panel.field_rules import fields_issue, meaningful
from src.panel.schemas import ChainCreate

router = APIRouter(prefix="/api/chains", tags=["chains"])


def check_hop(hop) -> None:
    """Хоп цепочки обязан быть тем же набором, что и хост: инбаунд цепочки — это
    её первый хоп, а из него собираются и конфиг, и ссылка подписки.

    Правила «поле чужой защиты» общие с хостами (field_rules): transition цепочки обязан
    собираться из тех же деталей, что и обычный хост, иначе человек получил бы окно,
    которое показывает одно, а на ноде работает другое.
    """
    if unsupported_protocol(hop.protocol):
        raise bad_request(UNSUPPORTED_HINT)
    issue = security_issue(hop.protocol, hop.security)
    if issue:
        raise bad_request(issue)
    if hop.security == "reality" and hop.network == "ws":
        raise bad_request("reality не работает поверх ws")
    if hop.protocol == "ss" and hop.network != "tcp":
        raise bad_request("shadowsocks тут только через tcp")
    issue = fields_issue(hop.security, hop.network, meaningful(hop), hop=True)
    if issue:
        raise bad_request(issue)


def hop_settings(hop) -> dict:
    """Детали хопа, которые переезжают в его же ряд hosts.

    Пустое значение — «разумное по умолчанию», его пишет рендер; здесь сохраняем только
    названное человеком, иначе правка адреса ноды не сможет подставить новое по умолчанию.
    """
    return {"dest": (hop.dest or "").strip(), "server_names": (hop.serverNames or "").strip(),
            "sni": (hop.sni or "").strip(), "fp": (hop.fp or "").strip(),
            "path": (hop.path or "").strip(), "host_header": (hop.hostHeader or "").strip(),
            "service_name": (hop.serviceName or "").strip(),
            "grpc_authority": (hop.grpcAuthority or "").strip(),
            "reject_unknown_sni": 1 if hop.rejectUnknownSni else 0}


def hop_settings_of(hop: dict) -> dict:
    """Детали хопа наружу: их читает окно правки цепочки, чтобы предзаполнить поля.

    Пустые строки — «не названо, действует разумное по умолчанию». Отпечаток при этом
    возвращается `null`, а не пустой строкой: список допустимых отпечатков закрыт (Literal),
    и `fp: ""` эхо GET -> PATCH ловил бы 422 вместо того, чтобы означать «не выбран».
    """
    return {"dest": hop.get("dest") or "", "serverNames": hop.get("server_names") or "",
            "sni": hop.get("sni") or "", "fp": hop.get("fp") or None,
            "path": hop.get("path") or "", "hostHeader": hop.get("host_header") or "",
            "serviceName": hop.get("service_name") or "",
            "grpcAuthority": hop.get("grpc_authority") or "",
            "rejectUnknownSni": bool(hop.get("reject_unknown_sni"))}


def hops_of(conn: sqlite3.Connection, raw: str) -> list[dict]:
    """Хопы наружу именами нод: если ноду удалили — остаётся имя из снимка."""
    out = []
    for hop in json.loads(raw):
        node = conn.execute("SELECT name FROM nodes WHERE id = ?", (hop["node_id"],)).fetchone()
        out.append({
            "node": node["name"] if node else hop.get("node", f"#{hop['node_id']}"),
            "protocol": hop["protocol"],
            "network": hop["network"],
            "security": hop["security"],
            "port": hop["port"],
            "address": hop.get("address") or "",
            **hop_settings_of(hop),
        })
    return out


def as_dict(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    return {"id": row["id"], "name": row["name"], "hops": hops_of(conn, row["hops"])}


def hop_issue(conn: sqlite3.Connection, hop: dict, skip_chain: int | None) -> str | None:
    """Чем занят порт этого хопа.

    Смотрим не «на ноде», а на адресе ноды: соседняя нода с тем же адресом — это та же
    машина, и два её слушателя на одном порту уронят Xray целиком (вместе с его здоровыми
    хостами). API-порт ноды участвует в проверке: он слушает там же.
    """
    return ports.host_port_conflict(conn, hop["node_id"], hop["port"], skip_chain=skip_chain)


def resolve_hops(conn: sqlite3.Connection, body: ChainCreate, skip_chain: int | None) -> tuple[list[dict], list[int]]:
    """Хопы запроса -> хопы базы: ноды по именам, порты проверены, порядок сохранён."""
    nodes = {}
    for hop in body.hops:
        check_hop(hop)
        row = conn.execute("SELECT id, name, address FROM nodes WHERE name = ?", (hop.node,)).fetchone()
        if row is None:
            raise bad_request(f"ноды «{hop.node}» нет")
        nodes[hop.node] = row

    for a, b in zip(body.hops, body.hops[1:], strict=False):
        if a.node == b.node:
            raise bad_request("соседние хопы должны быть на разных нодах")

    resolved = [{"node_id": nodes[h.node]["id"], "node": h.node, "protocol": h.protocol,
                 "network": h.network, "security": h.security, "port": h.port,
                 "address": ports.norm(h.address), **hop_settings(h)} for h in body.hops]

    # reality hop цепочки прячется за доменом: соседняя нода обязана назвать в SNI тот же
    # сайт, за который притворяется нода-приёмник, а IP в SNI клиент подставить не умеет
    for hop in resolved:
        if hop["security"] == "reality":
            node_address = conn.execute("SELECT address FROM nodes WHERE id = ?",
                                        (hop["node_id"],)).fetchone()["address"]
            target = {"server_names": hop["server_names"], "dest": hop["dest"], "sni": hop["sni"],
                      "address": hop["address"]}
            if not reality_client_sni(target, hop["address"] or node_address):
                raise bad_request(f"reality hop «{hop['node']}»: маскированный адрес (или список "
                                  "принимаемых SNI) обязан быть доменом, а не IP")

    # хопы одной цепочки могут попасть на одну машину (две ноды с одним адресом), и тогда
    # их порты обязаны различаться так же, как порты обычных хостов
    on_machine: dict[tuple[str, int], str] = {}
    for hop in resolved:
        issue = hop_issue(conn, hop, skip_chain=skip_chain)
        if issue:
            raise conflict(issue)
        key = (ports.node_address(conn, hop["node_id"]), hop["port"])
        if key in on_machine:
            raise conflict(f"порт {hop['port']} на {key[0]} уже занят хопом «{on_machine[key]}» "
                           "этой же цепочки")
        on_machine[key] = hop["node"]
    return resolved, [h["node_id"] for h in resolved]


@router.get("")
def list_chains(conn: sqlite3.Connection = Depends(get_conn)) -> list[dict]:
    return [as_dict(conn, r) for r in conn.execute("SELECT * FROM chains ORDER BY name").fetchall()]


@router.post("", status_code=201)
def create_chain(
    body: ChainCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    hops, node_ids = resolve_hops(conn, body, skip_chain=None)
    try:
        cur = conn.execute("INSERT INTO chains (name, hops, created_at) VALUES (?,?,?)",
                           (body.name, json.dumps(hops, ensure_ascii=False), now_ms()))
        chain_id = cur.lastrowid
        for index, hop in enumerate(hops):
            insert_hop(conn, chain_id, body.name, index, hop, now_ms())
    except sqlite3.IntegrityError:
        conn.rollback()
        raise conflict(f"цепочка «{body.name}» уже есть (или её порты уже заняты)")
    conn.commit()
    config_push.mark_dirty(conn, node_ids)
    config_push.schedule_push(node_ids)
    return as_dict(conn, fetch_one(conn, "SELECT * FROM chains WHERE id = ?", (chain_id,)))


@router.patch("/{chain_id}")
def patch_chain(
    chain_id: int,
    body: ChainCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    """Цепочка правится целиком, вместе со своими хопами.

    Хост цепочки нельзя править отдельно (`409` в hosts), поэтому здесь принимаются и
    новые хопа: строки хостов пересоздаются вместе с описанием цепочки. Ключи при этом
    выпускаются заново — подпись цепочки (ссылка подписки на её вход) меняется вслед за
    конфигами, расхождений «человек видит одно, нода работает по другому» не остаётся.
    """
    fetch_one(conn, "SELECT id FROM chains WHERE id = ?", (chain_id,))
    before = [row["node_id"] for row in conn.execute(
        "SELECT node_id FROM hosts WHERE chain_id = ?", (chain_id,)).fetchall()]
    hops, node_ids = resolve_hops(conn, body, skip_chain=chain_id)
    try:
        conn.execute("DELETE FROM hosts WHERE chain_id = ?", (chain_id,))
        conn.execute("UPDATE chains SET name = ?, hops = ? WHERE id = ?",
                     (body.name, json.dumps(hops, ensure_ascii=False), chain_id))
        for index, hop in enumerate(hops):
            insert_hop(conn, chain_id, body.name, index, hop, now_ms())
    except sqlite3.IntegrityError:
        conn.rollback()
        raise conflict(f"цепочка «{body.name}» уже есть (или её порты уже заняты)")
    conn.commit()
    touched = sorted(set(before) | set(node_ids))
    config_push.mark_dirty(conn, touched)
    config_push.schedule_push(touched)
    return as_dict(conn, fetch_one(conn, "SELECT * FROM chains WHERE id = ?", (chain_id,)))


@router.delete("/{chain_id}", status_code=204)
def delete_chain(
    chain_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> None:
    fetch_one(conn, "SELECT id FROM chains WHERE id = ?", (chain_id,))
    node_ids = [row["node_id"] for row in conn.execute(
        "SELECT node_id FROM hosts WHERE chain_id = ?", (chain_id,)).fetchall()]
    conn.execute("DELETE FROM chains WHERE id = ?", (chain_id,))   # hosts.chain_id ON DELETE CASCADE
    conn.commit()
    config_push.mark_dirty(conn, node_ids)
    config_push.schedule_push(node_ids)

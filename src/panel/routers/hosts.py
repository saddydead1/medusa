"""Хосты — то, что пользователь видит в подписке.

Хост цепочки здесь не выдумывается фронтендом: он создаётся вместе с цепочкой
и живёт в той же таблице, ссылаясь на неё (цепочка -> хост через chain_id).
Хост цепочки нельзя ни удалить, ни изменить отдельно — только вместе с цепочкой.

Хост можно править (PATCH): имя, нода, адрес, порт, протокол, транспорт, защита и
её поля. Правка живая: меняем состав — помечаем ноду грязной и тут же отправляем
ей новый конфиг.
"""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends

from src.core.xray_config import is_ip, reality_client_sni, security_issue, unsupported_protocol, UNSUPPORTED_HINT
from src.panel import config_push, ports
from src.panel.db import get_conn, now_ms
from src.panel.host_keys import new_reality_keys
from src.panel.deps import bad_request, conflict, fetch_one, node_by_name, writer
from src.panel.schemas import HostCreate, HostPatch

router = APIRouter(prefix="/api/hosts", tags=["hosts"])

SELECT = """
SELECT h.*, n.name AS node_name, c.name AS chain_name
FROM hosts h
JOIN nodes n ON n.id = h.node_id
LEFT JOIN chains c ON c.id = h.chain_id
"""
# хостом цепочки человек видит только её вход: промежуточные хопа — внутренняя связь нод,
# их адрес, порт и ключи наружу показывать нечего
VISIBLE = " WHERE h.chain_id IS NULL OR h.hop_index = 0"
ORDER = " ORDER BY (h.chain_id IS NOT NULL), h.name"


def as_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "node": row["node_name"],
        "address": row["address"],
        "protocol": row["protocol"],
        "port": row["port"],
        "network": row["network"],
        "security": row["security"],
        "chain": row["chain_id"],
        "chain_name": row["chain_name"],
        # публичный ключ reality не секрет: именно он нужен клиенту в ссылке;
        # приватного наружу никогда не отдаём
        "publicKey": row["public_key"],
        # настройки защиты: панель их отдаёт как есть, пустое — «значения по умолчанию знает рендер»
        "dest": row["dest"],
        "fp": row["fp"],
        "rejectUnknownSni": bool(row["reject_unknown_sni"]),
        "sni": row["sni"],
        "certFile": row["cert_file"],
        "keyFile": row["key_file"],
        "serverNames": row["server_names"],
        # транспортные детали
        "path": row["path"],
        "hostHeader": row["host_header"],
        "serviceName": row["service_name"],
        "grpcAuthority": row["grpc_authority"],
    }


def clean(value: object) -> str:
    return str(value or "").strip()


def check_combination(protocol: str, network: str, security: str, address: str, node_address: str,
                      server_names: str = "", dest: str = "") -> None:
    """Смысл combos один на create и patch: набор «reality поверх ws» или reality на IP
    одинаково бессмысленен при создании и при правке.

    Протокол, которого панель не умеет ни в конфиге, ни в ссылке (hy2), отвергается здесь
    же: панель не заводит хост, о котором подписчик никогда не узнает.
    """
    if unsupported_protocol(protocol):
        raise bad_request(UNSUPPORTED_HINT)
    issue = security_issue(protocol, security)
    if issue:
        raise bad_request(issue)
    if security == "reality" and network == "ws":
        raise bad_request("reality не работает поверх ws")
    if protocol == "ss" and network != "tcp":
        raise bad_request("shadowsocks тут только через tcp")
    if security == "reality" and not reality_client_sni({"server_names": server_names, "dest": dest},
                                                        address or node_address):
        # адрес самой ноды может быть и IP: клиент в reality называет не его, а сайт-
        # маску; вот она обязана быть доменом — IP в SNI клиент подставить не умеет
        raise bad_request("reality прячется за доменом: маскированный адрес (или список "
                          "принимаемых SNI) обязан быть доменом, а не IP")


def check_fields(body: HostCreate | HostPatch, security: str, network: str) -> None:
    """Поле чужой защиты или чужого транспорта — не «лишнее», а путаница:
    панель отвергает сразу, чтобы потом не удивляться молча игнорируемому полю."""
    if body.fp is not None and security == "none":
        raise bad_request("отпечаток клиента работает только при шифровании (tls или reality)")
    if body.dest is not None and security != "reality":
        raise bad_request("маскированный адрес — настройка reality, а не другой защиты")
    if body.serverNames is not None and security != "reality":
        raise bad_request("список принимаемых sni — настройка reality, а не другой защиты")
    tls_fields = (body.sni, body.certFile, body.keyFile)
    if any(v is not None for v in tls_fields) and security != "tls":
        raise bad_request("sni и файлы сертификатов — настройки tls, а не другой защиты")
    if body.rejectUnknownSni is not None and security != "tls":
        raise bad_request("отношение к чужому SNI — настройка tls, а не другой защиты")
    if (body.path is not None or body.hostHeader is not None) and network != "ws":
        raise bad_request("путь и Host-заголовок — настройки websocket, а не другого транспорта")
    if (body.serviceName is not None or body.grpcAuthority is not None) and network != "grpc":
        raise bad_request("имя сервиса и authority — настройки gRPC, а не другого транспорта")


def check_cert_pair(cert_file: str, key_file: str) -> None:
    """Свой сертификат — это всегда пара файлов; половина пары бесполезна,
    а случайное расширение скорее опечатка, чем замысел."""
    if bool(cert_file) != bool(key_file):
        raise bad_request("свой сертификат — это всегда пара: файл сертификата и файл ключа")
    if not cert_file:
        return
    if not cert_file.endswith((".crt", ".pem", ".cer")):
        raise bad_request("файл сертификата должен называться .crt, .pem или .cer")
    if not key_file.endswith((".key", ".pem")):
        raise bad_request("файл ключа должен называться .key или .pem")


def check_port(conn: sqlite3.Connection, node_id: int, port: int, own_id: int | None = None) -> None:
    """Порт хоста проверяется по машине ноды, а не по одной ноде.

    Две ноды с одним адресом — одна машина: её слушатели не должны наступать друг на друга,
    иначе Xray падает целиком (`bind: address already in use`) и вместе с ним все хосты ноды.
    API-порт ноды — такой же слушатель на том же адресе.
    """
    issue = ports.host_port_conflict(conn, node_id, port, skip_host=own_id)
    if issue:
        raise conflict(issue)


@router.get("")
def list_hosts(conn: sqlite3.Connection = Depends(get_conn)) -> list[dict]:
    return [as_dict(r) for r in conn.execute(SELECT + VISIBLE + ORDER).fetchall()]


@router.post("", status_code=201)
def create_host(
    body: HostCreate,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    node = node_by_name(conn, body.node)
    address = clean(body.address)
    check_combination(body.protocol, body.network, body.security, address, node["address"],
                      clean(body.serverNames), clean(body.dest))
    check_fields(body, body.security, body.network)
    check_cert_pair(clean(body.certFile), clean(body.keyFile))
    check_port(conn, node["id"], body.port)
    private_key = public_key = ""
    if body.security == "reality":
        private_key, public_key = new_reality_keys()
    try:
        conn.execute(
            """INSERT INTO hosts (name, node_id, protocol, port, network, security, chain_id,
                                  address, private_key, public_key, dest, fp, alpn, reject_unknown_sni,
                                  path, host_header, service_name, grpc_authority,
                                  sni, cert_file, key_file, server_names, created_at)
               VALUES (?,?,?,?,?,?,NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (body.name, node["id"], body.protocol, body.port, body.network, body.security,
             address, private_key, public_key,
             clean(body.dest), body.fp or "", "",
             1 if body.rejectUnknownSni else 0,
             clean(body.path), clean(body.hostHeader), clean(body.serviceName), clean(body.grpcAuthority),
             clean(body.sni), clean(body.certFile), clean(body.keyFile),
             clean(body.serverNames), now_ms()),
        )
    except sqlite3.IntegrityError:
        raise conflict(f"порт {body.port} на ноде {body.node} уже занят")
    conn.commit()
    new_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    config_push.mark_dirty(conn, [node["id"]])
    config_push.schedule_push([node["id"]])
    return as_dict(fetch_one(conn, SELECT + " WHERE h.id = ?", (new_id,)))


@router.patch("/{host_id}")
def patch_host(
    host_id: int,
    body: HostPatch,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> dict:
    row = fetch_one(conn, "SELECT * FROM hosts WHERE id = ?", (host_id,))
    if row["chain_id"] is not None:
        raise conflict("хост цепочки меняется вместе с цепочкой")

    node_id = row["node_id"]
    if body.node is not None:
        node_id = node_by_name(conn, body.node)["id"]
    node = fetch_one(conn, "SELECT name, address FROM nodes WHERE id = ?", (node_id,))

    merged = {
        "name": body.name if body.name is not None else row["name"],
        "protocol": body.protocol or row["protocol"],
        "port": body.port if body.port is not None else row["port"],
        "network": body.network or row["network"],
        "security": body.security or row["security"],
        # пустая строка — сброс к разумному по умолчанию, None — оставить как было
        "address": clean(body.address) if body.address is not None else row["address"],
        "dest": clean(body.dest) if body.dest is not None else row["dest"],
        "fp": body.fp if body.fp is not None else row["fp"],
        "reject_unknown_sni": (1 if body.rejectUnknownSni else 0)
                              if body.rejectUnknownSni is not None else row["reject_unknown_sni"],
        "path": clean(body.path) if body.path is not None else row["path"],
        "host_header": clean(body.hostHeader) if body.hostHeader is not None else row["host_header"],
        "service_name": clean(body.serviceName) if body.serviceName is not None else row["service_name"],
        "grpc_authority": clean(body.grpcAuthority) if body.grpcAuthority is not None else row["grpc_authority"],
        "sni": clean(body.sni) if body.sni is not None else row["sni"],
        "cert_file": clean(body.certFile) if body.certFile is not None else row["cert_file"],
        "key_file": clean(body.keyFile) if body.keyFile is not None else row["key_file"],
        "server_names": clean(body.serverNames) if body.serverNames is not None else row["server_names"],
    }

    check_combination(merged["protocol"], merged["network"], merged["security"], merged["address"],
                      node["address"], merged["server_names"], merged["dest"])
    check_fields(body, merged["security"], merged["network"])
    check_cert_pair(merged["cert_file"], merged["key_file"])
    check_port(conn, node_id, merged["port"], own_id=host_id)

    private_key, public_key = row["private_key"], row["public_key"]
    if merged["security"] == "reality" and not private_key:
        private_key, public_key = new_reality_keys()   # хост только сейчас стал reality

    conn.execute(
        """UPDATE hosts SET name = ?, node_id = ?, protocol = ?, port = ?, network = ?, security = ?,
                           address = ?, private_key = ?, public_key = ?, dest = ?, fp = ?, alpn = ?,
                           reject_unknown_sni = ?, path = ?, host_header = ?, service_name = ?,
                           grpc_authority = ?, sni = ?, cert_file = ?, key_file = ?, server_names = ?
           WHERE id = ?""",
        (merged["name"], node_id, merged["protocol"], merged["port"], merged["network"], merged["security"],
         merged["address"], private_key, public_key, merged["dest"], merged["fp"], row["alpn"],
         merged["reject_unknown_sni"], merged["path"], merged["host_header"], merged["service_name"],
         merged["grpc_authority"], merged["sni"], merged["cert_file"], merged["key_file"],
         merged["server_names"], host_id),
    )
    conn.commit()

    touched = {row["node_id"], node_id}      # если хост переехал на другую ноду — грязными станут обе
    config_push.mark_dirty(conn, list(touched))
    config_push.schedule_push(list(touched))
    return as_dict(fetch_one(conn, SELECT + " WHERE h.id = ?", (host_id,)))


@router.delete("/{host_id}", status_code=204)
def delete_host(
    host_id: int,
    conn: sqlite3.Connection = Depends(get_conn),
    _: sqlite3.Row | None = Depends(writer),
) -> None:
    row = fetch_one(conn, "SELECT chain_id, node_id FROM hosts WHERE id = ?", (host_id,))
    if row["chain_id"] is not None:
        raise conflict("хост цепочки удаляется вместе с цепочкой")
    conn.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
    conn.commit()
    config_push.mark_dirty(conn, [row["node_id"]])
    config_push.schedule_push([row["node_id"]])

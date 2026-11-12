"""Строка хопа цепочки в таблице hosts — общая для создания цепочки и для миграции прежних.

Цепочка заводит свой ряд hosts на каждый хоп (`hop_index` 0 — вход, 1.. — промежуточные),
поэтому хоп получает всё, что есть у обычного хоста: занятый порт (`UNIQUE (node_id, port)`),
ключи reality, а tls-хосту цепочки — сертификат, выпущенный панелью (её отпечаток потом
закрепляется за соседней нодой: Xray 26 самоподписанный сертификат «на веру» не принимает).

Здесь нет ни FastAPI, ни зависимостей: функции принимает соединение и готовое описание хопа,
чтобы ими пользовались и эндпоинты (`routers/chains.py`), и миграция схемы (`db.py`).
"""
from __future__ import annotations

import sqlite3

from src.panel.host_keys import new_hop_certificate, new_reality_keys

# hop_index входа: человек видит этот ряд хостом цепочки, остальные — нет
ENTRY_HOP = 0


def hop_name(chain_name: str, index: int) -> str:
    """Имя хопа: вход носит имя цепочки (его видит человек), дальше — «цепочка hop N».

    Имя хоста становится тегом инбаунда в конфиге Xray, поэтому по нему в логе ноды видно,
    какой переход какой цепочки обслужил трафик.
    """
    return chain_name if index == ENTRY_HOP else f"{chain_name} hop {index + 1}"


def settings(hop: dict, key: str) -> str:
    """Деталь хопа строкой: пустое значит «разумное по умолчанию», его пишет рендер."""
    value = hop.get(key)
    return value.strip() if isinstance(value, str) else ""


def hop_connect_address(hop: dict, node_address: str) -> str:
    """Куда придёт соседняя нода: свой адрес хопа, иначе адрес его ноды.

    Это то же правило, что и для подписчика (`connect_address` в рендере конфига): хост может
    жить на другом имени той же машины (домен наружу, отдельный VLAN), и соседняя нода обязана
    идти туда же, куда панель отправляет ссылку человеку.
    """
    return (hop.get("address") or "").strip() or (node_address or "").strip()


def hop_server_name(hop: dict, node_address: str) -> str:
    """Имя, которое соседняя нода назовёт в SNI этого хопа, и которое обязано быть в
    сертификате хопа: названный человеком sni, иначе адрес хопа (а если его не назвал —
    адрес ноды).

    Рендер (`hop_outbound`) ставит в tlsSettings.serverName именно sni хопа, поэтому
    сертификат нужно выпускать под него же: иначе сосед придёт с одним именем, а Xray
    увидит другое и развернёт рукопожатие.
    """
    return (hop.get("sni") or "").strip() or hop_connect_address(hop, node_address)


def hop_keys(conn: sqlite3.Connection, hop: dict, node_address: str) -> dict[str, str]:
    """Ключи защиты хопа: reality — пара x25519, tls — сертификат от панели.

    Сертификат выпускается на имя, по которому к этому hopу придут (свой sni хопа, иначе его
    адрес, иначе адрес его ноды): клиентом для соседней ноды является она сама, а имя в
    сертификате обязано совпасть с тем именем, которое она назовёт в SNI.
    """
    keys = {"private_key": "", "public_key": "", "cert_pem": "", "key_pem": "", "cert_sha256": ""}
    if hop["security"] == "reality":
        keys["private_key"], keys["public_key"] = new_reality_keys()
    elif hop["security"] == "tls":
        keys["cert_pem"], keys["key_pem"], keys["cert_sha256"] = new_hop_certificate(
            hop_server_name(hop, node_address))
    return keys


def reissue_hop_certs(conn: sqlite3.Connection, node_id: int) -> list[int]:
    """Перевыпустить сертификаты tls-хопов этой ноды.

    Нужно, когда нода сменила адрес: пустой адрес хопа означает «адрес ноды», а сертификат
    хопа выпускается на имя, по которому к нему придут. Оставить прежний сертификат — значит
    получить соседнюю ноду, которая стучится на новый адрес с именем старого (Xray 26 на такое
    смотрит строго). Возвращает id цепочек, чьи конфигы пришлось тронуть.
    """
    from src.panel.host_keys import new_hop_certificate

    address = conn.execute("SELECT address FROM nodes WHERE id = ?", (node_id,)).fetchone()["address"]
    rows = conn.execute("""SELECT id, address, sni, chain_id FROM hosts
                           WHERE node_id = ? AND chain_id IS NOT NULL AND security = 'tls'""",
                        (node_id,)).fetchall()
    chains = set()
    for row in rows:
        cert, key, sha = new_hop_certificate(hop_server_name(dict(row), address))
        conn.execute("UPDATE hosts SET cert_pem = ?, key_pem = ?, cert_sha256 = ? WHERE id = ?",
                     (cert, key, sha, row["id"]))
        chains.add(int(row["chain_id"]))
    return sorted(chains)


def insert_hop(conn: sqlite3.Connection, chain_id: int, chain_name: str, index: int,
               hop: dict, created_at: int) -> int:
    """Завести ряд хопа цепочки. `hop` — описание из цепочки: node_id, protocol, network,
    security, port, его адрес и детали защиты/транспорта. Возвращает id строки hosts.

    Адрес хопа пишется в ряд hosts как у обычного хоста: он попадает и в конфиг соседней ноды
    (её outbound), и в ссылку подписки, если это вход цепочки. Иначе «хост есть, адреса у
    него нет» — и цепочка едет по адресу ноды даже тогда, когда человек назвал другой.

    Детали (`path`, `host_header`, `service_name`, `grpc_authority`, `dest`, `server_names`,
    `sni`, `fp`, `reject_unknown_sni`) сохраняются теми же колонками, что и у обычного хоста:
    рендер читает один и тот же ряд и для инбаунда хопа, и для перехода соседней ноды, поэтому
    путь или маскированный адрес цепочки работают на обеих сторонах перехода сами.
    Своих файлов сертификатов у хопа нет: их выпустила панель, чтобы знать отпечаток.
    """
    node = conn.execute("SELECT id, address FROM nodes WHERE id = ?", (hop["node_id"],)).fetchone()
    if node is None:
        raise LookupError(f"ноды {hop['node_id']} нет — хоп цепочки завести некуда")
    keys = hop_keys(conn, hop, node["address"])
    conn.execute(
        """INSERT INTO hosts (name, node_id, protocol, port, network, security, chain_id, hop_index,
                              address, private_key, public_key, dest, fp, sni, server_names,
                              cert_file, key_file, cert_pem, key_pem, cert_sha256,
                              path, host_header, service_name, grpc_authority, reject_unknown_sni,
                              created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (hop_name(chain_name, index), node["id"], hop["protocol"], hop["port"], hop["network"],
         # свой адрес хопа пишется только если его назвал человек: пусто остаётся пустым,
         # и рендер каждый раз берёт актуальный адрес ноды (нода может переехать)
         hop["security"], chain_id, index, (hop.get("address") or "").strip(),
         keys["private_key"], keys["public_key"], settings(hop, "dest"), settings(hop, "fp"),
         settings(hop, "sni"), settings(hop, "server_names"),
         "", "", keys["cert_pem"], keys["key_pem"], keys["cert_sha256"],
         settings(hop, "path"), settings(hop, "host_header"),
         settings(hop, "service_name"), settings(hop, "grpc_authority"),
         1 if hop.get("reject_unknown_sni") else 0, created_at),
    )
    return conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]

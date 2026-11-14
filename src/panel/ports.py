"""Занятость портов на машине ноды.

Порт хоста нельзя проверять «внутри одной ноды»: две ноды с одним адресом живут на одной
машине (или выходят наружу под одним адресом), и там их слушатели сталкиваются. Проверка
поэтому смотрит на тройку (адрес ноды, порт, класс слушателя).

Что реально делает Xray 26 с двумя слушателями на одном номере (проверено живым
`xray` 26.11.9 на этой машине):

* два TCP-слушателя в одном процессе поднимаются оба — Xray ставит SO_REUSEPORT, и ядро
  **раздаёт соединения между ними вперемешку**: 12 запросов на один порт ушли пополовине
  в два разных инбаунда. Ни один не падает, просто половина подписчиков попадает не в свой
  хост (у них другие uuid/пароли — рукопожатие не проходит);
* два TCP-слушателя в двух процессах (две ноды на одной машине) — ровно то же самое;
* если на этом же номере сидит обычный слушатель без SO_REUSEPORT (API ноды — uvicorn),
  Xray действительно не поднимается: `failed to listen TCP on 8443 ... bind: address
  already in use` — и у ноды останавливаются все её хосты;
* UDP и TCP на одном номере не встречаются вовсе: hy2-инбаунд (QUIC/HTTP3, UDP) и
  tcp-инбаунд мирно сидят на одном номере, каждый берёт только свой протокол.

Отсюда правило: один и тот же номер на одной машине делят только слушатели **одного
класса**. hy2-хост может занять порт, на котором уже работает vless-tcp (и наоборот) —
это нормальная связка «443/tcp для VLESS, 443/udp для Hysteria2». Два hy2-хоста на одном
номере — уже конфликт: их UDP-пакеты Xray делит между ними так же, как TCP-соединения.

Хопа цепочки — такие же слушатели, как обычные хосты (у каждого хопа на его ноде свой
инбаунд), поэтому участвуют в проверке наравне со всеми и по тому же классу.

API-порт ноды панель резервирует за нодой целиком, для любого класса: формально hy2 поверх
UDP не помешал бы API ноды поверх TCP, но два разных сервиса на одном номере человек потом
разбирает в логах, и панель такой путаницы не устраивает.
"""
from __future__ import annotations

import sqlite3

PORT_MIN = 1
PORT_MAX = 65535

TCP_NET = "tcp"
UDP_NET = "udp"
ANY_NET = "any"          # «любой слушатель на этом номере» — так проверяется API-порт ноды

# hy2 — единственный протокол панели, который слушает UDP: его транспорт QUIC/HTTP3
UDP_PROTOCOLS = frozenset({"hy2"})

NET_LABEL = {TCP_NET: "TCP", UDP_NET: "UDP"}

# Та же граница в базе (уникальный индекс hosts_node_port): sqlite не пускает в одну ноду
# два слушателя одного класса на одном порту и пускает hy2 рядом с tcp-хостом.
LISTENER_NET_SQL = "CASE WHEN lower(protocol) = 'hy2' THEN 'udp' ELSE 'tcp' END"


def listener_net(protocol: str | None) -> str:
    """Что слушает этот хост/хоп: hy2 — UDP (QUIC), всё остальное — TCP."""
    return UDP_NET if (protocol or "").strip().lower() in UDP_PROTOCOLS else TCP_NET


def norm(address: str | None) -> str:
    """Адрес ноды для сравнения: без регистра и пробелов."""
    return (address or "").strip().lower()


def node_address(conn: sqlite3.Connection, node_id: int) -> str:
    row = conn.execute("SELECT address FROM nodes WHERE id = ?", (node_id,)).fetchone()
    return norm(row["address"]) if row else ""


def port_conflict(conn: sqlite3.Connection, address: str, port: int, *,
                  skip_api_of: int | None = None, skip_host: int | None = None,
                  skip_chain: int | None = None, own_node: int | None = None,
                  network: str = TCP_NET) -> str | None:
    """Кем занят (адрес, порт) слушателем класса `network`. None — свободно.

    `skip_api_of` — чей API-порт вот-вот изменится (правка ноды: её собственный API-порт
    конфликтом не является; для хоста или хопа этого исключения нет — порт своей же ноды занят
    и для него: Xray не поднимется на номере, где нода уже отвечает панелью). `own_node` — для
    human-текста: «на этой ноде» или «на этом же адресе». `skip_host` — строка хоста, которую
    правят. `skip_chain` — цепочку, которую пересобирают целиком: её прежние хопа исчезнут в
    той же транзакции. `network` — класс слушателя, который ставят на это место (`ANY_NET` —
    «любой»: так панель резервирует API-порт за нодой).
    """
    target = norm(address)
    if not target:
        return None

    for node in conn.execute("SELECT id, name, address, api_port FROM nodes ORDER BY name").fetchall():
        if norm(node["address"]) != target or int(node["api_port"]) != port:
            continue
        if skip_api_of is not None and int(node["id"]) == skip_api_of:
            continue
        # API-порт ноды — TCP (uvicorn): tcp-слушатель на этом номере не поднимется вовсе,
        # а UDP-хост панель не пускает, чтобы не держать два сервиса на одном порту
        reason = ("Xray на этой машине не поднимется" if network != UDP_NET
                  else "панель держит этот порт за нодой: два сервиса на одном номере "
                       "потом не разберёшь")
        return (f"порт {port} на {target} уже занят API-портом ноды «{node['name']}» — {reason}")

    for row in conn.execute(
        """SELECT h.id, h.name, h.port, h.protocol, h.chain_id,
                  n.id AS node_id, n.name AS node_name, n.address AS node_address
           FROM hosts h JOIN nodes n ON n.id = h.node_id ORDER BY h.id""").fetchall():
        if int(row["port"]) != port or norm(row["node_address"]) != target:
            continue
        if skip_host is not None and int(row["id"]) == skip_host:
            continue
        if skip_chain is not None and row["chain_id"] == skip_chain:
            continue
        occupied = listener_net(row["protocol"])
        if network != ANY_NET and occupied != network:
            continue
        own_here = own_node is not None and int(row["node_id"]) == own_node
        where = "на этой ноде" if own_here else "на этом же адресе"
        kind = "хостом цепочки" if row["chain_id"] is not None else "хостом"
        if network == ANY_NET:
            # порт спрашивает API ноды: TCP-слушателю сюда нельзя вовсе (Xray не поднимется),
            # UDP панель тоже не пускает — этот номер держится за нодой
            reason = (f"оба слушают {NET_LABEL[occupied]} на этом номере — Xray на этой машине "
                      "не поднимется" if occupied == TCP_NET else
                      "панель держит этот номер за API-портом ноды: клиентский порт Xray рядом "
                      "с ним человек потом разбирает по логам")
        else:
            reason = (f"оба слушают {NET_LABEL[occupied]} на этом номере: Xray поднимет оба "
                      "слушателя, но делит трафик между ними, и подписчики попадают не в тот хост")
        return (f"порт {port} на {target} уже занят {kind} «{row['name']}» "
                f"ноды «{row['node_name']}» {where}: {reason}")
    return None


def host_port_conflict(conn: sqlite3.Connection, node_id: int, port: int, *,
                       protocol: str | None = None,
                       skip_host: int | None = None, skip_chain: int | None = None) -> str | None:
    """Конфликт порта хоста: адрес берётся из ноды, куда этот хост должен сесть,
    а класс слушателя — из его протокола (hy2 слушает UDP, прочие — TCP)."""
    return port_conflict(conn, node_address(conn, node_id), port,
                         skip_host=skip_host, skip_chain=skip_chain, own_node=node_id,
                         network=listener_net(protocol))


def free_port(conn: sqlite3.Connection, node_id: int, wanted: int, *,
              protocol: str | None = None,
              reserved: set[tuple[int, int]] | None = None) -> int | None:
    """Первый свободный порт от `wanted` вверх — нужно миграции прежних цепочек.

    Живые порты людей панель молча не двигает: это решает человек. Миграции же приходится:
    прежняя цепочка могла занять чужой порт (например API-порт соседней ноды на той же
    машине), и оставить его занятым — значит опустить ноду целиком. Найденный порт миграция
    записывает и в ряд хопа, и в hops цепочки, и печатает в лог, чтобы это не было сюрпризом.
    """
    reserved = reserved or set()
    address = node_address(conn, node_id)
    network = listener_net(protocol)
    for port in range(max(PORT_MIN, wanted), PORT_MAX + 1):
        if (node_id, port) in reserved:
            continue
        if port_conflict(conn, address, port, own_node=node_id, network=network) is None:
            return port
    return None

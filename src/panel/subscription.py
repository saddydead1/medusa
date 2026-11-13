"""Ссылки подписки: из одного хоста панели — столько форматов, сколько просят приложения.

Панель описывает хост один раз (протокол, порт, транспорт, защита, пользователь),
а приложений у этого описания несколько:

* `vless://`, `vmess://`, `trojan://`, `ss://` — «общие» ссылки. Их понимают v2rayN,
  v2rayNG, Happ, Hiddify, Shadowrocket, Streisand, NekoBox. Переводной список таких
  ссылок, положенный в base64, — то самое, что вставляют в приложение как «ссылку
  подписки»: одно вставление, все хосты разом.
* Clash YAML (`proxies:` + группа выбора) — Clash Revive, Mihomo, Clash Verge, flclash.
  Mihomo-формат: `reality-opts`, `ws-opts`, `grpc-opts`, `client-fingerprint`.

Ссылка обязана описать ровно то, что панель собрала в конфиге Xray:uuid пользователя
(`user_uuid`), пароль (`user_password` / `ss_password`), короткий id reality
(`reality_short_id`), адрес хоста (не ноды!), транспорт и защита. Если ссылка расходится
с конфигом — подписчик подключиться не сможет, поэтому расхождение здесь считается ошибкой,
а не мелочью.

Hysteria2 панель раздаёт ссылкой `hy2://` (её понимают Hiddify, Shadowrocket, Streisand,
NekoBox и прочее hy2-семейство) и прокси `type: hysteria2` для Clash/Mihomo. В clash-фазе
живого прогона (`tools/live_demo.py`) Mihomo подключается к такому хосту панели — это
отдельно от reality, с которым Mihomo не договаривается.

Протоколы, ссылки которых панель не умеет, до хоста не допускаются на уровне API: лучше
честный отказ, чем хост, о котором подписчик не узнает.
"""
from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote, urlencode

import yaml

from src.core.xray_config import (SS_CIPHER, VMESS_CIPHER, hy2_auth, is_ip, reality_client_sni,
                                  reality_short_id, reality_sni_list, ss_password,
                                  user_password, user_uuid)

# что из хоста панели обязательно, чтобы собрать любую ссылку и любой Clash-прокси;
# {name} — откуда брать имя: у прямого хоста оно у хоста, у входа цепочки — у цепочки
HOST_COLUMNS = """h.id, {name} AS name, h.address, h.protocol, h.port, h.network, h.security,
                 h.public_key, h.fp, h.sni, h.server_names, h.dest, h.cert_file, h.key_file,
                 h.path, h.host_header, h.service_name, h.grpc_authority"""


def host_columns(name_expr: str) -> str:
    return HOST_COLUMNS.format(name=name_expr)


# во что протокол панели превращается в Clash YAML
CLASH_TYPE = {"vless": "vless", "vmess": "vmess", "trojan": "trojan", "ss": "ss",
              "hy2": "hysteria2"}
# Clash-группа выбора: без неё одиночный Clash (и Mihomo «конфигом») не знает,
# куда вообще класть трафик; Clash Verge её просто добавит к своим группам
CLASH_GROUP_SUFFIX = " · выбор"


def val(host: Any, key: str) -> str:
    """Поле хоста как строка: одинаково для sqlite3.Row и для словаря."""
    try:
        raw = host[key]
    except (KeyError, IndexError):
        return ""
    if raw is None:
        return ""
    return raw if isinstance(raw, str) else str(raw)


def connect_address(host: Any) -> str:
    """Куда подключается подписчик: свой адрес хоста, иначе адрес ноды."""
    return val(host, "address") or val(host, "node_address")


def client_sni(host: Any, address: str) -> str:
    """Имя, под которое клиент придёт: для reality — принятое имя (по умолчанию это
    домен маскировки), для tls — свой sni хоста, иначе адрес хоста.
    IP в SNI клиент подставить не умеет — тогда sni просто не называем."""
    if val(host, "security") == "reality":
        return reality_client_sni(host, address)
    sni = val(host, "sni").strip()
    if not sni:
        names = [n.strip() for n in val(host, "server_names").replace(",", " ").split() if n.strip()]
        sni = names[0] if names else address
    return sni if sni and not is_ip(sni) else ""


def reality_params(token: str, host: Any, address: str) -> dict[str, str]:
    """Параметры reality для клиента: публичный ключ (приватного наружу нет),
    отпечаток, sni из принимаемых (по умолчанию — домен маскировки), короткий id
    подписчика и spiderX."""
    params = {"security": "reality"}
    if val(host, "public_key"):
        params["pbk"] = val(host, "public_key")
    params["fp"] = val(host, "fp") or "chrome"
    sni = client_sni(host, address)
    if sni:
        params["sni"] = sni
    params["sid"] = reality_short_id(token)
    params["spx"] = "/"
    return params


def tls_params(host: Any, address: str) -> dict[str, str]:
    params = {"security": "tls", "sni": client_sni(host, address) or address}
    if val(host, "fp"):
        params["fp"] = val(host, "fp")
    return params


def transport_params(host: Any) -> dict[str, str]:
    """Транспортные детали ссылки: путь и Host у websocket, имя сервиса у gRPC.
    Не названные панелью поля не появляются — у клиента свои разумные значения."""
    params: dict[str, str] = {}
    network = val(host, "network")
    if network == "ws":
        if val(host, "path"):
            params["path"] = val(host, "path")
        if val(host, "host_header"):
            params["host"] = val(host, "host_header")
    elif network == "grpc" and val(host, "service_name"):
        params["serviceName"] = val(host, "service_name")
    return params


def fragment(name: str) -> str:
    return f"#{quote(name or '', safe='')}"


def query(params: dict[str, str]) -> str:
    return f"?{urlencode(params)}" if params else ""


# ----- общие ссылки: vless://, vmess://, trojan://, ss:// -----

def vless_link(token: str, host: Any) -> str:
    address = connect_address(host)
    params: dict[str, str] = {"type": val(host, "network"), "encryption": "none"}
    security = val(host, "security")
    if security == "tls":
        params.update(tls_params(host, address))
    elif security == "reality":
        params.update(reality_params(token, host, address))
    else:
        params["security"] = "none"
    params.update(transport_params(host))
    return f"vless://{user_uuid(token)}@{address}:{host['port']}{query(params)}{fragment(val(host, 'name'))}"


def vmess_link(token: str, host: Any) -> str:
    """VMess — не адрес, а base64 из JSON: таково соглашение всех vmess-приложений.

    `scy` и `cipher` — одно и то же поле у разных клиентов (v2rayN читает «scy»,
    Clash и v2rayNG — «cipher»): панель называет его дважды, чтобы шифр не потерялся.
    alterId всегда 0: устаревший режим клиенты давно не поддерживают.
    """
    address = connect_address(host)
    entry: dict[str, Any] = {
        "v": "2",
        "ps": val(host, "name"),
        "add": address,
        "port": str(host["port"]),
        "id": user_uuid(token),
        "aid": "0",
        "net": val(host, "network"),
        "type": "none",
        "scy": VMESS_CIPHER,
        "cipher": VMESS_CIPHER,
    }
    network = val(host, "network")
    if network == "ws":
        if val(host, "host_header"):
            entry["host"] = val(host, "host_header")
        if val(host, "path"):
            entry["path"] = val(host, "path")
    elif network == "grpc" and val(host, "service_name"):
        # у gRPC в vmess-JSON отдельного поля для имени сервиса нет: его держат в path
        entry["path"] = val(host, "service_name")
    if val(host, "security") == "tls":
        entry["tls"] = "tls"
        sni = client_sni(host, address)
        if sni:
            entry["sni"] = sni
    # ensure_ascii=True: в имени хоста бывает кириллица, а base64 из чистого ASCII
    # переваривает любой парсер, даже тот, что не ожидает UTF-8
    payload = base64.b64encode(json.dumps(entry, ensure_ascii=True).encode("utf-8")).decode("ascii")
    return f"vmess://{payload}{fragment(val(host, 'name'))}"


def trojan_link(token: str, host: Any) -> str:
    address = connect_address(host)
    security = val(host, "security")
    params: dict[str, str] = {}
    if security == "tls":
        params.update(tls_params(host, address))
    elif security == "reality":
        params.update(reality_params(token, host, address))
    params.update(transport_params(host))
    return (f"trojan://{user_password(token)}@{address}:{host['port']}"
            f"{query(params)}{fragment(val(host, 'name'))}")


def ss_link(token: str, host: Any) -> str:
    """Shadowsocks-ссылка (SIP002): шифр и пароль прямо в адресе.

    Пароль свой на каждом хосте: в shadowsocks пароль и есть ключ шифрования этого
    порта, поэтому на другом порту он обязан быть другим."""
    address = connect_address(host)
    return (f"ss://{SS_CIPHER}:{ss_password(token, host['id'])}@{address}:{host['port']}"
            f"{fragment(val(host, 'name'))}")


def hy2_link(token: str, host: Any) -> str:
    """Hysteria2-ссылка: ключ человека — auth строка рукопожатия, а не uuid и не пароль шифра.

    `insecure=1` панель ставит, когда сертификата хосту выдала себя сама (self-signed): без
    этого hy2-клиенты честно отказываются принимать чужой сертификат. Свои сертификаты
    (обычные, валидные) остаются без insecure — проверка stays как есть.
    """
    address = connect_address(host)
    params: dict[str, str] = {}
    sni = client_sni(host, address)
    if sni:
        params["sni"] = sni
    if not (val(host, "cert_file") and val(host, "key_file")):
        params["insecure"] = "1"
    auth = hy2_auth(token, host["id"])
    return (f"hy2://{auth}@{address}:{host['port']}{query(params)}"
            f"{fragment(val(host, 'name'))}")


LINK_BUILDERS = {"vless": vless_link, "vmess": vmess_link, "trojan": trojan_link, "ss": ss_link,
                 "hy2": hy2_link}


def host_link(token: str, host: Any) -> str | None:
    """Ссылка хоста в общем формате или None, если протокол панель описать не умеет."""
    build = LINK_BUILDERS.get(val(host, "protocol"))
    return build(token, host) if build else None


def links_for(token: str, hosts: list[Any]) -> list[str]:
    """Ссылки всех хостов, которые панель умеет раздавать; остальные подписчик не увидит."""
    return [link for link in (host_link(token, h) for h in hosts) if link]


# ----- Clash: Mihomo, Clash Verge, Clash Revive, flclash -----

def clash_proxy(token: str, host: Any) -> dict[str, Any] | None:
    protocol = val(host, "protocol")
    if protocol not in CLASH_TYPE:
        return None
    address = connect_address(host)
    if protocol == "hy2":
        # форма hysteria2 в Clash своя: у него нет network/opts, зато есть sni и password
        proxy_hy2: dict[str, Any] = {
            "name": val(host, "name"),
            "type": "hysteria2",
            "server": address,
            "port": host["port"],
            "password": hy2_auth(token, host["id"]),
            "sni": client_sni(host, address) or address,
            "skip-cert-verify": not (val(host, "cert_file") and val(host, "key_file")),
        }
        return proxy_hy2
    proxy: dict[str, Any] = {
        "name": val(host, "name"),
        "type": CLASH_TYPE[protocol],
        "server": address,
        "port": host["port"],
        "network": val(host, "network"),
        "udp": True,
    }
    if protocol == "vless":
        proxy["uuid"] = user_uuid(token)
    elif protocol == "vmess":
        proxy["uuid"] = user_uuid(token)
        proxy["cipher"] = VMESS_CIPHER
        # Mihomo требует alterId явно: без него vmess-прокси он отвергает, хотя
        # устаревший режим давно выключен
        proxy["alterId"] = 0
    elif protocol == "trojan":
        proxy["password"] = user_password(token)
    elif protocol == "ss":
        proxy["cipher"] = SS_CIPHER
        proxy["password"] = ss_password(token, host["id"])

    if proxy["network"] == "ws":
        opts: dict[str, Any] = {}
        if val(host, "path"):
            opts["path"] = val(host, "path")
        if val(host, "host_header"):
            opts["headers"] = {"Host": val(host, "host_header")}
        if opts:
            proxy["ws-opts"] = opts
    elif proxy["network"] == "grpc" and val(host, "service_name"):
        proxy["grpc-opts"] = {"grpc-service-name": val(host, "service_name")}

    security = val(host, "security")
    if security == "tls":
        proxy["tls"] = True
        proxy["servername"] = client_sni(host, address) or address
        # сертификаты нод самоподписанные, если своих файлов у хоста нет: Clash не должен
        # спотыкаться об них. Свой сертификат — проверяем честно, skip-verify не включаем
        proxy["skip-cert-verify"] = not (val(host, "cert_file") and val(host, "key_file"))
        if val(host, "fp"):
            proxy["client-fingerprint"] = val(host, "fp")
    elif security == "reality":
        proxy["tls"] = True
        # Имя, которое клиент называет в reality, обязано быть одним из принимаемых
        # сервером имён (по умолчанию — домен маскировки): наружу уходит настоящий
        # сертификат этого сайта, и Clash сверяет его с этим именем, а не с адресом ноды.
        # Mihomo для reality читает именно `sni` (на это указал живой прогон: с одним
        # лишь `servername` он стучался с sni = адрес ноды и получал чужой сертификат),
        # поэтому панель называет имя обоими полями — разные ветки Clash берут разное.
        names = reality_sni_list(host, address)
        sni = names[0] if names else address
        proxy["servername"] = sni
        proxy["sni"] = sni
        reality_opts: dict[str, Any] = {"short-id": reality_short_id(token)}
        if val(host, "public_key"):
            reality_opts["public-key"] = val(host, "public_key")
        proxy["reality-opts"] = reality_opts
        proxy["client-fingerprint"] = val(host, "fp") or "chrome"
    return proxy


def clash_proxies(token: str, hosts: list[Any]) -> list[dict[str, Any]]:
    """Список прокси Clash: имена не должны сталкиваться — Clash по имени и узнаёт прокси."""
    proxies: list[dict[str, Any]] = []
    seen: set[str] = set()
    for host in hosts:
        proxy = clash_proxy(token, host)
        if proxy is None:
            continue
        name = proxy["name"]
        if name in seen:
            name = f"{name} ({host['port']})"
        if name in seen:
            name = f"{name} #{host['id']}"
        proxy["name"] = name
        seen.add(name)
        proxies.append(proxy)
    return proxies


def clash_group_name(panel: str, proxies: list[dict[str, Any]]) -> str:
    base = (panel or "").strip() or "medusa"
    names = {p["name"] for p in proxies}
    for candidate in (f"{base}{CLASH_GROUP_SUFFIX}", base, "medusa выбор"):
        if candidate not in names:
            return candidate
    return "medusa"


def clash_document(panel: str, proxies: list[dict[str, Any]]) -> str:
    """YAML-подписка для Clash/Mihomo.

    Кроме самих прокси панель кладёт одну группу выбора и правило MATCH до неё: одиночный
    Mihomo, которому дали этот файл как конфиг, обязан знать, куда класть трафик. Clash Verge
    свою настройку держит сам, а группу из подписки просто добавит к своим.
    """
    doc: dict[str, Any] = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "unified-delay": True,
        "proxies": proxies,
    }
    if proxies:
        group = clash_group_name(panel, proxies)
        doc["proxy-groups"] = [{"name": group, "type": "select", "proxies": [p["name"] for p in proxies]}]
        doc["rules"] = [f"MATCH,{group}"]
    body = "# medusa: подписка панели, сгенерировано — не правьте руками\n" + yaml.safe_dump(
        doc, sort_keys=False, allow_unicode=True, default_flow_style=False)
    return body


def links_document(token: str, hosts: list[Any], raw: bool) -> str:
    """Переводной список ссылок: base64 от него и есть «ссылка подписки» для v2rayN,
    v2rayNG, Happ, Hiddify, Shadowrocket."""
    plain = "\n".join(links_for(token, hosts))
    return plain if raw else base64.b64encode(plain.encode("utf-8")).decode("ascii")

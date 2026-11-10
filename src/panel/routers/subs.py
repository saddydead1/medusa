"""Страница подписки: `GET /sub/<токен пользователя>`.

Адрес подписки задаётся в настройках панели целиком — до `/sub` включительно
(например `http://127.0.0.1:8000/sub`); панель дописывает к нему только токен
пользователя. Отдельного входа здесь нет: сам токен и есть пропуск.

Страница для людей: никнейм в заголовке, статус, трафик, приложение, доступные
хосты (у vless-хоста — кнопка копирования ссылки `vless://...`) и цепочки.
Язык по умолчанию русский, `?lang=en` переключает на английский. Раздачу
машинных конфигов (Clash YAML, sing-box JSON) это не отменяет — она впереди.
"""
from __future__ import annotations

import html
import sqlite3
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from src.core.xray_config import is_ip, reality_short_id, user_uuid
from src.panel.db import get_conn
from src.panel.routers.chains import hops_of

router = APIRouter(prefix="/sub", tags=["subscriptions"])

GB = 1024 ** 3
PROTO = {"vless": "VLESS", "vmess": "VMess", "trojan": "Trojan", "ss": "Shadowsocks", "hy2": "Hysteria2"}
SEC_BADGE = {"none": "b-off", "tls": "b-ok", "reality": "b-ok"}

ICONS = {
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>',
    "link": '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    "chev": '<path d="M9 6l6 6-6 6"/>',
    "copy": '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
    # те же иконки, что в карточках «Обзора» панели; календарь — в том же рисунке штрихом
    "activity": '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    "calendar": '<rect x="3.5" y="5" width="17" height="15" rx="2.5"/><path d="M3.5 10h17"/><path d="M8 3v4M16 3v4"/>',
}

STRINGS = {
    "ru": {
        "suffix": "Подписка",
        "stat.used": "потрачено", "stat.since": "дата регистрации",
        "active": "активен", "disabled": "отключён",
        "hosts": "Хосты", "chains": "Цепочки",
        "th.name": "Название", "th.protocol": "Протокол",
        "th.port": "Порт", "th.transport": "Транспорт", "th.security": "Защита",
        "th.route": "Маршрут",
        "empty.hosts": "Хостов пока нет", "empty.chains": "Цепочек пока нет",
        "copy": "Скопировать", "copied": "Скопировано",
        "lang.switch": "Переключить язык интерфейса",
        "disabled.note": "Учётка отключена: подписка не раздаётся, хосты скрыты",
        "404.title": "Ссылка не найдена",
        "404.text": "Такого токена подписки нет: возможно, пользователя удалили или в ссылке опечатка.",
    },
    "en": {
        "suffix": "Subscription",
        "stat.used": "used", "stat.since": "registration date",
        "active": "active", "disabled": "disabled",
        "hosts": "Hosts", "chains": "Chains",
        "th.name": "Name", "th.protocol": "Protocol",
        "th.port": "Port", "th.transport": "Transport", "th.security": "Security",
        "th.route": "Route",
        "empty.hosts": "No hosts yet", "empty.chains": "No chains yet",
        "copy": "Copy", "copied": "Copied",
        "lang.switch": "Switch interface language",
        "disabled.note": "Account disabled: the subscription is off, hosts are hidden",
        "404.title": "Link not found",
        "404.text": "There is no such subscription token: the user may have been deleted or the link has a typo.",
    },
}

# кнопочки копирования живёт своим крошечным скриптом: страница отдаётся без всего
# фронтенда панели, а просить весь script.js ради одной кнопки — лишнее
COPY_JS = """<script>
function legacyCopy(v){
  var ta = document.createElement('textarea');
  ta.value = v; ta.style.position = 'fixed'; ta.style.left = '-9999px';
  document.body.appendChild(ta); ta.focus(); ta.setSelectionRange(0, ta.value.length);
  var ok = false;
  try{ ok = document.execCommand('copy'); }catch(e){}
  document.body.removeChild(ta); return ok;
}
document.querySelectorAll('[data-copy]').forEach(function(b){
  b.addEventListener('click', function(){
    var v = b.getAttribute('data-copy'), old = b.innerHTML;
    var done = function(){ b.innerHTML = '\\u2713 ' + b.getAttribute('data-done');
      setTimeout(function(){ b.innerHTML = old; }, 1400); };
    var fail = function(){ prompt(v); };
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(v).then(done, function(){ legacyCopy(v) ? done() : fail(); });
    else legacyCopy(v) ? done() : fail();
  });
});
</script>"""


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def icon(name: str) -> str:
    return f'<svg class="ico" viewBox="0 0 24 24" aria-hidden="true">{ICONS[name]}</svg>'


def human(bytes_: int) -> str:
    if bytes_ >= GB:
        value = bytes_ / GB
        return f"{value:.0f} GB" if value >= 10 else f"{value:.1f} GB"
    return f"{bytes_ // (1024 * 1024)} MB"


def pick_lang(request: Request) -> str:
    """Русский по умолчанию; английский — только когда его явно попросили."""
    return "en" if request.query_params.get("lang", "").strip().lower().startswith("en") else "ru"


def lang_switch(lang: str) -> str:
    """Как в панели: одна кнопка с глобусом и текущим кодом языка, клик переключает."""
    next_lang, current = ("en", "RU") if lang == "ru" else ("ru", "EN")
    title = STRINGS[lang]["lang.switch"]
    return f'<a class="langbtn" href="?lang={next_lang}" title="{title}" aria-label="{title}">{icon("globe")}<span>{current}</span></a>'


def since(ms: int) -> str:
    if not ms:
        return ""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d")


def shell(title: str, lang: str, theme: str, body: str, status: int = 200) -> HTMLResponse:
    theme_attr = f' data-theme="{theme}"' if theme in ("light", "dark") else ""
    return HTMLResponse(
        f"""<!doctype html>
<html lang="{lang}"{theme_attr}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{esc(title)}</title>
<link rel="stylesheet" href="/style.css">
</head>
<body class="subpg">
<main>
{body}
</main>
{COPY_JS}
</body>
</html>""",
        status_code=status,
    )


def subscription_link(token: str, host: dict | sqlite3.Row) -> str:
    """Ссылка для приложения: uuid пользователя (он же id в Xray-конфиге), адрес хоста,
    порт и защита. Адрес хоста — тот, к которому подключается человек; адрес ноды —
    только если своего адреса у хоста нет.

    Пока только vless: остальные протоколы требуют своих полей (шифрование ss,
    json vmess), которых в базе хоста нет.
    """
    address = host["address"] or host["node_address"]
    params: dict[str, str] = {"type": host["network"], "encryption": "none"}
    # транспортные детали ссылки: путь и Host у ws, имя сервиса у gRPC
    if host["network"] == "ws":
        if host["path"]:
            params["path"] = host["path"]
        if host["host_header"]:
            params["host"] = host["host_header"]
    elif host["network"] == "grpc" and host["service_name"]:
        params["serviceName"] = host["service_name"]
    security = host["security"]
    if security == "tls":
        params.update({"security": "tls", "sni": address})
    elif security == "reality":
        params["security"] = "reality"
        if host["public_key"]:
            params["pbk"] = host["public_key"]
        params["fp"] = host["fp"] or "chrome"
        if not is_ip(address):
            params["sni"] = address
        params["sid"] = reality_short_id(token)
        params["spx"] = "/"
    else:
        params["security"] = "none"
    return (f"vless://{user_uuid(token)}@{address}:{host['port']}?{urlencode(params)}"
            f"#{quote(host['name'], safe='')}")


def hosts_table(hosts: list[sqlite3.Row], user: sqlite3.Row, strings: dict) -> str:
    rows = ""
    for h in hosts:
        copy = ""
        if h["protocol"] == "vless":
            link = subscription_link(user["token"], h)
            copy = (f'<button class="btn sm" type="button" data-copy="{esc(link)}" data-done="{strings["copied"]}"'
                    f' title="{esc(link)}">{icon("copy")}{strings["copy"]}</button>')
        rows += (f"""<tr><td>{esc(h["name"])}</td>
        <td><span class="badge b-proto">{esc(PROTO.get(h["protocol"], h["protocol"]))}</span></td>
        <td>{h["port"]}</td><td>{esc(h["network"])}</td>
        <td><span class="badge {SEC_BADGE.get(h["security"], "b-off")}">{esc(h["security"])}</span></td>
        <td><div class="acts">{copy}</div></td></tr>""")
    if not rows:
        return f'<div class="panel"><div class="empty">{strings["empty.hosts"]}</div></div>'
    heads = (strings["th.name"], strings["th.protocol"], strings["th.port"],
             strings["th.transport"], strings["th.security"], "")
    return ('<div class="panel"><table><thead><tr>'
            + "".join(f"<th>{h}</th>" for h in heads)
            + f"</tr></thead><tbody>{rows}</tbody></table></div>")


def chains_table(conn: sqlite3.Connection, chain_rows: list[sqlite3.Row],
                 user: sqlite3.Row, strings: dict) -> str:
    """Цепочка для подписчика — один вход: протокол, порт и защита первого хопа.

    Ссылка для приложения строится по входу цепочки: пользователь подключается
    к первой ноде, остальные хопа панель держит на своей стороне.
    """
    rows = ""
    for r in chain_rows:
        hops = hops_of(conn, r["hops"])
        route = icon("chev").join(esc(h["node"]) for h in hops)
        copy = ""
        if r["protocol"] == "vless":
            link = subscription_link(user["token"], r)
            copy = (f'<button class="btn sm" type="button" data-copy="{esc(link)}" data-done="{strings["copied"]}"'
                    f' title="{esc(link)}">{icon("copy")}{strings["copy"]}</button>')
        rows += (f"""<tr><td>{esc(r["name"])}</td><td><span class="route">{route}</span></td>
        <td><span class="badge b-proto">{esc(PROTO.get(r["protocol"], r["protocol"]))}</span></td>
        <td>{r["port"]}</td>
        <td><span class="badge {SEC_BADGE.get(r["security"], "b-off")}">{esc(r["security"])}</span></td>
        <td><div class="acts">{copy}</div></td></tr>""")
    if not rows:
        return f'<div class="panel"><div class="empty">{strings["empty.chains"]}</div></div>'
    heads = (strings["th.name"], strings["th.route"], strings["th.protocol"],
             strings["th.port"], strings["th.security"], "")
    return ('<div class="panel"><table><thead><tr>'
            + "".join(f"<th>{h}</th>" for h in heads)
            + f"</tr></thead><tbody>{rows}</tbody></table></div>")


@router.get("/{token}")
def subscription_page(token: str, request: Request,
                      conn: sqlite3.Connection = Depends(get_conn)) -> HTMLResponse:
    st = conn.execute("SELECT panelName,subTitle,subInterval,theme FROM settings WHERE id = 1").fetchone()
    lang = pick_lang(request)
    s = STRINGS[lang]
    user = conn.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()
    switch = lang_switch(lang)

    if user is None:
        body = (f'<div class="head"><h2>{s["404.title"]}</h2>{switch}</div>'
                f'<div class="panel"><div class="empty"><b>{s["404.title"]}</b>'
                f'<div class="sub">{s["404.text"]}</div></div></div>')
        return shell(f'{st["panelName"]} — {s["404.title"]}', lang, st["theme"], body, status=404)

    hosts = conn.execute(
        """SELECT h.name, h.address, h.public_key, h.fp, h.path, h.host_header, h.service_name,
                  h.protocol, h.port, h.network, h.security,
                  n.address AS node_address
           FROM hosts h JOIN nodes n ON n.id = h.node_id
           WHERE h.chain_id IS NULL ORDER BY h.name""").fetchall()
    chains = conn.execute(
        """SELECT c.name, c.hops, h.address, h.public_key, h.fp, h.path, h.host_header, h.service_name,
                  h.protocol, h.port, h.network, h.security,
                  n.address AS node_address
           FROM chains c JOIN hosts h ON h.chain_id = c.id JOIN nodes n ON n.id = h.node_id
           ORDER BY c.name""").fetchall()

    alive = user["status"] == "active"
    status_class = "badge b-ok live" if alive else "badge b-off"
    status_text = s["active"] if alive else s["disabled"]

    stats = f"""<div class="stats">
      <div class="stat"><i class="chip">{icon("activity")}</i><b>{human(user["used_bytes"])}</b><span>{s["stat.used"]}</span></div>
      <div class="stat"><i class="chip">{icon("calendar")}</i><b>{since(user["created_at"])}</b><span>{s["stat.since"]}</span></div>
    </div>"""

    if alive:
        lists = (
            f'<section class="grp"><div class="sect"><h3>{icon("globe")}{s["hosts"]}'
            f'<span class="count">{len(hosts)}</span></h3></div>{hosts_table(hosts, user, s)}</section>'
            f'<section class="grp"><div class="sect"><h3>{icon("link")}{s["chains"]}'
            f'<span class="count">{len(chains)}</span></h3></div>{chains_table(conn, chains, user, s)}</section>'
        )
    else:
        lists = f'<div class="badline">{s["disabled.note"]}</div>'

    body = (
        f'<div class="head"><h2>{esc(user["name"])} · {s["suffix"]}'
        f'<span class="{status_class}">{status_text}</span></h2>{switch}</div>'
        + stats + lists
    )
    return shell(f'{user["name"]} · {s["suffix"]}', lang, st["theme"], body)

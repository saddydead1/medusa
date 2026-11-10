"""Страница подписки: `GET /sub/<токен пользователя>`.

Адрес подписки задаётся в настройках панели целиком — до `/sub` включительно
(например `http://127.0.0.1:8000/sub`); панель дописывает к нему только токен
пользователя. Отдельного входа здесь нет: сам токен и есть пропуск.

Страница для людей: никнейм в заголовке, статус, трафик, переключатели языка и
темы, «ссылка подписки» (её вставляют в приложение целиком или сканируют QR —
и все хосты добавляются разом), хосты и цепочки (у vless — кнопка копирования
ссылки `vless://...` и кнопка QR-кода этой же ссылки).
Язык по умолчанию русский, `?lang=en` переключает на английский.

Машинные эндпоинты той же подписки:
* `GET /sub/<token>/links` — все ссылки сразу: base64-строка (как ждут
  v2rayN/v2rayNG и большинство клиентов); `?raw=1` — те же строки без base64;
* `GET /sub/<token>/qr/subscribe` — QR на ссылку подписки (целая подписка
  одним сканированием);
* `GET /sub/<token>/qr/host/<id>` — QR на ссылку одного хоста.
Раздача конфигов Clash YAML / sing-box JSON — впереди.
"""
from __future__ import annotations

import base64
import html
import io
import sqlite3
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

import segno
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response

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
    "qr": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14h1M14 20h3M20 20h1v1"/>',
    "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    "moon": '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>',
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
        "theme.switch": "Сменить тему",
        "qr.show": "QR-код", "qr.host": "Показать QR-код ссылки этого хоста",
        "sub.link": "Ссылка подписки",
        "sub.link.hint": "Вставьте её в приложение (v2rayN, v2rayNG, Hiddify…) или отсканируйте QR: "
                         "все доступные хосты добавятся разом. Ссылка содержит ваш личный токен — "
                         "не раздавайте её другим людям.",
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
        "theme.switch": "Switch theme",
        "qr.show": "QR code", "qr.host": "Show the QR code of this host's link",
        "sub.link": "Subscription link",
        "sub.link.hint": "Paste it into the app (v2rayN, v2rayNG, Hiddify…) or scan the QR: "
                         "every available host is imported at once. The link carries your personal "
                         "token — do not hand it around.",
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

# тема: сохранённый в браузере выбор важнее настройки панели; авто следует системе
THEME_JS = """<script>
(function(){
  var KEY='medusa-sub-theme', root=document.documentElement, btn=document.getElementById('themebtn');
  var saved=null; try{ saved=localStorage.getItem(KEY); }catch(e){}
  if(saved==='light'||saved==='dark') root.setAttribute('data-theme', saved);
  else if(!root.getAttribute('data-theme') && window.matchMedia
          && window.matchMedia('(prefers-color-scheme: light)').matches) root.setAttribute('data-theme','light');
  if(!btn) return;
  btn.addEventListener('click', function(){
    var next = root.getAttribute('data-theme')==='light' ? 'dark' : 'light';
    root.setAttribute('data-theme', next);
    try{ localStorage.setItem(KEY, next); }catch(e){}
  });
})();
</script>"""

# QR-модалка: картинка тянется тем же запросом, что и вся страница, — отдельного входа не нужно
QR_JS = """<script>
(function(){
  var dlg=document.getElementById('qrdlg'); if(!dlg) return;
  var img=dlg.querySelector('img'), cap=dlg.querySelector('.cap');
  document.querySelectorAll('[data-qr]').forEach(function(b){
    b.addEventListener('click', function(){
      img.src=b.getAttribute('data-qr'); cap.textContent=b.getAttribute('data-cap')||'';
      if(dlg.showModal) dlg.showModal(); else dlg.setAttribute('open','');
    });
  });
  dlg.querySelector('.closer').addEventListener('click', function(){
    if(dlg.close) dlg.close(); else dlg.removeAttribute('open');
  });
})();
</script>"""


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def icon(name: str, cls: str = "ico") -> str:
    return f'<svg class="{cls}" viewBox="0 0 24 24" aria-hidden="true">{ICONS[name]}</svg>'


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


def theme_switch(lang: str) -> str:
    """Солнце/луна: локальный выбор живёт в браузере и не трогает настройку панели."""
    title = STRINGS[lang]["theme.switch"]
    return (f'<button id="themebtn" class="langbtn themebtn" type="button" title="{title}" aria-label="{title}">'
            f'{icon("sun", "ico sun")}{icon("moon", "ico moon")}</button>')


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
<dialog id="qrdlg"><img alt="QR"><div class="cap"></div><button class="btn sm closer" type="button">&#10005;</button></dialog>
{COPY_JS}{THEME_JS}{QR_JS}
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
        params.update({"security": "tls", "sni": host["sni"] or address})
        if host["fp"]:
            params["fp"] = host["fp"]
    elif security == "reality":
        params["security"] = "reality"
        if host["public_key"]:
            params["pbk"] = host["public_key"]
        params["fp"] = host["fp"] or "chrome"
        # sni для клиента — первое имя из списка, который принимает reality
        sni = host["sni"] or (host["server_names"].split(",")[0].strip() if host["server_names"] else "") or address
        if not is_ip(sni):
            params["sni"] = sni
        params["sid"] = reality_short_id(token)
        params["spx"] = "/"
    else:
        params["security"] = "none"
    return (f"vless://{user_uuid(token)}@{address}:{host['port']}?{urlencode(params)}"
            f"#{quote(host['name'], safe='')}")


HOST_FIELDS = """h.id, h.name, h.address, h.public_key, h.fp, h.sni, h.server_names,
                  h.path, h.host_header, h.service_name,
                  h.protocol, h.port, h.network, h.security"""


def fetch_hosts(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        f"""SELECT {HOST_FIELDS}, n.address AS node_address
           FROM hosts h JOIN nodes n ON n.id = h.node_id
           WHERE h.chain_id IS NULL ORDER BY h.name""").fetchall()


def fetch_chains(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Для подписки цепочка — это её вход: адрес, порт и защита первой ноды,
    имя — имя цепочки (его подписчик и увидит в приложении)."""
    return conn.execute(
        """SELECT h.id, c.name, c.hops, h.address, h.public_key, h.fp, h.sni, h.server_names,
                  h.path, h.host_header, h.service_name,
                  h.protocol, h.port, h.network, h.security,
                  n.address AS node_address
           FROM chains c JOIN hosts h ON h.chain_id = c.id JOIN nodes n ON n.id = h.node_id
           ORDER BY c.name""").fetchall()


def qr_svg(data: str) -> Response:
    """QR как SVG: лёгкий, резкий на любом масштабе и не тянет ни одной картинки."""
    buf = io.BytesIO()
    segno.make(data, error="m").save(buf, kind="svg", scale=6, border=2, dark="#0b1020", light="#ffffff")
    return Response(content=buf.getvalue(), media_type="image/svg+xml",
                    headers={"Cache-Control": "no-store"})


def sub_base(request: Request, st: sqlite3.Row) -> str:
    """Настройка subUrl содержит адрес панели целиком, до `/sub` включительно;
    без неё панель берёт собственный адрес, с которого открыта эта страница."""
    raw = (st["subUrl"] or "").strip().rstrip("/")
    if raw:
        return raw
    return f"{request.url.scheme}://{request.url.netloc}/sub"


def active_user(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    """Пропуск машинных эндпоинтов: только живой пользователь своей подписки."""
    user = conn.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()
    return user if user is not None and user["status"] == "active" else None


def qr_button(token: str, host_id: int, caption: str, strings: dict) -> str:
    return (f'<button class="btn sm" type="button" data-qr="/sub/{token}/qr/host/{host_id}"'
            f' data-cap="{esc(caption)}" title="{strings["qr.host"]}">{icon("qr")}{strings["qr.show"]}</button>')


def hosts_table(hosts: list[sqlite3.Row], user: sqlite3.Row, strings: dict) -> str:
    rows = ""
    for h in hosts:
        acts = ""
        if h["protocol"] == "vless":
            link = subscription_link(user["token"], h)
            acts = (f'<button class="btn sm" type="button" data-copy="{esc(link)}" data-done="{strings["copied"]}"'
                    f' title="{esc(link)}">{icon("copy")}{strings["copy"]}</button>'
                    + qr_button(user["token"], h["id"], h["name"], strings))
        rows += (f"""<tr><td>{esc(h["name"])}</td>
        <td><span class="badge b-proto">{esc(PROTO.get(h["protocol"], h["protocol"]))}</span></td>
        <td>{h["port"]}</td><td>{esc(h["network"])}</td>
        <td><span class="badge {SEC_BADGE.get(h["security"], "b-off")}">{esc(h["security"])}</span></td>
        <td><div class="acts">{acts}</div></td></tr>""")
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
        acts = ""
        if r["protocol"] == "vless":
            link = subscription_link(user["token"], r)
            acts = (f'<button class="btn sm" type="button" data-copy="{esc(link)}" data-done="{strings["copied"]}"'
                    f' title="{esc(link)}">{icon("copy")}{strings["copy"]}</button>'
                    + qr_button(user["token"], r["id"], r["name"], strings))
        rows += (f"""<tr><td>{esc(r["name"])}</td><td><span class="route">{route}</span></td>
        <td><span class="badge b-proto">{esc(PROTO.get(r["protocol"], r["protocol"]))}</span></td>
        <td>{r["port"]}</td>
        <td><span class="badge {SEC_BADGE.get(r["security"], "b-off")}">{esc(r["security"])}</span></td>
        <td><div class="acts">{acts}</div></td></tr>""")
    if not rows:
        return f'<div class="panel"><div class="empty">{strings["empty.chains"]}</div></div>'
    heads = (strings["th.name"], strings["th.route"], strings["th.protocol"],
             strings["th.port"], strings["th.security"], "")
    return ('<div class="panel"><table><thead><tr>'
            + "".join(f"<th>{h}</th>" for h in heads)
            + f"</tr></thead><tbody>{rows}</tbody></table></div>")


def sub_link_section(token: str, links_url: str, strings: dict) -> str:
    return (f'<section class="grp"><div class="sect"><h3>{icon("link")}{strings["sub.link"]}</h3></div>'
            f'<div class="panel sublink"><div class="subrow">'
            f'<input class="url" readonly value="{esc(links_url)}" onclick="this.select()">'
            f'<button class="btn sm" type="button" data-copy="{esc(links_url)}" data-done="{strings["copied"]}">'
            f'{icon("copy")}{strings["copy"]}</button>'
            f'<button class="btn sm" type="button" data-qr="/sub/{token}/qr/subscribe" data-cap="{esc(strings["sub.link"])}">'
            f'{icon("qr")}{strings["qr.show"]}</button>'
            f'<img class="qr" src="/sub/{token}/qr/subscribe" alt="QR">'
            f'</div><p class="hint">{strings["sub.link.hint"]}</p></div></section>')


@router.get("/{token}")
def subscription_page(token: str, request: Request,
                      conn: sqlite3.Connection = Depends(get_conn)) -> HTMLResponse:
    st = conn.execute("SELECT panelName,subTitle,subInterval,theme,subUrl FROM settings WHERE id = 1").fetchone()
    lang = pick_lang(request)
    s = STRINGS[lang]
    user = conn.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()
    buttons = f'<div class="topbtns">{theme_switch(lang)}{lang_switch(lang)}</div>'

    if user is None:
        body = (f'<div class="head"><h2>{s["404.title"]}</h2>{buttons}</div>'
                f'<div class="panel"><div class="empty"><b>{s["404.title"]}</b>'
                f'<div class="sub">{s["404.text"]}</div></div></div>')
        return shell(f'{st["panelName"]} — {s["404.title"]}', lang, st["theme"], body, status=404)

    hosts, chains = fetch_hosts(conn), fetch_chains(conn)

    alive = user["status"] == "active"
    status_class = "badge b-ok live" if alive else "badge b-off"
    status_text = s["active"] if alive else s["disabled"]

    stats = f"""<div class="stats">
      <div class="stat"><i class="chip">{icon("activity")}</i><b>{human(user["used_bytes"])}</b><span>{s["stat.used"]}</span></div>
      <div class="stat"><i class="chip">{icon("calendar")}</i><b>{since(user["created_at"])}</b><span>{s["stat.since"]}</span></div>
    </div>"""

    if alive:
        links_url = f"{sub_base(request, st)}/{token}/links"
        lists = (sub_link_section(token, links_url, s)
                 + f'<section class="grp"><div class="sect"><h3>{icon("globe")}{s["hosts"]}'
                 f'<span class="count">{len(hosts)}</span></h3></div>{hosts_table(hosts, user, s)}</section>'
                 + f'<section class="grp"><div class="sect"><h3>{icon("link")}{s["chains"]}'
                 f'<span class="count">{len(chains)}</span></h3></div>{chains_table(conn, chains, user, s)}</section>')
    else:
        lists = f'<div class="badline">{s["disabled.note"]}</div>'

    body = (
        f'<div class="head"><h2>{esc(user["name"])} · {s["suffix"]}'
        f'<span class="{status_class}">{status_text}</span></h2>{buttons}</div>'
        + stats + lists
    )
    return shell(f'{user["name"]} · {s["suffix"]}', lang, st["theme"], body)


@router.get("/{token}/links")
def subscription_links(token: str, request: Request,
                       conn: sqlite3.Connection = Depends(get_conn)) -> Response:
    """Все vless-ссылки подписки одним куском: base64 (ждут v2rayN/v2rayNG и большинство
    клиентов), `?raw=1` — те же строки без base64."""
    user = active_user(conn, token)
    if user is None:
        return Response(content=b"", media_type="text/plain; charset=utf-8", status_code=404)
    links = [subscription_link(user["token"], r) for r in fetch_hosts(conn)]
    links += [subscription_link(user["token"], r) for r in fetch_chains(conn)]
    plain = "\n".join(links)
    body = plain if request.query_params.get("raw", "") in ("1", "true") else base64.b64encode(plain.encode("utf-8")).decode("ascii")
    return Response(content=body.encode("utf-8"), media_type="text/plain; charset=utf-8",
                    headers={"Cache-Control": "no-store"})


@router.get("/{token}/qr/subscribe")
def qr_subscribe(token: str, request: Request,
                 conn: sqlite3.Connection = Depends(get_conn)) -> Response:
    """QR на машинную ссылку подписки: одно сканирование вместо ручного вставления."""
    st = conn.execute("SELECT theme,subUrl FROM settings WHERE id = 1").fetchone()
    if active_user(conn, token) is None:
        return Response(content=b"", media_type="image/svg+xml", status_code=404)
    return qr_svg(f"{sub_base(request, st)}/{token}/links")


@router.get("/{token}/qr/host/{host_id}")
def qr_host(token: str, host_id: int,
            conn: sqlite3.Connection = Depends(get_conn)) -> Response:
    """QR на ссылку одного хоста (или входа цепочки — тот же hosts.id)."""
    user = active_user(conn, token)
    if user is None:
        return Response(content=b"", media_type="image/svg+xml", status_code=404)
    row = conn.execute(
        f"""SELECT {HOST_FIELDS}, COALESCE(c.name, h.name) AS name, n.address AS node_address
           FROM hosts h JOIN nodes n ON n.id = h.node_id LEFT JOIN chains c ON c.id = h.chain_id
           WHERE h.id = ?""", (host_id,)).fetchone()
    if row is None or row["protocol"] != "vless":
        return Response(content=b"", media_type="image/svg+xml", status_code=404)
    return qr_svg(subscription_link(user["token"], row))

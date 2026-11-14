"""Одно правило на весь панельный набор полей хоста и хопа цепочки.

У защиты и транспорта есть поля, которые к ним не относятся: sni у reality, маскированный
адрес у tls, путь у tcp. Молча проигнорировать их нельзя — человек решит, что настройка
работает, а Xray её просто не видит. Поэтому панель отвергает чужое поле `400` с тем же
текстом, что и в окне хоста, и делает это в одном месте: отсюда правилами пользуются и
обычные хосты (`routers/hosts.py`), и хопа цепочек (`routers/chains.py`).

Здесь же исключение для цепочки: свой сертификат хосту цепочки не выдаётся. Сертификат хопа
выпускает сама панель, потому что она обязана знать его отпечаток — именно его панель
закрепляет за соседней нодой (`pinnedPeerCertSha256`, Xray 26 не принимает самоподписанный
сертификат «на веру»). Файл, который панель не может прочитать, закрепить не даст никто.
"""
from __future__ import annotations

# поле -> защита/транспорт, которым оно принадлежит
SEC_FIELDS = {"dest": "reality", "serverNames": "reality", "sni": "tls",
              "certFile": "tls", "keyFile": "tls", "rejectUnknownSni": "tls"}
NET_FIELDS = {"path": "ws", "hostHeader": "ws", "serviceName": "grpc", "grpcAuthority": "grpc"}

TEXTS = {
    "fp": "отпечаток клиента работает только при шифровании (tls или reality)",
    "dest": "маскированный адрес — настройка reality, а не другой защиты",
    "serverNames": "список принимаемых sni — настройка reality, а не другой защиты",
    "sniFiles": "sni и файлы сертификатов — настройки tls, а не другой защиты",
    "rejectUnknownSni": "отношение к чужому SNI — настройка tls, а не другой защиты",
    "ws": "путь и Host-заголовок — настройки websocket, а не другого транспорта",
    "grpc": "имя сервиса и authority — настройки gRPC, а не другого транспорта",
    "hopCert": "сертификат хопа цепочки выпускает панель: она обязана знать его отпечаток, "
               "чтобы закрепить его за соседней нодой",
    "hy2Fp": "отпечаток клиента hy2-клиент называет сам (рукопожатие QUIC): панели тут "
             "не чем подставлять чужой hello",
}

TLS_FILE_FIELDS = ("sni", "certFile", "keyFile")
WS_FIELDS = ("path", "hostHeader")
GRPC_FIELDS = ("serviceName", "grpcAuthority")


def meaningful(model) -> set[str]:
    """Какие поля человек правда прислал: `None`, `""` и `False` — «ничего не сказал».

    Это нужно, чтобы GET -> PATCH не ловил отказ. Панель отдаёт хост и хопа со всеми
    деталями (пустыми, если человек их не называл), и правка часто отправляет тот же
    самый json обратно: «sni: ""» у reality-хопа — это не «чужое поле», это «ничего».
    Пустое значение и так значит «разумное по умолчанию» (так держатся хосты).
    """
    out = set()
    for name in getattr(model, "model_fields_set", set()):
        value = getattr(model, name, None)
        if value is None or value is False or value == "":
            continue
        out.add(name)
    return out


def fields_issue(security: str, network: str, provided: set[str], *, hop: bool = False,
                 protocol: str | None = None) -> str | None:
    """Первая претензия к набору полей, либо None. `provided` — какие поля человек прислал.

    `hop=True` добавляет правило про сертификаты: хосту цепочки их не разрешают, и текст
    объясняет почему (панель не знает отпечаток чужого файла, а закреплять надо именно его).
    """
    if "fp" in provided and security == "none":
        return TEXTS["fp"]
    if "fp" in provided and protocol == "hy2":
        return TEXTS["hy2Fp"]
    if hop and ("certFile" in provided or "keyFile" in provided):
        # для цепочки это не «поле чужой защиты», а поле, которого там быть не может вовсе
        return TEXTS["hopCert"]
    for field, owner in SEC_FIELDS.items():
        if field in provided and security != owner:
            # sni и файлы сертификатов — одна претензия на всю тройку: в окне хоста они
            # живут рядом, и человек присылает их вместе
            return TEXTS.get(field, TEXTS["sniFiles"])
    if any(f in provided for f in TLS_FILE_FIELDS) and security != "tls":
        return TEXTS["sniFiles"]
    if any(f in provided for f in WS_FIELDS) and network != "ws":
        return TEXTS["ws"]
    if any(f in provided for f in GRPC_FIELDS) and network != "grpc":
        return TEXTS["grpc"]
    return None


def belongs(field: str) -> str:
    """Для чего поле нужно: подсказка в интерфейсе и текст отказа держатся вместе."""
    if field in SEC_FIELDS:
        return SEC_FIELDS[field]
    return NET_FIELDS.get(field, "")

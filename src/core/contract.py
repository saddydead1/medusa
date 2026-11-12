"""Контракт обмена панели и ноды.

Один файл на двоих: панель описывает им этими моделями запросы, нода — ответы.
Разъехаться они могут только вместе, что и нужно монолиту.

Порядок такой: нода поднимается на своём порту, один раз громко печатает свой API-ключ,
администратор переносит его в панель. Дальше панель ходит на ноду сама:
сначала `GET /node/health` (он без ключа — чтобы отличить «нода не отвечает» от
«API-ключ не подходит»), потом защищённые эндпоинты с `Authorization: Bearer <API-ключ>`.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

API_VERSION = "1"
NODE_API_PREFIX = "/node"
NODE_ROLE = "medusa-node"

HEADER_AUTHORIZATION = "Authorization"
BEARER_PREFIX = "Bearer "

PATH_HEALTH = f"{NODE_API_PREFIX}/health"       # без ключа
PATH_IDENTITY = f"{NODE_API_PREFIX}/identity"   # по ключу
PATH_STATUS = f"{NODE_API_PREFIX}/status"       # по ключу
PATH_CONFIG = f"{NODE_API_PREFIX}/config"       # по ключу: применить конфиг

STATUS_OK = "ok"


class NodeHealth(BaseModel):
    """Витрина ноды: её видно и без ключа, но по ней нельзя ничего сделать.

    Имени у ноды нет: имя даёт панели человек, а ноду опознаёт API-ключ по отпечатку.
    `role` нужен, чтобы по этому порту не обмануться: если там сидит не Medusa-нода,
    контракт не сойдётся.
    """

    status: Literal["ok"] = STATUS_OK
    role: Literal["medusa-node"] = NODE_ROLE
    apiVersion: str = API_VERSION
    agentVersion: str
    fingerprint: str = Field(description="отпечаток ключа ноды, сам ключ не отдаётся никогда")
    uptimeMs: int = Field(ge=0)


class NodeIdentity(BaseModel):
    """Кто я такой — отдаётся только предъявителю правильного API-ключа."""

    role: Literal["medusa-node"] = NODE_ROLE
    fingerprint: str
    agentVersion: str
    apiVersion: str = API_VERSION
    xrayVersion: str | None = None
    startedAt: int
    uptimeMs: int


class NodeConfigApply(BaseModel):
    """Конфиг Xray для этой ноды, собранный панелью.

    `revision` — счётчик панели: нода помнит, какой ревизией она отвечает, и повтор
    того же ревизии не переподнимает инбаунды. `config` для панели непрозрачен:
    его собирает `src/core/xray_config`, нода проверяет его самим Xray.
    `certs` — подсказка ноде, какие tls-сертификаты нужны этому конфигу
    (path -> адрес, для которого сертификат выпустить, если его ещё нет).
    """

    revision: int = Field(ge=1)
    config: dict
    certs: list[dict] = Field(default_factory=list,
                              description="[{file, key, host, certificate?, privateKey?}] tls-сертификаты "
                                          "до применения: без PEM нода выпускает self-signed сама, с PEM "
                                          "кладёт то, что выпустила панель (хопа цепочек)")


class NodeApplyReport(BaseModel):
    """Что нода сделала с конфигом: применён ли, каким ревизией и что сломалось."""

    role: Literal["medusa-node"] = NODE_ROLE
    fingerprint: str
    ok: bool
    desiredRev: int
    appliedRev: int
    lastApplyAt: int
    xrayVersion: str | None = None
    error: str | None = None


class UserTraffic(BaseModel):
    """Трафик одной метки Xray на этой ноде.

    Метку придумала панель (`u<id пользователя` — подписчик, `hop<цепочка>-<номер>` —
    переход цепочки): по ней панель и узнаёт, чей это трафик. Нода, которая видит метку
    в своём конфиге, не узнаёт из неё ничего лишнего — uuid и пароли ей выдаются, чтобы
    поднять инбаунд.
    """

    email: str = Field(description="метка Xray: u<id> подписчика или hop<цепочка>-<номер>")
    bytes: int = Field(ge=0, description="накоплено на этой ноде (uplink + downlink)")


class NodeStatus(BaseModel):
    """Состояние ноды: ревизии конфига, её собственный счётчик трафика и всё, что нода
    знает о себе на самом деле."""

    role: Literal["medusa-node"] = NODE_ROLE
    fingerprint: str
    agentVersion: str
    apiVersion: str = API_VERSION
    xrayVersion: str | None = None
    desiredRev: int = 0
    appliedRev: int = 0
    lastApplyAt: int | None = None
    lastError: str | None = None
    uptimeMs: int
    # --- трафик, который нода насчитала сама (см. src/node/traffic.py) -------------
    # trafficBytes — всё, что провела эта нода: и подписчиков, и транзит цепочек.
    # Трафик перехода цепочки считается на ноде и ни одному человеку не приписывается.
    trafficBytes: int = Field(ge=0, default=0)
    userTraffic: list[UserTraffic] = Field(default_factory=list)
    statsAt: int = 0
    statsPort: int | None = None
    statsError: str | None = None

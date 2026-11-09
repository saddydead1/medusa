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


class NodeStatus(BaseModel):
    """Состояние ноды. Применения конфига ещё нет — отсюда поля-заглушки,
    но уже честные: нода сообщает то, что знает про себя на самом деле."""

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

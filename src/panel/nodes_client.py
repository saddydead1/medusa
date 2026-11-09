"""Клиент API ноды: панель ходит к ноде сама, нода к панели не приходит.

Нода отвечает на своём порту (`nodes.api_port`), адрес берётся из `nodes.address`.
API-ключ панель берёт из `nodes.api_key` — когда-то его создала сама нода.

Здесь два разных отказа, и путать их нельзя:
* `NodeUnreachable` — нода не ответила (порт закрыт, адрес протух, таймаут);
* `NodeUnauthorized` — нода ответила, но API-ключ не подходит.
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx

from src.core.contract import (
    BEARER_PREFIX,
    PATH_HEALTH,
    PATH_IDENTITY,
    PATH_STATUS,
    NodeHealth,
    NodeIdentity,
    NodeStatus,
)


class NodeError(Exception):
    """Любой отказ ноды: сообщение идёт человеку, поэтому оно по-русски и без «HTTP 500». """


class NodeUnreachable(NodeError):
    pass


class NodeUnauthorized(NodeError):
    pass


@dataclass(frozen=True)
class NodeTarget:
    address: str
    port: int
    api_key: str | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self.address}:{self.port}"

    @property
    def configured(self) -> bool:
        return bool(self.api_key)


def _get(target: NodeTarget, path: str, timeout: float, auth: bool) -> dict:
    headers = {"Authorization": f"{BEARER_PREFIX}{target.api_key}"} if auth and target.api_key else {}
    try:
        response = httpx.get(target.base_url + path, headers=headers, timeout=timeout)
    except httpx.HTTPError as err:
        raise NodeUnreachable(f"нода {target.address}:{target.port} не ответила: {err.__class__.__name__}") from err

    if response.status_code == 401:
        raise NodeUnauthorized(detail_of(response) or "нода отвергла API-ключ")
    if response.status_code == 404:
        raise NodeUnreachable("нода отвечает, но /node/... у неё нет — похоже, нода старше панели")
    if response.status_code >= 400:
        raise NodeUnreachable(f"нода ответила {response.status_code}: {detail_of(response)}")
    try:
        return response.json()
    except ValueError as err:
        raise NodeUnreachable("нода ответила не JSON") from err


def detail_of(response: httpx.Response) -> str:
    try:
        detail = response.json().get("detail")
    except ValueError:
        return ""
    return str(detail)


def node_health(target: NodeTarget, timeout: float = 5.0) -> NodeHealth:
    return NodeHealth.model_validate(_get(target, PATH_HEALTH, timeout, auth=False))


def node_identity(target: NodeTarget, timeout: float = 5.0) -> NodeIdentity:
    return NodeIdentity.model_validate(_get(target, PATH_IDENTITY, timeout, auth=True))


def node_status(target: NodeTarget, timeout: float = 5.0) -> NodeStatus:
    """Панель пока его не зовёт: он понадобится, когда нода начнёт применять конфиг
    (там же появятся `desiredRev`/`appliedRev`). Держим его здесь, а не «потом придумаем»:
    путь и форма ответа уже зафиксированы контрактом.
    """
    return NodeStatus.model_validate(_get(target, PATH_STATUS, timeout, auth=True))

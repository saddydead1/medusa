"""Клиент API ноды: панель ходит к ноде сама, нода к панели не приходит.

Нода отвечает на своём порту (`nodes.api_port`), адрес берётся из `nodes.address`.
API-ключ панель берёт из `nodes.api_key` — когда-то его создала сама нода.
Если у ноды вписан socks5-прокси (`nodes.api_proxy`) — панель идёт через него: нода может
сидеть за NAT или быть доступна только через прыжок.

Здесь три разных отказа, и путать их нельзя:
* `NodeUnreachable` — нода не ответила (порт закрыт, адрес протух, таймаут);
* `NodeUnreachable` с другим текстом — не ответил прокси: человек обязан видеть, что
  встал не сам Xray, а путь до него;
* `NodeUnauthorized` — нода ответила, но API-ключ не подходит.
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx

from src.panel.proxy_url import mask_proxy
from src.core.contract import (
    BEARER_PREFIX,
    PATH_CONFIG,
    PATH_HEALTH,
    PATH_IDENTITY,
    PATH_STATUS,
    NodeApplyReport,
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
    proxy: str | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self.address}:{self.port}"

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    @property
    def via(self) -> str:
        """Человеческое «откуда мы стучимся»: адрес ноды, плюс прокси если он есть."""
        return f"{self.address}:{self.port} через прокси {mask_proxy(self.proxy or '')}" \
            if self.proxy else f"{self.address}:{self.port}"


def _client(target: NodeTarget, timeout: float) -> httpx.Client:
    """httpx понимает socks5:// и socks5h://; без прокси клиент самый обычный."""
    kwargs: dict = {"timeout": timeout}
    if target.proxy:
        kwargs["proxy"] = target.proxy
    return httpx.Client(**kwargs)


def _unreachable(target: NodeTarget, err: httpx.HTTPError) -> NodeUnreachable:
    """Отказ обязан называть то, что действительно встало: саму ноду или путь до неё.
    Иначе человек будет чинить Xray на ноде, которая тут ни при чём.
    """
    if isinstance(err, httpx.ProxyError):
        return NodeUnreachable(f"прокси {mask_proxy(target.proxy or '')} не пустил к ноде "
                               f"{target.address}:{target.port}: {err}")
    if target.proxy:
        return NodeUnreachable(f"нода {target.address}:{target.port} не ответила: панель идёт через "
                               f"прокси {mask_proxy(target.proxy)}, и он не отвечает "
                               f"({err.__class__.__name__})")
    return NodeUnreachable(f"нода {target.address}:{target.port} не ответила: {err.__class__.__name__}")


def _get(target: NodeTarget, path: str, timeout: float, auth: bool) -> dict:
    headers = {"Authorization": f"{BEARER_PREFIX}{target.api_key}"} if auth and target.api_key else {}
    try:
        with _client(target, timeout) as client:
            response = client.get(target.base_url + path, headers=headers)
    except httpx.HTTPError as err:
        raise _unreachable(target, err) from err

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


def node_apply(target: NodeTarget, revision: int, config: dict, certs: list[dict],
               timeout: float = 15.0) -> NodeApplyReport:
    """Применить конфиг Xray. Отказ ноды (`ok: false` с человеческой ошибкой) —
    это тоже успешный HTTP-ответ: панель узнаёт о проблеме из отчёта, а не из кода.
    """
    headers = {"Authorization": f"{BEARER_PREFIX}{target.api_key}"}
    payload = {"revision": revision, "config": config, "certs": certs}
    try:
        with _client(target, timeout) as client:
            response = client.put(target.base_url + PATH_CONFIG, json=payload, headers=headers)
    except httpx.HTTPError as err:
        raise _unreachable(target, err) from err
    if response.status_code == 401:
        raise NodeUnauthorized(detail_of(response) or "нода отвергла API-ключ")
    if response.status_code >= 400:
        raise NodeUnreachable(f"нода ответила {response.status_code}: {detail_of(response)}")
    try:
        return NodeApplyReport.model_validate(response.json())
    except ValueError as err:
        raise NodeUnreachable("нода ответила по applied не JSON") from err


def node_identity(target: NodeTarget, timeout: float = 5.0) -> NodeIdentity:
    return NodeIdentity.model_validate(_get(target, PATH_IDENTITY, timeout, auth=True))


def node_status(target: NodeTarget, timeout: float = 5.0) -> NodeStatus:
    """Панель пока его не зовёт: он понадобится, когда нода начнёт применять конфиг
    (там же появятся `desiredRev`/`appliedRev`). Держим его здесь, а не «потом придумаем»:
    путь и форма ответа уже зафиксированы контрактом.
    """
    return NodeStatus.model_validate(_get(target, PATH_STATUS, timeout, auth=True))

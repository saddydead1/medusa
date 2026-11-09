"""Проверка API-ключа ноды: кто к ней пришёл и пускать ли его внутрь.

Ключ знают только нода и панель. Сравнение — за постоянное время, чтобы по длительности
ответа нельзя было подбирать ключ.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.core.contract import BEARER_PREFIX
from src.core.api_keys import keys_match
from src.node.identity import NodeIdentity

bearer_scheme = HTTPBearer(auto_error=False, description="API-ключ ноды, выданный самой нодой")


def identity_of(request: Request) -> NodeIdentity:
    identity = getattr(request.app.state, "node_identity", None)
    if identity is None:
        raise HTTPException(status_code=503, detail="нода ещё не прочитала своё состояние")
    return identity


def require_node_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> NodeIdentity:
    identity = identity_of(request)
    presented = _presented_key(request, credentials)
    if not presented:
        raise _unauthorized("нужен API-ключ ноды: Authorization: Bearer <ключ>")
    if not keys_match(presented, identity.api_key):
        raise _unauthorized("API-ключ ноды не подходит")
    return identity


def _presented_key(request: Request, credentials: HTTPAuthorizationCredentials | None) -> str:
    """Разбираем заголовок сами, не полагаясь на форму HTTPBearer.

    `HTTPBearer` принимает токен только «безопасного» алфавита. Если администратор задал
    `MEDUSA_NODE_API_KEY` с символом вне его (`:`, `!`), правильный ключ был бы отвергнут
    до всякой проверки. Поэтому читаем заголовок как есть.
    """
    if credentials and credentials.scheme.lower() == "bearer":
        return credentials.credentials.strip()
    header = request.headers.get("authorization", "")
    if header.lower().startswith(BEARER_PREFIX.lower()):
        return header[len(BEARER_PREFIX):].strip()
    return ""


def _unauthorized(message: str) -> HTTPException:
    return HTTPException(status_code=401, detail=message, headers={"WWW-Authenticate": "Bearer"})

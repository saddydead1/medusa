"""API ноды. Витрина `/node/health` открыта и без ключа, всё остальное — по API-ключу."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from src.core.contract import (
    API_VERSION,
    NODE_API_PREFIX,
    NODE_ROLE,
    NodeApplyReport,
    NodeConfigApply,
    NodeHealth,
    NodeIdentity as IdentityPayload,
    NodeStatus,
    UserTraffic,
)
from src.core.version import project_version
from src.node.deps import identity_of, require_node_key
from src.node.identity import NodeIdentity, now_ms
from src.node.xray import xray_version

router = APIRouter(prefix=NODE_API_PREFIX, tags=["node"])


@router.get("/health", response_model=NodeHealth)
def health(request: Request) -> NodeHealth:
    """Витрина без ключа: по ней панель различает «нода не отвечает» и «API-ключ не подходит».

    Отпечаток ключа здесь есть, сам ключ — никогда.
    """
    identity = identity_of(request)
    return NodeHealth(
        agentVersion=project_version(),
        fingerprint=identity.fingerprint,
        uptimeMs=identity.uptime_ms,
    )


@router.get("/identity", response_model=IdentityPayload)
def identity(request: Request, node: NodeIdentity = Depends(require_node_key)) -> IdentityPayload:
    """Кто этот узел на самом деле: проверка, что API-ключ в панели — от этой же ноды."""
    config = request.app.state.node_config
    return IdentityPayload(
        fingerprint=node.fingerprint,
        agentVersion=project_version(),
        apiVersion=API_VERSION,
        xrayVersion=xray_version(config),
        startedAt=node.started_at,
        uptimeMs=node.uptime_ms,
    )


@router.get("/status", response_model=NodeStatus)
def status(request: Request, node: NodeIdentity = Depends(require_node_key)) -> NodeStatus:
    """Что нода помнит о себе. Ревизии настоящие: их двигает применение конфига, а
    трафик нода снимает с Xray прямо перед ответом. Перед ответом раннер проверяет, жив ли
    процесс Xray: мёртвый процесс не должен прятаться за «применено».
    """
    config = request.app.state.node_config
    runner = getattr(request.app.state, "xray_runner", None)
    if runner is not None:
        runner.note_process_state()
    # Здесь счётчики снимаются ради панели (`/node/status` — единственный путь, которым она
    # узнаёт про трафик). Кроме этого нода делает то же самое сама по кругу и перед всякой
    # остановкой Xray: счётчики живут в памяти процесса Xray и сами по себе не переживают
    # перезапуск, см. `src/node/traffic.py`.
    ledger = getattr(request.app.state, "traffic_ledger", None)
    traffic = ledger.read() if ledger is not None else None
    return NodeStatus(
        fingerprint=node.fingerprint,
        agentVersion=project_version(),
        apiVersion=API_VERSION,
        xrayVersion=xray_version(config),
        desiredRev=node.desired_rev,
        appliedRev=node.applied_rev,
        lastApplyAt=node.last_apply_at,
        lastError=node.last_error,
        uptimeMs=node.uptime_ms,
        trafficBytes=traffic.trafficBytes if traffic else 0,
        userTraffic=[UserTraffic.model_validate(item) for item in
                     (traffic.userTraffic if traffic else [])],
        statsAt=traffic.statsAt if traffic else 0,
        statsPort=runner.stats_port if runner is not None else None,
        statsError=traffic.statsError if traffic else "нода ещё не подняла раннер xray",
    )


@router.put("/config", response_model=NodeApplyReport)
def apply_config(body: NodeConfigApply, request: Request,
                 node: NodeIdentity = Depends(require_node_key)) -> NodeApplyReport:
    """Применить конфиг Xray, собранный панелью. Отказ — тоже ответ: `ok: false`
    и человеческая ошибка, а не HTTP-исключение: панель записывает его в строку ноды."""
    runner = getattr(request.app.state, "xray_runner", None)
    if runner is None:
        raise HTTPException(status_code=503, detail="нода ещё не подняла раннер xray")
    return runner.apply(body.revision, body.config, body.certs)


@router.get("", include_in_schema=False)
def index(request: Request) -> dict:
    """Ответ на «а что тут вообще живёт» в браузере."""
    identity = identity_of(request)
    return {
        "role": NODE_ROLE,
        "apiVersion": API_VERSION,
        "agentVersion": project_version(),
        "fingerprint": identity.fingerprint,
        "endpoints": ["/node/health", "/node/identity", "/node/status", "/node/config"],
        "checkedAt": now_ms(),
    }

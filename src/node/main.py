"""Сборка приложения ноды.

Запуск:
    uv run medusa-node                       # прочитает MEDUSA_NODE_* из окружения
    uv run fastapi dev src/node/main.py      # то же самое, через fastapi-cli
    uvicorn src.node.main:app --host 0.0.0.0 --port 9443
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.core.version import project_version
from src.core.contract import NODE_ROLE
from src.node.api import router
from src.node.config import NodeConfig
from src.node.identity import load_identity
from src.node.runner import XrayRunner
from src.node.traffic import TrafficLedger, self_poll
from src.node.xray import resolve_xray_bin


def create_app(config: NodeConfig | None = None) -> FastAPI:
    settings = config or NodeConfig.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        identity = load_identity(settings)
        app.state.node_identity = identity
        runner = XrayRunner(settings, identity)
        app.state.xray_runner = runner
        # ledger живёт рядом с раннером: он копит счётчики в том же файле состояния
        ledger = TrafficLedger(settings, identity, runner)
        runner.ledger = ledger
        app.state.traffic_ledger = ledger
        # нода снимает счётчики и сама, не дожидаясь панели: Xray хранит их в памяти
        # своего процесса, и ждать панели, чтобы их не потерять, — плохая идея
        stats_stop = asyncio.Event()
        stats_task = asyncio.create_task(self_poll(ledger, stats_stop))
        xray_bin = resolve_xray_bin(settings)
        print(
            f"[medusa-node] API http://{settings.host}:{settings.port}{router.prefix}/health, "
            f"отпечаток API-ключа {identity.fingerprint} (источник: {identity.key_source})",
            flush=True,
        )
        print(
            f"[medusa-node] xray: {xray_bin or 'не найден — MEDUSA_XRAY_BIN или PATH'}",
            flush=True,
        )
        runner.autostart()
        yield
        stats_stop.set()
        stats_task.cancel()
        runner.harvest()            # последний снимок: то, что наработало после последнего круга
        runner.shutdown()
        app.state.xray_runner = None
        app.state.traffic_ledger = None
        app.state.node_identity = None

    app = FastAPI(
        title="Medusa node",
        version=project_version(),
        lifespan=lifespan,
        docs_url="/node/docs",
        openapi_url="/node/openapi.json",
    )
    app.state.node_config = settings
    app.state.node_identity = None
    app.include_router(router)

    @app.get("/", include_in_schema=False)
    def root():
        return {"role": NODE_ROLE, "api": f"{router.prefix}/health", "docs": "/node/docs"}

    return app


app = create_app()

import asyncio
import sqlite3
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.staticfiles import StaticFiles

from src.panel.db import DB_PATH, init_db
from src.panel.deps import current_admin
from src.panel.meta import STATIC_DIR, project_meta
from src.panel import poller
from src.panel.routers import admins, chains, hosts, nodes, settings, subs, users
from src.panel.system import system_info


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Схема, настройки и владелец создаются при старте панели, вместе с опросом нод."""
    init_db()
    print(f"[medusa] база: {DB_PATH}", flush=True)
    stop = asyncio.Event()
    task = None
    if poller.enabled():
        task = asyncio.create_task(poller.poll_loop(stop))
        print("[medusa] опрос нод: включён (MEDUSA_NODE_AUTO=0 — выключить)", flush=True)
    else:
        print("[medusa] опрос нод: выключён (MEDUSA_NODE_AUTO=0)", flush=True)
    yield
    stop.set()
    if task is not None:
        await task


app = FastAPI(title="Medusa", lifespan=lifespan)

# Вход и выход — единственные эндпоинты, доступные без сессии. Всё остальное требует
# вошедшего администратора: без учётки панель упирается в 401, правка — в writer-проверку.
auth_needed = [Depends(current_admin)]

app.include_router(admins.auth_router)
app.include_router(admins.router, dependencies=auth_needed)
app.include_router(users.router, dependencies=auth_needed)
app.include_router(nodes.router, dependencies=auth_needed)
app.include_router(hosts.router, dependencies=auth_needed)
app.include_router(chains.router, dependencies=auth_needed)
app.include_router(settings.router, dependencies=auth_needed)

# Страница подписки: входа администратора не требует — пропуск это сам токен
# пользователя в адресе. Отдаётся до статики, иначе catch-all съест /sub/...
app.include_router(subs.router)


@app.get("/api/meta")
def api_meta() -> dict[str, str]:
    """Версия панели — она берётся из pyproject.toml."""
    return project_meta()


@app.get("/api/system")
def api_system(_: sqlite3.Row | None = Depends(current_admin)) -> dict:
    """Метрики сервера: ЦП, память, диски, uptime.

    Обычный def (не async): внутри есть короткий сэмпл /proc/stat и вызовы statvfs,
    FastAPI выполнит это в threadpool и не заблокирует event loop.
    """
    return system_info(db_path=DB_PATH)


# Статика монтируется последним — так /api/... не перекрывается catch-all'ом.
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")

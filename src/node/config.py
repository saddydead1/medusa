"""Настройки агента ноды: только окружение и аргументы запуска, никакой базы панели.

Панель настраивается своими переменными (`MEDUSA_DB`, `MEDUSA_ADMIN_*`), нода —
своими (`MEDUSA_NODE_*`). Пересечения нет намеренно: контейнер ноды не должен
случайно начать читать настройки панели.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 9443            # отдельный порт API ноды; клиентские порты Xray его не касаются
DEFAULT_STATE = ROOT / "data" / "node" / "state.json"
DEFAULT_XRAY_BIN = "xray"


def env_path(name: str, default: Path) -> Path:
    raw = os.getenv(name)
    return Path(raw).expanduser() if raw else default


def env_port(name: str, default: int) -> int:
    raw = os.getenv(name)
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


@dataclass
class NodeConfig:
    """Что нужно ноде, чтобы запуститься. Всё приходит извне: env или флаги CLI."""

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    state_path: Path = field(default_factory=lambda: DEFAULT_STATE)
    api_key: str | None = None
    xray_bin: str | None = None

    @classmethod
    def from_env(cls) -> "NodeConfig":
        return cls(
            host=os.getenv("MEDUSA_NODE_HOST", DEFAULT_HOST),
            port=env_port("MEDUSA_NODE_PORT", DEFAULT_PORT),
            state_path=env_path("MEDUSA_NODE_STATE", DEFAULT_STATE),
            api_key=os.getenv("MEDUSA_NODE_API_KEY") or None,
            xray_bin=os.getenv("MEDUSA_XRAY_BIN") or None,
        )

    @property
    def api_url(self) -> str:
        host = self.host if self.host not in ("0.0.0.0", "::") else "127.0.0.1"
        return f"http://{host}:{self.port}"

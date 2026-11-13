"""Запуск панели: `medusa-panel`.

    medusa-panel                       # http://127.0.0.1:8000 с перезагрузкой на правках
    medusa-panel --host 0.0.0.0 --no-reload
    MEDUSA_PANEL_PORT=8080 medusa-panel --no-reload      # порт (и адрес) можно окружением

Флаг перекрывает переменную окружения: `--port` важнее `MEDUSA_PANEL_PORT`. Нужено это для
Docker: образ не должен прикиваться параметрами запуска, чтобы порт менялся одной строкой
в compose.
"""
from __future__ import annotations

import argparse
import os
import sys

import uvicorn

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000


def _env_port() -> int:
    raw = os.getenv("MEDUSA_PANEL_PORT", "")
    try:
        port = int(raw)
    except ValueError:
        return DEFAULT_PORT
    if not 1 <= port <= 65535:
        raise SystemExit(f"MEDUSA_PANEL_PORT: порт {raw!r} вне диапазона 1..65535")
    return port


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="medusa-panel", description="панель Medusa")
    parser.add_argument("--host", default=os.getenv("MEDUSA_PANEL_HOST") or DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=_env_port())
    parser.add_argument("--db", help="путь к базе (MEDUSA_DB)")
    parser.add_argument("--demo", action="store_true", help="наполнить базу демо-данными (MEDUSA_DEMO=1)")
    parser.add_argument("--no-reload", action="store_true", help="не перезагружать сервер на правках кода")
    args = parser.parse_args(argv)

    if args.db:
        os.environ["MEDUSA_DB"] = args.db
    if args.demo:
        os.environ["MEDUSA_DEMO"] = "1"

    uvicorn.run("src.panel.main:app", host=args.host, port=args.port, reload=not args.no_reload)
    return 0


if __name__ == "__main__":
    sys.exit(main())

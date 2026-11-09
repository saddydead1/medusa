"""Запуск ноды: `medusa-node`.

    medusa-node --port 9443                     # API-ключ создаст сам и печатает его в лог
    medusa-node --print-api-key               # вспомнить API-ключ существующей ноды

Флаги перекрывают переменные окружения; и то и другое уходит в окружение uvicorn, чтобы
`src.node.main:app` собрался ровно с этими настройками.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from src.core.api_keys import mask_api_key
from src.node.config import NodeConfig


def parse(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="medusa-node", description="агент ноды Medusa")
    parser.add_argument("--host", help="адрес, на котором слушать API (MEDUSA_NODE_HOST)")
    parser.add_argument("--port", type=int, help="порт API ноды (MEDUSA_NODE_PORT)")
    parser.add_argument("--state", help="файл состояния ноды (MEDUSA_NODE_STATE)")
    parser.add_argument("--api-key", help="готовый API-ключ вместо создаваемого (MEDUSA_NODE_API_KEY)")
    parser.add_argument("--xray-bin", help="путь к бинарнику xray (MEDUSA_XRAY_BIN)")
    parser.add_argument("--print-api-key", action="store_true", help="показать API-ключ ноды и выйти")
    return parser.parse_args(argv)


def build_config(argv: list[str] | None = None) -> tuple[NodeConfig, argparse.Namespace]:
    args = parse(argv)
    config = NodeConfig.from_env()
    for flag, attribute in (("host", "host"), ("port", "port"),
                            ("api_key", "api_key"), ("xray_bin", "xray_bin")):
        value = getattr(args, flag)
        if value is not None:
            setattr(config, attribute, value)
    if args.state:
        config.state_path = Path(args.state).expanduser()
    return config, args


def main(argv: list[str] | None = None) -> int:
    config, args = build_config(argv)

    if args.print_api_key:
        from src.node.identity import load_identity

        identity = load_identity(config)
        print(f"файл состояния: {config.state_path}")
        print(f"отпечаток: {identity.fingerprint}")
        print(f"API-ключ (его нужно ввести в панели): {identity.api_key}")
        print(f"в списках и логах он показывается как {mask_api_key(identity.api_key)}")
        return 0

    from src.node.identity import load_identity

    print(f"[medusa-node] API-ключ для панели: {mask_api_key(load_identity(config).api_key)}", flush=True)

    import uvicorn

    uvicorn.run("src.node.main:app", host=config.host, port=config.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())

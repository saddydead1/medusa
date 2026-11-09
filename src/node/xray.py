"""Xray на ноде: пока только находим бинарник и его версию.

Поднять инбаунды и применять конфиг будет другой слой (`src/node/runner.py`, когда
появится рендер конфига в `src/core`). Здесь — честно только то, что нода знает сама:
есть ли Xray и какой он версии.
"""
from __future__ import annotations

import os
import shutil
import re
import subprocess
from functools import lru_cache

from src.node.config import DEFAULT_XRAY_BIN, NodeConfig

# версия в выводе xray — число с точкой сразу после слова Xray
VERSION_RE = re.compile(r"xray\s+(\d[\w.\-]*)", re.IGNORECASE)


def resolve_xray_bin(config: NodeConfig) -> str | None:
    candidate = config.xray_bin or DEFAULT_XRAY_BIN
    if "/" in candidate:                       # задан путь явно — проверяем его сами
        return candidate if _executable(candidate) else shutil.which(candidate)
    return shutil.which(candidate)


def _executable(path: str) -> bool:
    """Путь с косой чертой проверяем сам: `which` чужие директории не видит."""
    return os.access(path, os.X_OK)


@lru_cache(maxsize=4)
def _version_of(bin_path: str) -> str | None:
    try:
        out = subprocess.run([bin_path, "version"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    # `xray version` печатает длинную строку вида
    # «Xray 25.8.3 (Xray, Penetrates Everything.) 4d0a3c1 (go1.25.6 linux_amd64)»
    text = f"{out.stdout or ''}\n{out.stderr or ''}"
    found = VERSION_RE.search(text)
    return found.group(1) if found else None


def xray_version(config: NodeConfig) -> str | None:
    bin_path = resolve_xray_bin(config)
    return _version_of(bin_path) if bin_path else None



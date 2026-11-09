"""Метаданные панели: версия читается из pyproject.toml."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"
STATIC_DIR = ROOT / "src" / "panel" / "static"

FALLBACK_VERSION = "0.0.0"


def project_meta() -> dict[str, str]:
    """Имя и версия проекта из pyproject.toml (без кэша — файл маленький, а версия должна
    совпадать с тем, что реально лежит в pyproject.toml)."""
    try:
        with PYPROJECT.open("rb") as fh:
            project = tomllib.load(fh).get("project", {})
    except (OSError, tomllib.TOMLDecodeError):
        return {"name": "medusa", "version": FALLBACK_VERSION}
    return {
        "name": str(project.get("name") or "medusa"),
        "version": str(project.get("version") or FALLBACK_VERSION),
    }

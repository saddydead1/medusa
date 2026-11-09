"""Версия проекта: читается из pyproject.toml и одна на панель, и на ноду.

Нода сообщает свою версию панели, поэтому версия должна браться из того же
`pyproject.toml`, что и панель, — иначе в монолите версии разъедутся.
"""
from __future__ import annotations

import tomllib
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"

FALLBACK_NAME = "medusa"
FALLBACK_VERSION = "0.0.0"


@lru_cache(maxsize=1)
def project_meta() -> dict[str, str]:
    try:
        with PYPROJECT.open("rb") as fh:
            project = tomllib.load(fh).get("project", {})
    except (OSError, tomllib.TOMLDecodeError):
        return {"name": FALLBACK_NAME, "version": FALLBACK_VERSION}
    return {
        "name": str(project.get("name") or FALLBACK_NAME),
        "version": str(project.get("version") or FALLBACK_VERSION),
    }


def project_version() -> str:
    return project_meta()["version"]


def project_name() -> str:
    return project_meta()["name"]

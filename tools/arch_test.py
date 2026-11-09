"""Границы монолита: панель не знает про ноду, нода не знает про панель, ядро не знает ни про кого.

Смысл не в красоте, а в контейнерах: в образ ноды не уедет код панели вместе с её
базой и паролями, и наоборот. Проверяем импорты через AST — это ближе к правде,
чем поиск по тексту.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

FORBIDDEN = {
    "panel": {"src.node"},          # панель говорит с нодой только по HTTP
    "node": {"src.panel"},          # нода не читает базу панели и не знает её маршрутов
    "core": {"src.panel", "src.node"},  # ядро импортируют обе стороны, оно ни на кого не смотрит
}

FAILS = 0


def ok(cond: object, message: str) -> None:
    global FAILS
    print(("PASS  " if cond else "FAIL  ") + message)
    if not cond:
        FAILS += 1


def top_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        for name in names:
            parts = name.split(".")
            found.add(".".join(parts[:2]) if len(parts) > 1 else parts[0])
    return found


def main() -> int:
    for side, forbidden in FORBIDDEN.items():
        folder = SRC / side
        files = sorted(folder.rglob("*.py"))
        ok(files, f"{side}: {len(files)} файлов найдено")
        offenders = []
        for path in files:
            hits = {m for m in top_modules(path) if m in forbidden}
            if hits:
                offenders.append(f"{path.relative_to(ROOT)} -> {', '.join(sorted(hits))}")
        ok(not offenders, f"{side} не импортирует {', '.join(sorted(forbidden))}"
           + (f": {len(offenders)} нарушений" if offenders else ""))
        for line in offenders:
            print("      " + line)

    # общий обмен описан в одном месте: и панель, и нода берут пути из ядра
    panel_paths = {m for f in (SRC / "panel").rglob("*.py") for m in top_modules(f) if m == "src.core"}
    node_paths = {m for f in (SRC / "node").rglob("*.py") for m in top_modules(f) if m == "src.core"}
    ok(panel_paths and node_paths, f"ядро используют обе стороны: панель {sorted(panel_paths)}, нода {sorted(node_paths)}")

    print()
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())

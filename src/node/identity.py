"""Ключ и состояние ноды: что нода помнит о себе между перезапусками.

Файл состояния (`MEDUSA_NODE_STATE`, по умолчанию `data/node/state.json`, права 0600)
принадлежит ноде: в ней её API-ключ и последние применённые ревизии. API-ключ создаётся
один раз и громко печатается в лог при первом запуске — его нужно перенести в панель.

`MEDUSA_NODE_API_KEY` перебивает файл: так можно зафиксировать ключ (секретом в
оркестраторе) или заменить его, не трогая остальное состояние.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from src.core.api_keys import API_KEY_PREFIX, api_key_fingerprint, looks_like_api_key, new_api_key
from src.node.config import NodeConfig

STATE_VERSION = 3

# API-ключ при первом запуске должен бросаться в глаза: его нужно скопировать в панель,
# а лог к тому моменту уже успевает закрыться служебными строками uvicorn.
API_KEY_BANNER = """
+--------------------------------------------------------------+
|  API-КЛЮЧ НОДЫ — введите его в панели при добавлении ноды   |
+--------------------------------------------------------------+
|  {key}
|
|  отпечаток: {fp}
|  сохранён:  {path} (права 0600)
|  вспомнить: medusa-node --print-api-key
+--------------------------------------------------------------+
"""


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class NodeIdentity:
    api_key: str
    fingerprint: str
    created_at: int
    state_path: Path
    desired_rev: int = 0
    applied_rev: int = 0
    last_apply_at: int | None = None
    last_error: str | None = None
    started_at: int = field(default_factory=now_ms)
    key_source: str = "state"          # state | env | generated
    # --- трафик, который нода посчитала сама -------------------------------------
    # Счётчики Xray живут в памяти его процесса: перезапуск ноды или новое применение
    # конфига обнуляют их. Поэтому нода снимает счётчики сброшенными (`-reset`: после
    # чтения у Xray остаётся ноль) и копит байты у себя — так трафик не теряется при
    # перезапуске и не считается дважды.
    traffic_bytes: int = 0                                       # по всем меткам, включая транзит
    user_traffic: dict[str, int] = field(default_factory=dict)   # метка -> накопленные байты
    stats_at: int = 0                                            # когда счётчики снимались последний раз
    stats_port: int | None = None                                # порт сервиса счётчиков (подбирает нода)

    @property
    def uptime_ms(self) -> int:
        return now_ms() - self.started_at


def _read(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, OSError) as err:
        print(f"[medusa-node] состояние {path} не прочитано ({err}); начинаю заново", flush=True)
        return {}


def save_identity(identity: NodeIdentity) -> None:
    """Атомарно: оборванная запись — это потерянный ключ, а половинчатое состояние хуже пустого."""
    path = identity.state_path
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    payload = {
        "version": STATE_VERSION,
        "apiKey": identity.api_key,
        "createdAt": identity.created_at,
        "desiredRev": identity.desired_rev,
        "appliedRev": identity.applied_rev,
        "lastApplyAt": identity.last_apply_at,
        "lastError": identity.last_error,
        "trafficBytes": identity.traffic_bytes,
        "userTraffic": identity.user_traffic,
        "statsAt": identity.stats_at,
        "statsPort": identity.stats_port,
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def load_identity(config: NodeConfig) -> NodeIdentity:
    stored = _read(config.state_path)
    created_at = int(stored.get("createdAt") or now_ms())

    if config.api_key:
        api_key, source = config.api_key, "env"
    elif stored.get("apiKey"):
        api_key, source = str(stored["apiKey"]), "state"
    else:
        api_key, source = new_api_key(), "generated"

    identity = NodeIdentity(
        api_key=api_key,
        fingerprint=api_key_fingerprint(api_key),
        created_at=created_at,
        state_path=config.state_path,
        desired_rev=int(stored.get("desiredRev") or 0),
        applied_rev=int(stored.get("appliedRev") or 0),
        last_apply_at=stored.get("lastApplyAt"),
        last_error=stored.get("lastError"),
        key_source=source,
        traffic_bytes=int(stored.get("trafficBytes") or 0),
        user_traffic={str(k): int(v) for k, v in (stored.get("userTraffic") or {}).items()
                      if isinstance(v, (int, float))},
        stats_at=int(stored.get("statsAt") or 0),
        stats_port=(int(stored["statsPort"]) if stored.get("statsPort") else None),
    )

    # env-ключ мог отличаться от записанного: фиксируем победителя, иначе после
    # перезапуска ноды панель окажется с ключом, который нода уже не принимает
    if str(stored.get("apiKey") or "") != api_key:
        save_identity(identity)

    if source == "generated":
        print(API_KEY_BANNER.format(key=api_key, path=config.state_path, fp=identity.fingerprint), flush=True)
    elif not looks_like_api_key(api_key):
        print(f"[medusa-node] внимание: API-ключ не похож на тот, что создаёт нода (ждём {API_KEY_PREFIX}…) — проверь MEDUSA_NODE_API_KEY", flush=True)

    return identity

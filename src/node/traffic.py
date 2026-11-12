"""Что нода знает о трафике: снимает счётчики с Xray и копит их у себя.

Xray считает трафик по подписчикам (у каждого клиента в конфиге есть метка `u<id>` или
`hop<цепочка>-<номер>`, см. `src/core/xray_config`), но держит эти счётчики в памяти
своего процесса: перезапуск ноды или новое применение конфига обнуляют их. Поэтому нода
читает счётчики сброшенными (`-reset`) и прибавляет их к своим накопленным итогам в файле
состояния — так трафик не теряется при перезапуске и не считается дважды.

Читает нода сама, через CLI того же Xray: `xray api statsquery -pattern=user>>> -reset`.
Своего gRPC-клиента поднимать незачем — бинарник на ноде уже есть, и ровно тем же
способом нода проверяет конфиг (`xray -test`).

Нулевые метки (счётчик завёлся, но по нему ничего не прошло) в состояние не пишутся:
их бывает столько же, сколько подписчиков, и хранить нули смысла нет.
"""
from __future__ import annotations

import json
import subprocess
import threading
from dataclasses import dataclass
from typing import Any

from src.node.config import NodeConfig
from src.node.identity import NodeIdentity, now_ms, save_identity
from src.node.xray import resolve_xray_bin

# имя счётчика Xray: user>>><метка>>>traffic>>>{uplink|downlink}
STATS_PATTERN = "user>>>"
STATS_DIRECTIONS = ("uplink", "downlink")
API_TIMEOUT_SECONDS = 8
# сколько меток нода готова помнить: подписчики + хопа цепочек (плюс те, кто был раньше)
MAX_LABELS = 4000
# как часто нода сама снимает счётчики, не дожидаясь панели. Нужно не ради свежести
# красивых цифр, а ради их сохранения: Xray хранит счётчики в памяти своего процесса,
# и если он умрёт сам (или его пересоберут), насчитанное между чтениями пропадёт.
SELF_POLL_SECONDS = 15


@dataclass
class TrafficSnapshot:
    """Что нода насчитала. Это же уходит панели в `/node/status`."""

    trafficBytes: int
    userTraffic: list[dict[str, Any]]
    statsAt: int
    statsError: str | None = None


def parse_counters(payload: dict) -> dict[str, int]:
    """{метка: байты} из ответа `xray api statsquery`: обе направления складываются.

    После `-reset` Xray возвращает имена счётчиков без значения — это ноль, а не
    «счётчик потерялся»."""
    totals: dict[str, int] = {}
    for entry in payload.get("stat") or []:
        if not isinstance(entry, dict):
            continue
        parts = str(entry.get("name") or "").split(">>>")
        if len(parts) != 4 or parts[0] != "user" or parts[3] not in STATS_DIRECTIONS:
            continue
        label = parts[1]
        if not label:
            continue
        raw = entry.get("value")
        try:
            value = int(raw) if raw is not None else 0
        except (TypeError, ValueError):
            value = 0
        totals[label] = totals.get(label, 0) + max(value, 0)
    return totals


async def self_poll(ledger: "TrafficLedger", stop) -> None:
    """Фоновый круг самоопроса: нода снимает счётчики чаще, чем к ней приходит панель.

    Panели достаточно приходить раз в минуту — байты не потеряются, потому что нода
    успевает их забрать и у себя, и в файле состояния.
    """
    import asyncio

    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=SELF_POLL_SECONDS)
        except TimeoutError:
            pass
        if stop.is_set():
            return
        try:
            await asyncio.to_thread(ledger.read)
        except Exception as err:  # noqa: BLE001 — самоопрос не имеет права ронять ноду
            print(f"[medusa-node] самоопрос счётчиков сорвался: {err}", flush=True)


class TrafficLedger:
    """Накопленные итоги ноды по трафику. Одны экземпляр на ноду, живёт в app.state."""

    def __init__(self, config: NodeConfig, identity: NodeIdentity, runner) -> None:
        self.config = config
        self.identity = identity
        self.runner = runner
        # снимает счётчики и обнуляет их — два параллельных чтения (панель и самоопрос ноды)
        # обязаны идти по очереди, иначе один и тот же кусок трафика попал бы в сумму дважды
        self._lock = threading.Lock()

    def read(self) -> TrafficSnapshot:
        """Снять счётчики и прибавить их к своим итогам.

        Нода снимает их при каждом спросе — кнопка панели, фоновый опрос, самоопрос ноды
        и перед остановкой Xray. Промежуток по времени здесь был бы ловушкой: Xray копит
        счётчики сам, но обнуляет их при перезапуске, и чтение, пропущенное «потому что
        недавно читали», теряло бы байты, наработанные после прежнего чтения.
        """
        with self._lock:
            return self._read()

    def snapshot(self, error: str | None) -> TrafficSnapshot:
        """Ответ панели даже тогда, когда считать нечем: цифры остаются прежними,
        а причина появляется отдельно. Нулевые метки наружу не идут."""
        users = [{"email": label, "bytes": total}
                 for label, total in sorted(self.identity.user_traffic.items()) if total > 0]
        return TrafficSnapshot(
            trafficBytes=self.identity.traffic_bytes,
            userTraffic=users,
            statsAt=self.identity.stats_at,
            statsError=error,
        )

    def _read(self) -> TrafficSnapshot:
        binary = resolve_xray_bin(self.config)
        if not binary:
            return self.snapshot("на ноде нет бинарника xray — счётчики снять нечем")
        port = self.runner.stats_port
        if not port:
            return self.snapshot("Xray не поднят (или порт счётчиков не подобран) — трафик не считался")

        command = [binary, "api", "statsquery", f"-pattern={STATS_PATTERN}", "-reset",
                   f"--server=127.0.0.1:{port}", f"-timeout={API_TIMEOUT_SECONDS}"]
        try:
            done = subprocess.run(command, capture_output=True, text=True,
                                  timeout=API_TIMEOUT_SECONDS + 15)
        except (OSError, subprocess.SubprocessError) as err:
            return self.snapshot(f"счётчики Xray не ответили: {err}")
        if done.returncode != 0:
            reason = (done.stderr or done.stdout or "").strip().splitlines()
            return self.snapshot(f"счётчики Xray не ответили: {reason[-1] if reason else f'код {done.returncode}'}")

        try:
            counters = parse_counters(json.loads(done.stdout or "{}"))
        except ValueError as err:
            return self.snapshot(f"ответ счётчиков Xray не разобрался: {err}")

        moment = now_ms()
        gained = 0
        for label, total in counters.items():
            if total <= 0:
                continue
            gained += total
            self.identity.user_traffic[label] = self.identity.user_traffic.get(label, 0) + total
        self.identity.traffic_bytes += gained
        self.identity.stats_at = moment
        self._fit_labels()
        save_identity(self.identity)
        return self.snapshot(None)

    def _fit_labels(self) -> None:
        """Файл состояния не должен разрастаться бесконечно: остаются самые загруженные метки.

        Теряются только те, кто принёс меньше всего байтов, и их прежние итоги уже
        записаны в базе панели — на ноде они нужны лишь для того, чтобы не обнулить
        человека при следующем чтении.
        """
        if len(self.identity.user_traffic) <= MAX_LABELS:
            return
        keep = sorted(self.identity.user_traffic.items(), key=lambda kv: kv[1], reverse=True)[:MAX_LABELS]
        self.identity.user_traffic = dict(keep)

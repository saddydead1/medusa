"""Метрики сервера, на котором запущена панель.

Читает /proc и statvfs напрямую — без сторонних зависимостей (psutil не нужен).
Всё рассчитано на Linux; на других системах возвращает то, что удалось получить
(None вместо недоступных значений), а фронт в этом случае просто скрывает блок.
"""

from __future__ import annotations

import os
import re
import socket
import time
from pathlib import Path

PROC_STAT = Path("/proc/stat")
MEMINFO = Path("/proc/meminfo")
MOUNTS = Path("/proc/mounts")
UPTIME = Path("/proc/uptime")

# только «настоящие» файловые системы: псевдо-фс и контейнерные монтирования не показываем
REAL_FS = {
    "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs",
    "jfs", "reiserfs", "vfs", "vfat", "exfat", "ntfs", "ntfs3",
    "apfs", "ufs", "btrfs", "nilfs2",
}
SKIP_MOUNTS = ("/proc", "/sys", "/dev", "/run", "/snap", "/boot/efi", "/var/lib/docker", "/var/lib/kubelet")

_UNESCAPE = re.compile(rb"\\([0-7]{3})")
_CACHE_TTL = 3.0
_cache: tuple[float, dict] = (0.0, {})


def _unescape(text: str) -> str:
    raw = text.encode("latin-1", "ignore")
    raw = _UNESCAPE.sub(lambda m: bytes([int(m.group(1), 8)]), raw)
    return raw.decode("utf-8", "replace")


def _cpu_times() -> tuple[int, int] | None:
    try:
        fields = PROC_STAT.read_text().splitlines()[0].split()[1:]
    except (OSError, IndexError):
        return None
    values = [int(v) for v in fields]
    if len(values) < 5:
        return None
    idle = values[3] + values[4]  # idle + iowait
    return sum(values), idle


def cpu_percent(sample_seconds: float = 0.25) -> float | None:
    """Загрузка ЦП в процентах: две выборки /proc/stat с коротким интервалом."""
    first = _cpu_times()
    if first is None:
        return None
    time.sleep(sample_seconds)
    second = _cpu_times()
    if second is None:
        return None
    delta_total = second[0] - first[0]
    delta_idle = second[1] - first[1]
    if delta_total <= 0:
        return None
    return round((1 - delta_idle / delta_total) * 100, 1)


def cpu() -> dict | None:
    percent = cpu_percent()
    if percent is None:
        return None
    try:
        load1, load5, load15 = os.getloadavg()
    except OSError:
        load1 = load5 = load15 = None
    return {
        "percent": percent,
        "cores": os.cpu_count(),
        "load1": round(load1, 2) if load1 is not None else None,
        "load5": round(load5, 2) if load5 is not None else None,
        "load15": round(load15, 2) if load15 is not None else None,
    }


def _meminfo() -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        for line in MEMINFO.read_text().splitlines():
            key, _, rest = line.partition(":")
            parts = rest.split()
            if parts:
                values[key] = int(parts[0]) * 1024  # в /proc/meminfo значения в КиБ
    except (OSError, ValueError):
        pass
    return values


def memory() -> dict | None:
    info = _meminfo()
    total = info.get("MemTotal")
    if not total:
        return None
    available = info.get("MemAvailable", info.get("MemFree", 0))
    swap_total = info.get("SwapTotal", 0)
    swap_used = swap_total - info.get("SwapFree", 0) if swap_total else 0
    used = total - available
    return {
        "total": total,
        "available": available,
        "used": used,
        "percent": round(used / total * 100, 1),
        "swapTotal": swap_total,
        "swapUsed": swap_used,
    }


def disks(limit: int = 4) -> list[dict]:
    """Диски по реальным монтированиям; если что-то пошло не так — минимум с '/'."""
    mounts: list[tuple[str, str]] = []
    try:
        for line in MOUNTS.read_text().splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            device, mount, fstype = parts[0], _unescape(parts[1]), parts[2]
            if fstype not in REAL_FS:
                continue
            if mount.startswith(SKIP_MOUNTS):
                continue
            mounts.append((device, mount))
    except OSError:
        mounts = []

    if not any(mount == "/" for _, mount in mounts):
        mounts.insert(0, ("", "/"))

    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for device, mount in mounts:
        key = (device, mount)
        if key in seen:
            continue
        seen.add(key)
        try:
            st = os.statvfs(mount)
        except OSError:
            continue
        total = st.f_blocks * st.f_frsize
        if total <= 0:
            continue
        free = st.f_bavail * st.f_frsize
        used = total - st.f_bfree * st.f_frsize
        out.append({
            "mount": mount,
            "device": device,
            "total": total,
            "used": used,
            "free": free,
            "percent": round(used / total * 100, 1),
        })
    out.sort(key=lambda x: x["total"], reverse=True)
    return out[:limit]


def uptime_seconds() -> float | None:
    try:
        return round(float(UPTIME.read_text().split()[0]), 1)
    except (OSError, ValueError, IndexError):
        return None


def system_info(use_cache: bool = True) -> dict:
    global _cache
    now = time.monotonic()
    if use_cache and _cache[1] and now - _cache[0] < _CACHE_TTL:
        return _cache[1]

    try:
        import platform
        kernel = f"{platform.system()} {platform.release()}"
    except Exception:
        kernel = None

    data = {
        "hostname": socket.gethostname(),
        "platform": kernel,
        "cpu": cpu(),
        "memory": memory(),
        "disks": disks(),
        "uptime": uptime_seconds(),
        "collectedAt": int(time.time()),
    }
    _cache = (now, data)
    return data

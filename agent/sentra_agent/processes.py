"""Process snapshots: every running process with owner, path, parent, CPU and memory.

Cross-platform through psutil, read-only, no admin rights: processes of other users simply
come without owner or path (AccessDenied) instead of failing the snapshot.

CPU is the average over the time since the previous snapshot (psutil keeps the Process objects
between calls), expressed as a share of the whole machine (0-100, like the asset's CPU metric)
rather than psutil's per-core sum. A process seen for the first time has no previous reading,
so its CPU is reported as unknown (null) instead of a misleading 0.
"""

from datetime import UTC, datetime
from typing import Any

import psutil

# Mirrors the API bound (MAX_SNAPSHOT_PROCESSES). Above it, the busiest processes are kept.
MAX_PROCESSES = 2000
_ATTRS = ["pid", "ppid", "name", "exe", "username", "memory_info", "create_time", "status"]


def _text(value: object, length: int) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\x00", "").strip()
    return text[:length] or None


class ProcessSampler:
    def __init__(self) -> None:
        # (pid, create_time) of processes already measured once: pids are reused by the OS,
        # the pair identifies one process.
        self._seen: set[tuple[int, float]] = set()
        self._cores = psutil.cpu_count() or 1

    def snapshot(self) -> dict[str, Any]:
        processes = []
        seen: set[tuple[int, float]] = set()
        for proc in psutil.process_iter(_ATTRS, ad_value=None):
            info = proc.info
            created = info.get("create_time")
            key = (int(info["pid"]), float(created or 0))
            seen.add(key)
            try:
                # Since the previous call on this same Process object (process_iter caches
                # them); the first call only primes the counter.
                raw = proc.cpu_percent(interval=None)
            except (psutil.Error, OSError):
                raw = None
            cpu = (
                round(min(max(raw / self._cores, 0.0), 100.0), 2)
                if raw is not None and key in self._seen
                else None
            )
            memory = info.get("memory_info")
            processes.append(
                {
                    "pid": key[0],
                    "ppid": info.get("ppid") or None,
                    "name": _text(info.get("name"), 255) or f"pid {key[0]}",
                    "exe": _text(info.get("exe"), 1024),
                    "username": _text(info.get("username"), 255),
                    "cpu_percent": cpu,
                    "memory_bytes": int(memory.rss) if memory else 0,
                    "started_at": datetime.fromtimestamp(created, UTC).isoformat()
                    if created
                    else None,
                    "status": _text(info.get("status"), 32),
                }
            )
        self._seen = seen
        if len(processes) > MAX_PROCESSES:
            processes.sort(key=lambda p: (p["cpu_percent"] or 0, p["memory_bytes"]), reverse=True)
            processes = processes[:MAX_PROCESSES]
        return {"collected_at": datetime.now(UTC).isoformat(), "processes": processes}

import os
import time
from datetime import datetime

from sentra_agent.processes import ProcessSampler


def test_real_snapshot_is_valid_for_the_api_and_cpu_needs_two_readings() -> None:
    sampler = ProcessSampler()

    first = sampler.snapshot()
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:  # burn some CPU in this process
        pass
    second = sampler.snapshot()

    assert datetime.fromisoformat(first["collected_at"]).utcoffset() is not None
    # No previous reading: unknown, not a misleading 0 %.
    assert all(p["cpu_percent"] is None for p in first["processes"])
    me = next(p for p in second["processes"] if p["pid"] == os.getpid())
    assert me["cpu_percent"] is not None and me["cpu_percent"] > 0
    assert me["started_at"] and me["memory_bytes"] > 0
    for process in second["processes"]:
        cpu = process["cpu_percent"]
        assert cpu is None or 0 <= cpu <= 100  # share of the whole machine
        assert 1 <= len(process["name"]) <= 255
        assert process["exe"] is None or len(process["exe"]) <= 1024
        assert process["ppid"] is None or process["ppid"] >= 0

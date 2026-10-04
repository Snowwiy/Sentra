"""Bounded telemetry buffer that survives agent restarts.

Samples wait here until the API confirms them. The buffer is mirrored to a small JSON file so
an outage followed by an agent restart (reboot, crash, update) does not lose the history
collected meanwhile. Both copies are capped at `maxlen` samples; when full, the oldest are
dropped first because the most recent state matters most to an operator.
"""

import json
import logging
import uuid
from collections import deque
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sentra_agent.identity import write_atomic

logger = logging.getLogger("sentra_agent")

BUFFER_FILE = "telemetry_buffer.json"


class SampleBuffer:
    def __init__(self, maxlen: int, path: Path | None = None) -> None:
        self._items: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._path = path
        self._dirty = False
        if path is not None:
            self._load(path)

    def _load(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            items = [item for item in data if isinstance(item, dict)]
            for item in items:
                # Spools written before sample_id existed: give each sample an id now so at
                # least every resend from here on is deduplicated by the server.
                item.setdefault("sample_id", str(uuid.uuid4()))
        except (ValueError, TypeError, OSError) as exc:
            # A corrupt spool only costs buffered samples; never block start-up on it.
            logger.warning("telemetry buffer unreadable, discarded", extra={"error": str(exc)})
            items = []
        # deque(maxlen) keeps the newest items if the file holds more than the current cap
        # (buffer_size lowered between runs).
        self._items.extend(items)
        if items:
            logger.info("restored buffered samples", extra={"count": len(self._items)})

    def append(self, item: dict[str, Any]) -> None:
        self._items.append(item)
        self._dirty = True

    def peek(self) -> dict[str, Any]:
        return self._items[0]

    def popleft(self) -> dict[str, Any]:
        self._dirty = True
        return self._items.popleft()

    def persist(self) -> None:
        """Write the buffer to disk if it changed since the last write."""
        if self._path is None or not self._dirty:
            return
        try:
            if self._items:
                write_atomic(self._path, json.dumps(list(self._items)), private=False)
            else:
                self._path.unlink(missing_ok=True)
            self._dirty = False
        except OSError as exc:
            # Disk full or locked: keep running with the in-memory copy and retry next cycle.
            logger.warning("could not persist telemetry buffer", extra={"error": str(exc)})

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self._items)

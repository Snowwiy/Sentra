"""Agent main loop: registration, heartbeat, telemetry, buffering and retry policy."""

import logging
import random
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import UUID, uuid4

from sentra_agent.buffer import BUFFER_FILE, SampleBuffer
from sentra_agent.client import ApiError, SentraClient, TransportError
from sentra_agent.collectors import HostInfo, collect_host_info, collect_metrics
from sentra_agent.config import AgentConfig
from sentra_agent.events import EventCollector
from sentra_agent.identity import Identity, IdentityStore
from sentra_agent.inventory import collect_inventory
from sentra_agent.logs import register_secret

logger = logging.getLogger("sentra_agent")

HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_PAYLOAD_TOO_LARGE = 413
HTTP_UNPROCESSABLE = 422
# Rejections that will repeat identically for the same payload: retrying them would loop
# forever (422 invalid content, 413 body over the server's size limit).
PERMANENT_REJECTIONS = {HTTP_PAYLOAD_TOO_LARGE, HTTP_UNPROCESSABLE}
AGENT_REVOKED_CODE = "agent_revoked"


class EventSource(Protocol):
    def pending(self) -> tuple[list[dict[str, Any]], dict[str, int]]: ...

    def commit(self, cursor: dict[str, int]) -> None: ...


class EnrollmentKeyMissingError(Exception):
    """The agent has no token and no enrollment key to obtain one."""


class CredentialsRejectedError(Exception):
    """The server refuses to let this agent in: revoked, or wrong/disabled enrollment key.

    Retrying soon cannot fix this; an operator has to act (reinstate the agent or fix the
    key). The loop backs off to its maximum interval instead of hammering the API.
    """

    def __init__(self, reason: str, status: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


def backoff_delay(failures: int, interval: float, maximum: float) -> float:
    """Exponential backoff with jitter for consecutive transport failures.

    Doubling avoids hammering an API that is down; the cap bounds how long a recovered API
    waits to hear from us; jitter keeps a fleet of agents from retrying in lockstep after an
    outage (thundering herd).
    """
    base = min(maximum, interval * 2 ** max(0, failures - 1))
    return float(base * random.uniform(0.8, 1.2))  # noqa: S311  (jitter, not cryptography)


class Agent:
    def __init__(
        self,
        config: AgentConfig,
        client: SentraClient,
        store: IdentityStore,
        host_info: Callable[[], HostInfo] = collect_host_info,
        metrics: Callable[[], dict[str, Any]] = collect_metrics,
        inventory: Callable[[], dict[str, Any]] = collect_inventory,
        events: EventSource | None = None,
        stop_event: threading.Event | None = None,
    ) -> None:
        self.config = config
        self.client = client
        self.store = store
        self.host_info = host_info
        self.metrics = metrics
        self.inventory = inventory
        self.events: EventSource = events or EventCollector(config.state_dir)
        self._events_sent_at: float | None = None
        # Monotonic clock: wall-clock jumps (NTP sync, DST, manual changes) must not
        # suppress or flood inventory uploads.
        self._inventory_sent_at: float | None = None
        # Inventory sections this server rejected as unknown (older backend than agent). They
        # are left out for the rest of this run so the known sections still get through.
        self._unsupported_sections: set[str] = set()
        self.stop_event = stop_event or threading.Event()
        # Samples survive outages (and agent restarts during an outage) up to buffer_size;
        # each sample carries its own timestamp, so late delivery lands at the right point in
        # the history.
        self.buffer = SampleBuffer(config.buffer_size, config.state_dir / BUFFER_FILE)
        self.identity: Identity = store.load_or_create()
        register_secret(self.identity.token)
        register_secret(config.enrollment_key)

    def run(self, once: bool = False) -> None:
        logger.info(
            "agent started",
            extra={"agent_id": str(self.identity.agent_id), "api_url": self.config.api_url},
        )
        failures = 0
        while not self.stop_event.is_set():
            delay: float = self.config.interval_seconds
            try:
                self.cycle()
                if failures:
                    logger.info("connection to API restored", extra={"failed_cycles": failures})
                failures = 0
            except TransportError as exc:
                failures += 1
                delay = backoff_delay(
                    failures, self.config.interval_seconds, self.config.max_backoff_seconds
                )
                if exc.retry_after is not None:
                    # Honor the server's own hint when it asks for more patience than our
                    # backoff, but never exceed our cap.
                    delay = min(max(delay, exc.retry_after), self.config.max_backoff_seconds)
                logger.warning(
                    "API unreachable",
                    extra={
                        "error": str(exc),
                        "retry_in_s": round(delay, 1),
                        "buffered": len(self.buffer),
                    },
                )
            except EnrollmentKeyMissingError:
                logger.error(
                    "agent is not enrolled and no enrollment key is configured; "
                    "set SENTRA_AGENT_ENROLLMENT_KEY"
                )
            except CredentialsRejectedError as exc:
                delay = backoff_delay(
                    1, self.config.max_backoff_seconds, self.config.max_backoff_seconds
                )
                logger.error(
                    "API refused agent credentials",
                    extra={
                        "reason": exc.reason,
                        "status": exc.status,
                        "retry_in_s": round(delay, 1),
                    },
                )
            except ApiError as exc:
                # The server rejected us for a reason retrying will not fix (e.g. a contract
                # mismatch after an upgrade). Keep the normal pace instead of a tight loop.
                logger.error("API rejected request", extra={"status": exc.status, "body": exc.body})
            finally:
                self.buffer.persist()
            if once:
                return
            self.stop_event.wait(delay)
        logger.info("agent stopped")

    def cycle(self) -> None:
        # Measure first, so the sample exists even if the API turns out to be unreachable.
        # The sample_id is fixed at measurement time and travels with the sample through the
        # buffer (and its disk copy): if a response is lost and we resend, the server sees the
        # same id and does not store the sample twice.
        sample = self.metrics()
        sample.setdefault("sample_id", str(uuid4()))
        self.buffer.append(sample)
        self._ensure_enrolled()
        self._authenticated(self._heartbeat)
        self._authenticated(self._flush_buffer)
        self._authenticated(self._maybe_send_inventory)
        self._authenticated(self._maybe_send_events)

    def _maybe_send_events(self, token: str) -> None:
        now = time.monotonic()
        if (
            self._events_sent_at is not None
            and now - self._events_sent_at < self.config.events_interval_seconds
        ):
            return
        events, cursor = self.events.pending()
        if events:
            try:
                self.client.send_events(self.identity.agent_id, token, events)
            except ApiError as exc:
                if exc.status not in PERMANENT_REJECTIONS:
                    raise
                # A batch the server rejects would be re-read forever; skip past it.
                logger.warning("event batch rejected", extra={"body": exc.body})
        # Advance only after the API accepted (or permanently rejected) the batch; on a
        # transport error we never get here and the same events are re-read next time.
        self.events.commit(cursor)
        self._events_sent_at = now

    def _authenticated(self, call: Callable[[str], None]) -> None:
        """Run an API call with our token; on 401 enroll again once and retry.

        401 means the server no longer accepts our token (database reset, token rotated by a
        re-install elsewhere, asset revoked). Re-enrolling keeps the same agent_id, so the
        asset and its history survive; a revoked agent is refused at enrollment (403), which
        surfaces as CredentialsRejectedError. A second 401 propagates instead of looping.

        403 on a data call means the server knows us but forbids reporting: never retry it
        quickly and never discard our token for it.
        """
        try:
            call(self._ensure_enrolled())
            return
        except ApiError as exc:
            _raise_if_forbidden(exc)
            if exc.status != HTTP_UNAUTHORIZED:
                raise
        logger.warning("agent token rejected, enrolling again")
        self.identity.token = None
        self.identity.token_issued_at = None
        self.store.save(self.identity)
        try:
            call(self._ensure_enrolled())
        except ApiError as exc:
            _raise_if_forbidden(exc)
            raise

    def _ensure_enrolled(self) -> str:
        """Return our token, enrolling first if we do not have one."""
        if self.identity.token is not None:
            return self.identity.token
        if not self.config.enrollment_key:
            raise EnrollmentKeyMissingError
        try:
            response = self.client.register(
                self.identity.agent_id, self.host_info().as_payload(), self.config.enrollment_key
            )
        except ApiError as exc:
            if exc.status == HTTP_FORBIDDEN:
                # Either this agent was revoked by an operator or enrollment is disabled.
                reason = (
                    "agent revoked by an operator"
                    if exc.code == AGENT_REVOKED_CODE
                    else "enrollment disabled on server"
                )
                raise CredentialsRejectedError(reason, exc.status) from exc
            if exc.status == HTTP_UNAUTHORIZED:
                raise CredentialsRejectedError("invalid enrollment key", exc.status) from exc
            raise
        # Persist the token before using it: if we crash right after, the next start must not
        # enroll again and silently revoke a token the server already considers current.
        token: str = response["agent_token"]
        register_secret(token)
        self.identity.token = token
        self.identity.token_issued_at = datetime.now(UTC)
        self.identity.asset_id = UUID(response["asset_id"])
        self.store.save(self.identity)
        logger.info("agent enrolled", extra={"asset_id": response["asset_id"]})
        return token

    def _heartbeat(self, token: str) -> None:
        # Host info rides along on every heartbeat so IP/OS/agent version changes reach the
        # server without a separate inventory call.
        response = self.client.heartbeat(
            self.identity.agent_id, token, self.host_info().as_payload()
        )
        self._remember_asset(response["asset_id"])

    def _flush_buffer(self, token: str) -> None:
        while self.buffer:
            sample = self.buffer.peek()
            try:
                self.client.send_telemetry(self.identity.agent_id, token, sample)
            except ApiError as exc:
                if exc.status not in PERMANENT_REJECTIONS:
                    raise
                # A sample the server will never accept (e.g. clock far in the future) must not
                # block every newer sample behind it.
                logger.warning("dropping rejected sample", extra={"body": exc.body})
            # Drop the sample only once the server confirmed (or permanently rejected) it, so a
            # failure mid-flush keeps it for the next attempt.
            self.buffer.popleft()

    def _maybe_send_inventory(self, token: str) -> None:
        now = time.monotonic()
        due = (
            self._inventory_sent_at is None
            or now - self._inventory_sent_at >= self.config.inventory_interval_seconds
        )
        if not due:
            return
        snapshot = self.inventory()
        try:
            self._send_inventory(token, snapshot)
        except ApiError as exc:
            if exc.status not in PERMANENT_REJECTIONS:
                raise
            # Rejected snapshot: wait for the next interval instead of re-sending the same
            # large payload every cycle.
            logger.warning("inventory rejected", extra={"body": exc.body})
        self._inventory_sent_at = now

    def _send_inventory(self, token: str, snapshot: dict[str, Any]) -> None:
        payload = {k: v for k, v in snapshot.items() if k not in self._unsupported_sections}
        try:
            self.client.send_inventory(self.identity.agent_id, token, payload)
            return
        except ApiError as exc:
            unknown = _unknown_top_level_fields(exc) if exc.status == HTTP_UNPROCESSABLE else set()
            if not unknown:
                raise
        # The API rejects unknown fields; an agent newer than its server would otherwise lose
        # the whole inventory over one new section. Drop those sections and retry once.
        logger.info(
            "server does not accept some inventory sections yet",
            extra={"sections": sorted(unknown)},
        )
        self._unsupported_sections |= unknown
        payload = {k: v for k, v in payload.items() if k not in unknown}
        self.client.send_inventory(self.identity.agent_id, token, payload)

    def _remember_asset(self, asset_id: str) -> None:
        if self.identity.asset_id is None or str(self.identity.asset_id) != asset_id:
            self.identity.asset_id = UUID(asset_id)
            self.store.save(self.identity)


def _raise_if_forbidden(exc: ApiError) -> None:
    if exc.status == HTTP_FORBIDDEN:
        raise CredentialsRejectedError(exc.code or "forbidden", exc.status) from exc


def _unknown_top_level_fields(exc: ApiError) -> set[str]:
    """Top-level body fields a 422 rejected as unknown (`extra_forbidden`).

    Error envelope: {"error": {"details": [{"loc": ["body", "<field>"], "type": ...}]}}.
    Only errors that are *all* about unknown top-level fields count; any other validation
    error means the payload itself is wrong and must not be "fixed" by dropping data.
    """
    error = exc.body.get("error")
    details = error.get("details") if isinstance(error, dict) else None
    if not isinstance(details, list) or not details:
        return set()
    fields: set[str] = set()
    for detail in details:
        loc = detail.get("loc") if isinstance(detail, dict) else None
        if (
            detail.get("type") != "extra_forbidden"
            or not isinstance(loc, list)
            or len(loc) != 2
            or loc[0] != "body"
            or not isinstance(loc[1], str)
            or loc[1] in ("agent_id", "collected_at")
        ):
            return set()
        fields.add(loc[1])
    return fields

"""Agent main loop: registration, heartbeat, telemetry, buffering and retry policy."""

import logging
import random
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID, uuid4

from sentra_agent.buffer import BUFFER_FILE, SampleBuffer
from sentra_agent.client import ApiError, SentraClient, TransportError
from sentra_agent.collectors import HostInfo, collect_host_info, collect_metrics
from sentra_agent.config import AgentConfig
from sentra_agent.events import EventCollector
from sentra_agent.identity import Identity, IdentityStore
from sentra_agent.inventory import collect_inventory
from sentra_agent.linux_events import COVERAGE_REFRESH_SECONDS
from sentra_agent.logs import register_secret
from sentra_agent.processes import ProcessSampler

logger = logging.getLogger("sentra_agent")

HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_PAYLOAD_TOO_LARGE = 413
HTTP_UNPROCESSABLE = 422
# Rejections that will repeat identically for the same payload: retrying them would loop
# forever (422 invalid content, 413 body over the server's size limit).
PERMANENT_REJECTIONS = {HTTP_PAYLOAD_TOO_LARGE, HTTP_UNPROCESSABLE}
AGENT_REVOKED_CODE = "agent_revoked"


# Máximo de eventos por petición que acepta el servidor (EventBatch).
EVENTS_PER_REQUEST = 500
ASSET_ARCHIVED_CODE = "asset_archived"


class EventSource(Protocol):
    # El cursor es opaco para el runner: lo devuelve pending() y se confirma con commit().
    def pending(self) -> tuple[list[dict[str, Any]], Any]: ...

    def commit(self, cursor: Any) -> None: ...


def default_event_source(state_dir: Path) -> EventSource:
    """Visor de eventos en Windows, journal en Linux (Fase 5C.1); nada en otros sistemas."""
    if sys.platform.startswith("linux"):
        from sentra_agent.linux_events import LinuxJournalCollector

        return LinuxJournalCollector(state_dir)
    return EventCollector(state_dir)


class EnrollmentKeyMissingError(Exception):
    """The agent has no token and no enrollment credential (token or key) to obtain one."""


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
        processes: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        self.config = config
        self.client = client
        self.store = store
        self.host_info = host_info
        self.metrics = metrics
        self.inventory = inventory
        self.events: EventSource = events or default_event_source(config.state_dir)
        self.processes = processes or ProcessSampler().snapshot
        self._events_sent_at: float | None = None
        # Fase 5C.1: última cobertura de eventos enviada y cuándo (se reenvía al cambiar o
        # cada COVERAGE_REFRESH_SECONDS para que el servidor sepa que sigue vigente).
        self._coverage_sent: dict[str, str] | None = None
        self._coverage_sent_at: float | None = None
        # Monotonic clock: wall-clock jumps (NTP sync, DST, manual changes) must not
        # suppress or flood inventory uploads.
        self._inventory_sent_at: float | None = None
        self._processes_sent_at: float | None = None
        # False once the server answered 404 to /processes (older backend): not retried in
        # this run, so an old server never sees a request per cycle it cannot serve.
        self._processes_supported = True
        # Fields each endpoint's server rejected as unknown (older backend than agent), as
        # paths without list indexes, e.g. ("disks",) or ("services", "pid"). They are left
        # out for the rest of this run so everything the server knows still gets through.
        self._unsupported: dict[str, set[tuple[str, ...]]] = {}
        self.stop_event = stop_event or threading.Event()
        # Samples survive outages (and agent restarts during an outage) up to buffer_size;
        # each sample carries its own timestamp, so late delivery lands at the right point in
        # the history.
        self.buffer = SampleBuffer(config.buffer_size, config.state_dir / BUFFER_FILE)
        self.identity: Identity = store.load_or_create()
        register_secret(self.identity.token)
        register_secret(config.enrollment_key)
        register_secret(config.enrollment_token)
        # A one-time token is tried at most once per run: once used (or refused) it cannot
        # work again, so it is forgotten and never sent anywhere else.
        self._bootstrap_spent = False

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
                    "agent is not enrolled and has no enrollment credential; create a one-time"
                    " token on the server and set SENTRA_AGENT_ENROLLMENT_TOKEN (or"
                    " enrollment_token_file)"
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
            except Exception:
                # Last line of defense: an unexpected error (a collector failing in a new way,
                # a proxy answering 200 with a body that is not ours, a corrupt state file)
                # must not kill the agent.
                # Aunque systemd o el SCM de Windows lo reinicien, una caída pierde el estado en
                # memoria y deja el equipo "offline" durante el retardo de reinicio; ejecutado a
                # mano, nadie lo reiniciaría.
                # Keep the normal pace: earlier steps of the cycle (heartbeat, telemetry) may
                # still be working, and backing off would only slow them down. The traceback
                # goes to the (secret-redacting) log for diagnosis.
                logger.exception("agent cycle failed unexpectedly")
                if once:
                    # A single diagnostic cycle (--once) still fails loudly, with a non-zero
                    # exit code, as before: there is no next cycle to recover in.
                    raise
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
        self._authenticated(self._maybe_send_processes)
        self._authenticated(self._maybe_send_events)

    def _maybe_send_events(self, token: str) -> None:
        now = time.monotonic()
        if (
            self._events_sent_at is not None
            and now - self._events_sent_at < self.config.events_interval_seconds
        ):
            return
        try:
            events, cursor = self.events.pending()
        except Exception:
            # Fase 5C.1: un colector de eventos roto nunca afecta a heartbeat, telemetría ni
            # inventario (ya enviados en este ciclo); se reintenta en el siguiente intervalo.
            logger.exception("event collection failed")
            self._events_sent_at = now
            return
        coverage = _source_coverage(self.events)
        coverage_due = coverage is not None and (
            coverage != self._coverage_sent
            or self._coverage_sent_at is None
            or now - self._coverage_sent_at >= COVERAGE_REFRESH_SECONDS
        )
        if ("coverage",) in self._unsupported.get("events", set()):
            # Servidor anterior a la Fase 5C.1: no hay a quién informar la cobertura.
            coverage_due = False
        if events or coverage_due:
            # Lotes de como mucho EVENTS_PER_REQUEST; la cobertura viaja en el primero. Si un
            # lote posterior falla, no se confirma el cursor y se reenvía todo: el servidor
            # ignora los repetidos (record_id), así que no se duplica nada.
            chunks = [
                events[i : i + EVENTS_PER_REQUEST]
                for i in range(0, len(events), EVENTS_PER_REQUEST)
            ] or [[]]
            for index, chunk in enumerate(chunks):
                payload: dict[str, Any] = {"events": chunk}
                if index == 0 and coverage_due:
                    payload["coverage"] = coverage
                try:
                    self._send_adapting(
                        "events",
                        lambda body: self.client.send_events(
                            self.identity.agent_id,
                            token,
                            body["events"],
                            body.get("coverage"),
                        ),
                        payload,
                    )
                except ApiError as exc:
                    if exc.status not in PERMANENT_REJECTIONS:
                        raise
                    # A batch the server rejects would be re-read forever; skip past it.
                    logger.warning("event batch rejected", extra={"body": exc.body})
            if coverage_due:
                self._coverage_sent = coverage
                self._coverage_sent_at = now
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

    def enroll(self) -> UUID | None:
        """Enroll now if needed (no other API call) and return the asset id we report as.

        Used by installers to verify enrollment before starting the service. An agent that
        already holds its own token keeps its identity, so a reinstall or upgrade never
        enrolls twice; it only contacts the server when a new one-time token was supplied,
        to check whether its own token still works. Raises like a cycle would:
        EnrollmentKeyMissingError, CredentialsRejectedError, TransportError.
        """
        if self.identity.token is not None and self._bootstrap_token() is not None:
            # An operator handed us a new one-time token although we hold our own: it may be
            # dead (agent revoked then reinstated, server database reset). Prove it with one
            # heartbeat; on 401 `_authenticated` enrolls again with the new token, keeping
            # our agent_id (same asset, same history). A valid token is kept and the new
            # one-time token stays unused.
            self._authenticated(self._heartbeat)
        else:
            self._ensure_enrolled()
        return self.identity.asset_id

    def has_bootstrap(self) -> bool:
        """True si hay un token de un solo uso pendiente (configurado o en su archivo)."""
        return self._bootstrap_token() is not None

    def discard_bootstrap(self) -> None:
        """Borra el token de un solo uso que no hizo falta (el agente ya tenía uno válido).

        El servicio Windows lo llama tras un enrolamiento resuelto: un token que no se usó
        no debe quedarse en disco hasta caducar.
        """
        path = self.config.enrollment_token_file
        if self.config.enrollment_token or (path is not None and path.exists()):
            self._forget_bootstrap()
        else:
            self._bootstrap_spent = True

    def _bootstrap_token(self) -> str | None:
        """The one-time token from the config or its file, unless already spent this run."""
        if self._bootstrap_spent:
            return None
        if self.config.enrollment_token:
            return self.config.enrollment_token
        path = self.config.enrollment_token_file
        if path is not None and path.is_file():
            try:
                # utf-8-sig: el Bloc de notas de Windows guarda con BOM, que si no acabaría
                # dentro del token y el servidor lo rechazaría.
                token = path.read_text(encoding="utf-8-sig").strip()
            except OSError as exc:
                logger.warning("enrollment token file unreadable", extra={"error": str(exc)})
                return None
            register_secret(token)
            return token or None
        return None

    def _forget_bootstrap(self) -> None:
        """Drop every copy of the one-time token we control (memory and its file)."""
        self._bootstrap_spent = True
        self.config = replace(self.config, enrollment_token=None)
        path = self.config.enrollment_token_file
        if path is not None:
            try:
                path.unlink(missing_ok=True)
                logger.info("enrollment token file deleted", extra={"path": str(path)})
            except OSError as exc:
                logger.warning(
                    "could not delete the enrollment token file; delete it by hand",
                    extra={"path": str(path), "error": str(exc)},
                )

    def _ensure_enrolled(self) -> str:
        """Return our token, enrolling first if we do not have one."""
        if self.identity.token is not None:
            return self.identity.token
        bootstrap = self._bootstrap_token()
        if bootstrap is None and not self.config.enrollment_key:
            raise EnrollmentKeyMissingError
        try:
            if bootstrap is not None:
                response = self._send_adapting(
                    "register",
                    lambda body: self.client.register(
                        self.identity.agent_id, body, enrollment_token=bootstrap
                    ),
                    self._host_payload(),
                )
            else:
                response = self._send_adapting(
                    "register",
                    lambda body: self.client.register(
                        self.identity.agent_id, body, self.config.enrollment_key
                    ),
                    self._host_payload(),
                )
        except ApiError as exc:
            if exc.status in (HTTP_FORBIDDEN, HTTP_UNAUTHORIZED) and bootstrap is not None:
                # Expired, used, revoked or not for this host: it will never work again.
                self._forget_bootstrap()
            if exc.status == HTTP_FORBIDDEN:
                # Either this agent was revoked by an operator or enrollment is disabled.
                if exc.code == AGENT_REVOKED_CODE:
                    reason = "agent revoked by an operator"
                elif exc.code == ASSET_ARCHIVED_CODE:
                    # Fase 5C.1: el activo de este agente está archivado; un administrador
                    # debe restaurarlo (o reconciliarlo) antes de que vuelva a informar.
                    reason = "asset archived by an operator; restore it on the server"
                else:
                    reason = "enrollment disabled on server"
                raise CredentialsRejectedError(reason, exc.status) from exc
            if exc.status == HTTP_UNAUTHORIZED:
                reason = (
                    "enrollment token invalid, expired or already used; create a new one"
                    if bootstrap is not None
                    else "invalid enrollment key"
                )
                raise CredentialsRejectedError(reason, exc.status) from exc
            raise
        # Persist the token before using it: if we crash right after, the next start must not
        # enroll again and silently revoke a token the server already considers current.
        token: str = response["agent_token"]
        register_secret(token)
        self.identity.token = token
        self.identity.token_issued_at = datetime.now(UTC)
        self.identity.asset_id = UUID(response["asset_id"])
        self.store.save(self.identity)
        if bootstrap is not None:
            # Enrolled: only the per-agent token (just saved) is used from now on.
            self._forget_bootstrap()
        logger.info(
            "agent enrolled",
            extra={
                "asset_id": response["asset_id"],
                "method": "one-time token" if bootstrap is not None else "shared key (legacy)",
            },
        )
        return token

    def _heartbeat(self, token: str) -> None:
        # Host info rides along on every heartbeat so IP/OS/agent version changes reach the
        # server without a separate inventory call.
        response = self._send_adapting(
            "heartbeat",
            lambda body: self.client.heartbeat(self.identity.agent_id, token, body["host"]),
            {"host": self._host_payload()},
        )
        self._remember_asset(response["asset_id"])

    def _host_payload(self) -> dict[str, Any]:
        payload = self.host_info().as_payload()
        # Solo se envía si el instalador lo configuró: un servidor anterior a la Fase 4F lo
        # rechazaría con 422 extra_forbidden (y _send_adapting lo quitaría para esta ejecución).
        if self.config.installation_method:
            payload["installation_method"] = self.config.installation_method
        return payload

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
        self._send_adapting(
            "inventory",
            lambda body: self.client.send_inventory(self.identity.agent_id, token, body),
            snapshot,
        )

    def _maybe_send_processes(self, token: str) -> None:
        now = time.monotonic()
        due = (
            self._processes_sent_at is None
            or now - self._processes_sent_at >= self.config.processes_interval_seconds
        )
        if not self._processes_supported or not due:
            return
        snapshot = self.processes()
        try:
            self._send_adapting(
                "processes",
                lambda body: self.client.send_processes(self.identity.agent_id, token, body),
                snapshot,
            )
        except ApiError as exc:
            if exc.status == HTTP_NOT_FOUND:
                logger.info("server does not accept process snapshots yet; disabled for this run")
                self._processes_supported = False
            elif exc.status not in PERMANENT_REJECTIONS:
                raise
            else:
                logger.warning("process snapshot rejected", extra={"body": exc.body})
        self._processes_sent_at = now

    def _send_adapting(
        self,
        endpoint: str,
        send: Callable[[dict[str, Any]], dict[str, Any]],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Send a payload, leaving out fields this server rejected as unknown.

        The API refuses unknown fields; an agent newer than its server would otherwise lose
        a whole inventory (or event batch) over one new field. On a 422 made only of
        `extra_forbidden` errors, those fields are dropped (for the rest of the run) and the
        request is retried once. Any other validation error is a real problem and is raised.
        """
        dropped = self._unsupported.setdefault(endpoint, set())
        try:
            return send(_drop_fields(payload, dropped))
        except ApiError as exc:
            unknown = _unknown_fields(exc) if exc.status == HTTP_UNPROCESSABLE else set()
            if not unknown:
                raise
        logger.info(
            "server does not accept some fields yet",
            extra={"endpoint": endpoint, "fields": sorted(".".join(path) for path in unknown)},
        )
        dropped |= unknown
        return send(_drop_fields(payload, dropped))

    def _remember_asset(self, asset_id: str) -> None:
        if self.identity.asset_id is None or str(self.identity.asset_id) != asset_id:
            self.identity.asset_id = UUID(asset_id)
            self.store.save(self.identity)


def _source_coverage(source: EventSource) -> dict[str, str] | None:
    """Cobertura de la fuente de eventos si la ofrece (el colector de Windows no)."""
    coverage = getattr(source, "coverage", None)
    if not callable(coverage):
        return None
    try:
        value = coverage()
    except Exception:
        logger.exception("event coverage unavailable")
        return None
    return dict(value) if isinstance(value, dict) and value else None


def _raise_if_forbidden(exc: ApiError) -> None:
    if exc.status == HTTP_FORBIDDEN:
        raise CredentialsRejectedError(exc.code or "forbidden", exc.status) from exc


def _unknown_fields(exc: ApiError) -> set[tuple[str, ...]]:
    """Body fields a 422 rejected as unknown (`extra_forbidden`), as paths without indexes.

    Error envelope: {"error": {"details": [{"loc": ["body", "services", 3, "pid"], ...}]}}
    gives ("services", "pid"). Only errors that are *all* about unknown fields count; any
    other validation error means the payload itself is wrong and must not be "fixed" by
    dropping data. The identity fields are never dropped.
    """
    error = exc.body.get("error")
    details = error.get("details") if isinstance(error, dict) else None
    if not isinstance(details, list) or not details:
        return set()
    fields: set[tuple[str, ...]] = set()
    for detail in details:
        # The body comes from the network: check the shape before calling dict methods, or a
        # malformed error (e.g. from a proxy) would raise AttributeError instead of "unknown".
        if not isinstance(detail, dict):
            return set()
        loc = detail.get("loc")
        if detail.get("type") != "extra_forbidden" or not isinstance(loc, list):
            return set()
        path = tuple(part for part in loc[1:] if not isinstance(part, int))
        if (
            len(loc) < 2
            or loc[0] != "body"
            or not path
            or not all(isinstance(part, str) for part in path)
            or path in (("agent_id",), ("collected_at",))
        ):
            return set()
        fields.add(path)
    return fields


def _drop_fields(payload: Any, paths: set[tuple[str, ...]]) -> Any:
    for path in paths:
        payload = _drop(payload, path)
    return payload


def _drop(value: Any, path: tuple[str, ...]) -> Any:
    """Copy of `value` without the field at `path`; lists apply it to every item."""
    if isinstance(value, list):
        return [_drop(item, path) for item in value]
    if not isinstance(value, dict) or not path:
        return value
    head, rest = path[0], path[1:]
    if not rest:
        return {key: item for key, item in value.items() if key != head}
    return {key: (_drop(item, rest) if key == head else item) for key, item in value.items()}

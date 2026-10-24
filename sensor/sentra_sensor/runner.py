"""Bucle principal del sensor: heartbeat → poll → start → scan → spool → flush.

Principios:
* Sin busy loop: cada vuelta calcula cuándo vence lo siguiente (heartbeat, poll, reintento
  del spool) y duerme hasta entonces; un evento lo despierta antes si hay trabajo nuevo
  (lote encolado, scan terminado) o una parada.
* Tolerante a caídas largas del servidor: lo observado queda en el spool (durable) y se
  entrega al volver, con backoff exponencial + jitter para no martillear al servidor.
* Un solo job a la vez, en un hilo aparte, para que los heartbeats (y por tanto las
  cancelaciones y rotaciones) sigan fluyendo durante un scan largo.
"""

import logging
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentra_sensor import CAPABILITIES, __version__
from sentra_sensor.backoff import backoff_delay
from sentra_sensor.batching import BatchBuilder, enqueue_complete
from sentra_sensor.client import ApiError, SensorClient, Transport, TransportError
from sentra_sensor.config import LocalConfig
from sentra_sensor.credentials import CredentialError, CredentialStore, SensorIdentity
from sentra_sensor.dhcp import MAX_LEASES_PER_BATCH, DhcpCollector, DhcpReport
from sentra_sensor.jobs import (
    DhcpParameters,
    DiscoveryJob,
    DiscoveryParameters,
    JobRejectedError,
    SnmpParameters,
    validate_job,
)
from sentra_sensor.logs import register_secret
from sentra_sensor.names import IdentityProber
from sentra_sensor.protocol import ProtocolError, ServerConfig
from sentra_sensor.scanner import (
    IcmpProber,
    NeighborReader,
    Observation,
    ReverseResolver,
    Scanner,
    ScanReport,
    TcpProber,
)
from sentra_sensor.snmp.collector import SnmpCollector, SnmpCredentials, SnmpReport
from sentra_sensor.snmp.transport import SnmpTransport
from sentra_sensor.spool import KIND_COMPLETE, KIND_RESULTS, Spool, SpoolItem
from sentra_sensor.state import (
    MODE_ACTIVE,
    MODE_DISABLED,
    MODE_REVOKED,
    MODE_UNAUTHORIZED,
    LocalState,
    host_metadata,
    load_state,
    save_state,
)

logger = logging.getLogger("sentra_sensor.runner")

# Base del backoff de red: el primer reintento llega en 2,5-5 s y se dobla hasta el tope.
BACKOFF_BASE_SECONDS = 5.0
# Suelo de espera entre vueltas: aunque algo "venza ya" en bucle, nunca más de 4 vueltas/s.
MIN_WAIT_SECONDS = 0.25
# Códigos de error que dicen "este envío ya no tiene sentido": se descarta (registrado).
_DISCARD_STATUSES = {404, 409, 410, 413, 422}

REVOKED_INSTRUCTIONS = (
    "sensor credential was REVOKED by the server: this sensor will not request work. "
    "Create a new sensor enrollment token in Sentra (Sites > Sensors) and run "
    "`sentra-sensor enroll --server <url> --token-file <file> --force`, then restart the service"
)


@dataclass
class ProberSet:
    tcp: TcpProber | None = None
    icmp: IcmpProber | None = None
    neighbors: NeighborReader | None = None
    resolver: ReverseResolver | None = None
    # Corrección 6C: sondas de nombre (mDNS, NetBIOS, SSDP/UPnP); None = no se hacen.
    identity: IdentityProber | None = None


SnmpTransportFactory = Callable[[SnmpParameters, SnmpCredentials], SnmpTransport]


def default_snmp_transport(params: SnmpParameters, credentials: SnmpCredentials) -> SnmpTransport:
    # Importación diferida: pysnmp es opcional y solo se carga con un job SNMP real.
    from sentra_sensor.snmp.pysnmp_adapter import make_transport

    return make_transport(
        params.address, params.port, credentials, params.timeout_ms, params.retries
    )


def parse_credentials(raw: object, params: SnmpParameters) -> SnmpCredentials | None:
    """Credencial de la respuesta de start. Debe corresponder EXACTAMENTE al job (perfil,
    revisión y versión); si no, el job no se ejecuta."""
    if not isinstance(raw, dict):
        return None
    if (
        str(raw.get("profile_id")) != params.profile_id
        or raw.get("secret_revision") != params.secret_revision
        or raw.get("snmp_version") != params.snmp_version
    ):
        return None

    def opt(key: str) -> str | None:
        value = raw.get(key)
        return value if isinstance(value, str) and value else None

    return SnmpCredentials(
        snmp_version=params.snmp_version,
        username=opt("username"),
        auth_protocol=params.auth_protocol,
        priv_protocol=params.priv_protocol,
        auth_password=opt("auth_password"),
        priv_password=opt("priv_password"),
        community=opt("community"),
    )


@dataclass
class ActiveJob:
    job: DiscoveryJob
    scanner: Scanner | SnmpCollector | DhcpCollector
    builder: BatchBuilder
    thread: threading.Thread | None = None
    report: ScanReport | SnmpReport | DhcpReport | None = None
    crash: str | None = None
    done: threading.Event = field(default_factory=threading.Event)


def utc_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat()


class SensorRunner:
    def __init__(
        self,
        config: LocalConfig,
        transport: Transport,
        store: CredentialStore | None = None,
        spool: Spool | None = None,
        probers: Callable[[], ProberSet] | None = None,
        clock: Callable[[], float] = time.time,
        rng: random.Random | None = None,
        threaded_jobs: bool = True,
        snmp_transport: SnmpTransportFactory | None = None,
    ) -> None:
        self.config = config
        self._transport = transport
        self.store = store or CredentialStore(config.credential_file())
        # La identidad se carga antes de crear nada en disco: sin enrolar no se arranca.
        self.identity: SensorIdentity = self.store.load()
        self.spool = spool or Spool(
            config.spool_file(),
            max_bytes=config.spool_max_mb * 1024 * 1024,
            max_items=config.spool_max_items,
            max_age_seconds=config.spool_max_age_hours * 3600,
            clock=clock,
        )
        # El runner solo cierra el spool que abre él (uno inyectado es de quien lo creó).
        self._owns_spool = spool is None
        try:
            self._probers = probers or ProberSet
            self._clock = clock
            self._rng = rng or random.Random()  # noqa: S311  (jitter, no criptografía)
            self._threaded_jobs = threaded_jobs
            self._snmp_transport = snmp_transport or default_snmp_transport
            self._wake = threading.Event()
            self._stopping = threading.Event()
            self._state_path = config.state_file()
            self.state: LocalState = load_state(self._state_path)
            self.server_config: ServerConfig | None = None
            if self.state.server_config is not None:
                try:
                    self.server_config = ServerConfig.parse(self.state.server_config)
                except ProtocolError:
                    self.server_config = None
            self._identity_mtime = self.store.mtime()
            self.client = self._make_client()
            self.mode = MODE_ACTIVE
            self.started_at = clock()
            self.clock_offset = 0.0
            self.pending_jobs = 0
            self.active: ActiveJob | None = None
            self.next_heartbeat_at = 0.0
        except BaseException:
            # Si el resto del arranque falla (estado ilegible, cliente), la conexión SQLite
            # recién abierta no puede quedar viva hasta el GC.
            if self._owns_spool:
                self.spool.close()
            raise
        self.next_poll_at = 0.0
        self._heartbeat_failures = 0
        self._poll_failures = 0
        self._flush_not_before = 0.0
        self._server_reachable = False
        self._revoked_logged = False

    # --- utilidades -------------------------------------------------------------------

    def _make_client(self) -> SensorClient:
        url = self.config.server_url or self.identity.server_url
        return SensorClient(
            url,
            self._transport,
            timeout=self.config.request_timeout_seconds,
            credential=self.identity.credential,
        )

    def _heartbeat_interval(self) -> float:
        if self.server_config is not None:
            return self.server_config.heartbeat_interval_seconds
        return self.config.heartbeat_interval_seconds

    def _poll_interval(self) -> float:
        if self.server_config is not None:
            return self.server_config.poll_interval_seconds
        return self.config.poll_interval_seconds

    def _backoff(self, attempts: int, retry_after: float | None = None) -> float:
        return backoff_delay(
            attempts,
            BACKOFF_BASE_SECONDS,
            self.config.retry_max_delay_seconds,
            retry_after,
            self._rng,
        )

    def _persist_state(self) -> None:
        self.state.mode = self.mode
        if self.server_config is not None:
            self.state.server_config = self.server_config.to_json()
        try:
            save_state(self._state_path, self.state)
        except OSError as exc:
            logger.warning("could not persist local state", extra={"error": str(exc)})

    def server_now(self) -> datetime:
        """Hora local corregida con la del servidor: la caducidad de jobs la fija él."""
        return datetime.fromtimestamp(self._clock() + self.clock_offset, UTC)

    def wake(self) -> None:
        self._wake.set()

    def stop(self) -> None:
        self._stopping.set()
        if self.active is not None:
            self.active.scanner.request_cancel()
        self._wake.set()

    # --- bucle ------------------------------------------------------------------------

    def run(self) -> None:
        logger.info(
            "sensor started",
            extra={
                "sensor_id": self.identity.sensor_id,
                "site_id": self.identity.site_id,
                "version": __version__,
            },
        )
        while not self._stopping.is_set():
            try:
                delay = self.tick()
            except Exception:
                # Un fallo inesperado no debe tumbar el servicio: se registra y se espera.
                logger.exception("unexpected error in sensor loop")
                delay = float(self.config.retry_max_delay_seconds) / 10
            self._wake.wait(delay)
            self._wake.clear()
        self._shutdown()

    def _shutdown(self) -> None:
        try:
            active = self.active
            if active is not None:
                active.scanner.request_cancel()
                if active.thread is not None:
                    active.thread.join(timeout=30)
                self._reap_job()
            # Último intento de entregar lo pendiente; lo que no salga sigue en el spool.
            if self.mode == MODE_ACTIVE and self._server_reachable:
                self.flush()
        finally:
            # Aunque recoger el job o el último envío fallen, el spool se cierra: lo
            # pendiente ya está confirmado en disco y se reenvía en el próximo arranque.
            self.close()
        logger.info("sensor stopped")

    def close(self) -> None:
        """Libera los recursos locales del runner (la conexión del spool). Idempotente."""
        self.spool.close()

    def tick(self) -> float:
        """Una vuelta del bucle. Devuelve cuántos segundos dormir hasta la siguiente."""
        now = self._clock()
        self._maybe_reload_identity()
        if now >= self.next_heartbeat_at:
            self.heartbeat()
        self._reap_job()
        if self._can_work() and self.active is None:
            due = self.pending_jobs > 0 or now >= self.next_poll_at
            if due and self.server_config is not None and self.server_config.jobs_enabled:
                self.poll()
                # Un job ejecutado en línea (tests) ya terminó: se cierra en esta vuelta.
                self._reap_job()
        if self._can_work() and self._clock() >= self._flush_not_before:
            self.flush()
        return self._next_wait()

    def _can_work(self) -> bool:
        return self.mode == MODE_ACTIVE and self._server_reachable and not self._stopping.is_set()

    def _next_wait(self) -> float:
        now = self._clock()
        candidates = [self.next_heartbeat_at]
        if self._can_work():
            if self.active is None and self.server_config and self.server_config.jobs_enabled:
                candidates.append(self.next_poll_at)
            spool_due = self.spool.next_attempt_time()
            if spool_due is not None:
                candidates.append(max(spool_due, self._flush_not_before))
        return max(MIN_WAIT_SECONDS, min(candidates) - now)

    def _maybe_reload_identity(self) -> None:
        # Permite re-enrolar (tras una revocación) sin reiniciar el proceso.
        mtime = self.store.mtime()
        if mtime is None or mtime == self._identity_mtime:
            return
        try:
            identity = self.store.load()
        except CredentialError as exc:
            logger.error("credential file changed but cannot be loaded", extra={"error": str(exc)})
            return
        self._identity_mtime = mtime
        if identity.credential != self.identity.credential:
            logger.info("credential file changed on disk, reloaded")
            self.identity = identity
            self.client = self._make_client()
            self.mode = MODE_ACTIVE
            self._revoked_logged = False
            self.next_heartbeat_at = 0.0

    # --- heartbeat --------------------------------------------------------------------

    def heartbeat_body(self) -> dict[str, Any]:
        stats = self.spool.stats()
        queued_jobs = len({item.job_id for item in self.spool.heads()})
        body: dict[str, Any] = {
            **host_metadata(),
            "sensor_version": __version__,
            "capabilities": list(CAPABILITIES),
            # Trabajo pendiente: jobs con envíos en el spool + el que se está escaneando.
            "queue_depth": queued_jobs + (1 if self.active is not None else 0),
            "spool_items": stats.items,
            "spool_bytes": stats.bytes,
            "uptime_seconds": int(self._clock() - self.started_at),
            "sent_at": utc_iso(self._clock()),
        }
        if self.state.last_successful_job_at:
            body["last_successful_job_at"] = self.state.last_successful_job_at
        return body

    def heartbeat(self) -> None:
        now = self._clock()
        try:
            response = self.client.heartbeat(self.heartbeat_body())
            config = ServerConfig.parse(response.get("config"))
        except (TransportError, ProtocolError) as exc:
            self._heartbeat_failed(str(exc), None)
            return
        except ApiError as exc:
            if self._handle_auth_error(exc):
                return
            self._heartbeat_failed(str(exc), exc.retry_after)
            return
        recovered = self._heartbeat_failures > 0 or not self._server_reachable
        self._heartbeat_failures = 0
        self._server_reachable = True
        if recovered:
            # El servidor vuelve: lo acumulado en el spool sale ya, sin esperar a que venza
            # el backoff de cada elemento (que pudo crecer hasta el tope durante la caída).
            self.spool.reset_backoff()
            self._flush_not_before = 0.0
        self._apply_config(config)
        self._update_clock_offset(response.get("server_time"), now)
        pending = response.get("pending_jobs")
        self.pending_jobs = pending if isinstance(pending, int) and pending > 0 else 0
        status = response.get("status")
        previous_mode = self.mode
        self.mode = MODE_DISABLED if status == "disabled" else MODE_ACTIVE
        if self.mode != previous_mode:
            logger.warning("sensor mode changed", extra={"mode": self.mode})
        if self.mode == MODE_DISABLED and self.active is not None:
            self.active.scanner.request_cancel()
        cancel_ids = response.get("cancel_job_ids")
        active = self.active
        if (
            isinstance(cancel_ids, list)
            and active is not None
            and active.job.job_id in {str(c) for c in cancel_ids}
        ):
            logger.info("job cancelled by server", extra={"job_id": active.job.job_id})
            active.scanner.request_cancel()
        self.state.last_heartbeat_at = utc_iso(now)
        self._persist_state()
        self.next_heartbeat_at = now + self._heartbeat_interval()
        if response.get("rotate_credential") is True:
            self.rotate_credential()

    def _heartbeat_failed(self, error: str, retry_after: float | None) -> None:
        self._heartbeat_failures += 1
        self._server_reachable = False
        delay = self._backoff(self._heartbeat_failures, retry_after)
        # La primera caída se avisa; las siguientes a nivel debug para no inundar el log.
        level = logging.WARNING if self._heartbeat_failures in (1, 10, 100) else logging.DEBUG
        logger.log(
            level,
            "heartbeat failed, backing off",
            extra={"error": error, "failures": self._heartbeat_failures, "retry_in": delay},
        )
        self.next_heartbeat_at = self._clock() + delay

    def _handle_auth_error(self, exc: ApiError) -> bool:
        """401/403: cambia de modo, nunca descarta datos. Devuelve True si lo gestionó."""
        if exc.status == 403 and exc.code == "sensor_revoked":
            self.mode = MODE_REVOKED
            self._server_reachable = False
            if not self._revoked_logged:
                logger.error(REVOKED_INSTRUCTIONS)
                self._revoked_logged = True
            if self.active is not None:
                self.active.scanner.request_cancel()
            self.next_heartbeat_at = self._clock() + self.config.retry_max_delay_seconds
            self._persist_state()
            return True
        if exc.status == 403 and exc.code == "sensor_disabled":
            if self.mode != MODE_DISABLED:
                logger.warning("sensor is DISABLED by the server: only heartbeats are sent")
            self.mode = MODE_DISABLED
            self._server_reachable = True
            if self.active is not None:
                self.active.scanner.request_cancel()
            self.next_heartbeat_at = self._clock() + self._heartbeat_interval()
            self._persist_state()
            return True
        if exc.status in (401, 403):
            self._heartbeat_failures += 1
            if self.mode != MODE_UNAUTHORIZED:
                logger.error(
                    "server rejected the sensor credential; check enrollment",
                    extra={"code": exc.code},
                )
            self.mode = MODE_UNAUTHORIZED
            self._server_reachable = False
            self.next_heartbeat_at = self._clock() + self._backoff(self._heartbeat_failures)
            return True
        return False

    def _apply_config(self, config: ServerConfig) -> None:
        if config.site_id and config.site_id != self.identity.site_id:
            # El site se deriva de la credencial en el servidor; si no coincide, algo raro pasa.
            logger.warning("server config site differs from enrolled site")
        self.server_config = config

    def _update_clock_offset(self, server_time: object, sent_local: float) -> None:
        if not isinstance(server_time, str):
            return
        try:
            parsed = datetime.fromisoformat(server_time)
        except ValueError:
            return
        if parsed.tzinfo is None:
            return
        midpoint = (sent_local + self._clock()) / 2
        self.clock_offset = parsed.timestamp() - midpoint

    # --- rotación de credencial -------------------------------------------------------

    def rotate_credential(self) -> None:
        """Fase 2 de la rotación: pedir la nueva, guardarla de forma atómica y usarla.

        Si el guardado falla se sigue con la credencial antigua: el servidor mantiene la
        rotación pendiente y la vuelve a pedir en el siguiente heartbeat.
        """
        try:
            response = self.client.rotate_credential()
        except (TransportError, ApiError) as exc:
            logger.warning("credential rotation failed, will retry", extra={"error": str(exc)})
            return
        credential = response.get("credential")
        if not isinstance(credential, str) or not credential:
            logger.warning("credential rotation returned no credential")
            return
        issued = response.get("credential_issued_at")
        new_identity = SensorIdentity(
            sensor_id=self.identity.sensor_id,
            site_id=self.identity.site_id,
            site_name=self.identity.site_name,
            server_url=self.identity.server_url,
            credential_issued_at=issued if isinstance(issued, str) else None,
            enrolled_at=self.identity.enrolled_at,
            credential=credential,
        )
        try:
            self.store.save(new_identity)
        except OSError as exc:
            logger.error("could not store rotated credential", extra={"error": str(exc)})
            return
        self.identity = new_identity
        self._identity_mtime = self.store.mtime()
        self.client.set_credential(credential)
        logger.info(
            "sensor credential rotated", extra={"issued_at": new_identity.credential_issued_at}
        )

    # --- jobs -------------------------------------------------------------------------

    def poll(self) -> None:
        now = self._clock()
        try:
            response = self.client.poll(max_jobs=1)
            config = ServerConfig.parse(response.get("config"))
        except (TransportError, ProtocolError) as exc:
            self._poll_failed(str(exc), None)
            return
        except ApiError as exc:
            if not self._handle_auth_error(exc):
                self._poll_failed(str(exc), exc.retry_after)
            return
        self._poll_failures = 0
        self._apply_config(config)
        self.pending_jobs = 0
        self.next_poll_at = now + self._poll_interval()
        jobs = response.get("jobs")
        if not isinstance(jobs, list):
            return
        for raw in jobs[:1]:
            self._accept_job(raw, config)

    def _poll_failed(self, error: str, retry_after: float | None) -> None:
        self._poll_failures += 1
        delay = self._backoff(self._poll_failures, retry_after)
        logger.warning("job poll failed", extra={"error": error, "retry_in": delay})
        self.pending_jobs = 0
        self.next_poll_at = self._clock() + delay

    def _accept_job(self, raw: object, config: ServerConfig) -> None:
        try:
            job = validate_job(
                raw,
                sensor_id=self.identity.sensor_id,
                site_id=self.identity.site_id,
                config=config,
                now=self.server_now(),
            )
        except JobRejectedError as exc:
            logger.warning(
                "job rejected by local validation, not executed",
                extra={"job_id": exc.job_id, "reason": exc.code, "detail": exc.detail},
            )
            if exc.job_id is not None and exc.attempt is not None:
                enqueue_complete(
                    self.spool, exc.job_id, exc.attempt, "failed", errors=[exc.short_error]
                )
                self.wake()
            return
        try:
            started = self.client.start(job.job_id, job.attempt)
        except (TransportError, ApiError) as exc:
            # Sin start confirmado no se escanea: el lease caducará y el servidor decidirá.
            logger.warning("job start failed", extra={"job_id": job.job_id, "error": str(exc)})
            if isinstance(exc, ApiError):
                self._handle_auth_error(exc)
            return
        if isinstance(job.parameters, SnmpParameters):
            credentials = parse_credentials(started.get("credentials"), job.parameters)
            if credentials is None:
                logger.warning(
                    "snmp job without matching credentials, not executed",
                    extra={"job_id": job.job_id},
                )
                enqueue_complete(
                    self.spool,
                    job.job_id,
                    job.attempt,
                    "failed",
                    errors=["job_rejected:credentials_missing"],
                    snmp={"modules": {}, "error_code": "internal"},
                )
                self.wake()
                return
            # Defensa en profundidad: aunque ningún camino los registra, nunca en un log.
            for secret in (
                credentials.auth_password,
                credentials.priv_password,
                credentials.community,
            ):
                register_secret(secret)
            self._launch_snmp(job, job.parameters, credentials, config)
            return
        if isinstance(job.parameters, DhcpParameters):
            self._launch_dhcp(job, job.parameters, config)
            return
        self._launch(job, config)

    def _launch_dhcp(self, job: DiscoveryJob, params: DhcpParameters, config: ServerConfig) -> None:
        # Lotes de como mucho 5000 leases (contrato) y nunca más de lo que el servidor admite
        # por lote; el BatchBuilder además parte por bytes (max_batch_bytes).
        builder = BatchBuilder(
            self.spool,
            job.job_id,
            job.attempt,
            min(MAX_LEASES_PER_BATCH, config.max_observations_per_batch),
            config.max_batch_bytes,
            on_enqueue=self.wake,
            items_key="leases",
        )

        def emit(leases: list[dict[str, Any]]) -> None:
            builder.add(leases)
            builder.flush()

        collector = DhcpCollector(params.source_name, self.config, emit, clock=self._clock)
        active = ActiveJob(job=job, scanner=collector, builder=builder)
        self.active = active
        source = self.config.dhcp_source(params.source_name)
        # Ni la ruta ni el contenido van al log: solo el nombre (si existe) y el formato.
        logger.info(
            "job started",
            extra={
                "job_id": job.job_id,
                "job_type": job.job_type,
                "dhcp_source": source.name if source else None,
                "dhcp_format": source.format if source else None,
            },
        )

        def body() -> None:
            try:
                active.report = collector.run()
            except Exception as exc:
                logger.exception("dhcp lease import crashed", extra={"job_id": job.job_id})
                active.crash = f"dhcp error: {type(exc).__name__}"
            finally:
                active.done.set()
                self.wake()

        self._start_body(active, body)

    def _launch_snmp(
        self,
        job: DiscoveryJob,
        params: SnmpParameters,
        credentials: SnmpCredentials,
        config: ServerConfig,
    ) -> None:
        builder = BatchBuilder(
            self.spool,
            job.job_id,
            job.attempt,
            config.max_observations_per_batch,
            config.max_batch_bytes,
            on_enqueue=self.wake,
            items_key="records",
        )

        def emit(records: list[dict[str, Any]]) -> None:
            builder.add(records)
            builder.flush()

        factory = self._snmp_transport
        collector = SnmpCollector(
            params.modules,
            lambda: factory(params, credentials),
            emit,
            max_varbinds=params.max_varbinds,
            max_rows=params.max_rows_per_table,
            max_repetitions=params.max_repetitions,
            deadline_seconds=params.deadline_seconds,
        )
        active = ActiveJob(job=job, scanner=collector, builder=builder)
        self.active = active
        logger.info(
            "job started",
            extra={
                "job_id": job.job_id,
                "job_type": job.job_type,
                "target": params.address,
                "snmp_version": params.snmp_version,
                "modules": list(params.modules),
            },
        )

        def body() -> None:
            try:
                active.report = collector.run()
            except Exception as exc:
                logger.exception("snmp collection crashed", extra={"job_id": job.job_id})
                active.crash = f"snmp error: {type(exc).__name__}"
            finally:
                active.done.set()
                self.wake()

        self._start_body(active, body)

    def _start_body(self, active: ActiveJob, body: Callable[[], None]) -> None:
        if self._threaded_jobs:
            active.thread = threading.Thread(target=body, name="sensor-scan", daemon=True)
            active.thread.start()
        else:
            body()

    def _launch(self, job: DiscoveryJob, config: ServerConfig) -> None:
        assert isinstance(job.parameters, DiscoveryParameters)  # noqa: S101
        probers = self._probers()
        builder = BatchBuilder(
            self.spool,
            job.job_id,
            job.attempt,
            config.max_observations_per_batch,
            config.max_batch_bytes,
            on_enqueue=self.wake,
        )

        def emit(observations: list[Observation]) -> None:
            # Cada tanda del scan va al spool en cuanto termina: si el proceso muere a mitad
            # de un scan largo, lo ya observado sobrevive y se entrega.
            builder.add([o.to_json() for o in observations])
            builder.flush()

        scanner = Scanner(
            job.parameters,
            emit,
            tcp=probers.tcp,
            icmp=probers.icmp,
            neighbors=probers.neighbors,
            resolver=probers.resolver,
            identity=probers.identity,
        )
        active = ActiveJob(job=job, scanner=scanner, builder=builder)
        self.active = active
        logger.info(
            "job started",
            extra={
                "job_id": job.job_id,
                "job_type": job.job_type,
                "target": str(job.parameters.target),
            },
        )

        def body() -> None:
            try:
                active.report = scanner.run()
            except Exception as exc:
                logger.exception("scan crashed", extra={"job_id": job.job_id})
                active.crash = f"scan error: {type(exc).__name__}"
            finally:
                active.done.set()
                self.wake()

        self._start_body(active, body)

    def _reap_snmp(self, active: ActiveJob, report: SnmpReport | None) -> None:
        errors = list(active.builder.errors)
        if report is None:
            outcome = "failed"
            errors.insert(0, active.crash or "snmp error")
            summary: dict[str, Any] = {"modules": {}, "error_code": "internal"}
        else:
            outcome = report.outcome
            errors = report.errors + errors
            summary = report.summary()
        enqueue_complete(
            self.spool,
            active.job.job_id,
            active.job.attempt,
            outcome,
            errors=errors,
            batches_sent=active.builder.batches_enqueued,
            snmp=summary,
        )
        logger.info(
            "job finished",
            extra={
                "job_id": active.job.job_id,
                "outcome": outcome,
                "records": report.records if report is not None else 0,
                "error_code": summary.get("error_code"),
                "batches": active.builder.batches_enqueued,
            },
        )
        if outcome == "completed":
            self.state.last_successful_job_at = utc_iso(self._clock())
            self._persist_state()

    def _reap_dhcp(self, active: ActiveJob, report: DhcpReport | None) -> None:
        errors = list(active.builder.errors)
        if report is None:
            outcome = "failed"
            errors.insert(0, active.crash or "dhcp error")
            source = self.config.dhcp_source(getattr(active.job.parameters, "source_name", ""))
            summary: dict[str, Any] = {
                "format": source.format if source else None,
                "lines": 0,
                "parsed": 0,
                "skipped": 0,
                "truncated": False,
                "file_mtime": None,
                "error_code": None,
            }
        else:
            outcome = report.outcome
            errors = report.errors + errors
            summary = report.summary
        enqueue_complete(
            self.spool,
            active.job.job_id,
            active.job.attempt,
            outcome,
            errors=errors,
            batches_sent=active.builder.batches_enqueued,
            dhcp=summary,
        )
        logger.info(
            "job finished",
            extra={
                "job_id": active.job.job_id,
                "outcome": outcome,
                "leases": report.leases if report is not None else 0,
                "error_code": summary.get("error_code"),
                "batches": active.builder.batches_enqueued,
            },
        )
        if outcome == "completed":
            self.state.last_successful_job_at = utc_iso(self._clock())
            self._persist_state()

    def _reap_job(self) -> None:
        active = self.active
        if active is None or not active.done.is_set():
            return
        self.active = None
        active.builder.flush()
        report = active.report
        if isinstance(active.scanner, SnmpCollector):
            self._reap_snmp(active, report if isinstance(report, SnmpReport) else None)
            return
        if isinstance(active.scanner, DhcpCollector):
            self._reap_dhcp(active, report if isinstance(report, DhcpReport) else None)
            return
        assert not isinstance(report, SnmpReport | DhcpReport)  # noqa: S101
        errors = list(active.builder.errors)
        if report is None:
            outcome = "failed"
            errors.insert(0, active.crash or "scan error")
            report = ScanReport(0, 0, 0, [], [], False, False, 0)
        else:
            errors = report.errors + errors
            if report.cancelled:
                outcome = "cancelled"
            elif report.timed_out:
                outcome = "timed_out"
            else:
                outcome = "completed"
        enqueue_complete(
            self.spool,
            active.job.job_id,
            active.job.attempt,
            outcome,
            hosts_scanned=report.hosts_scanned,
            hosts_checked=report.hosts_checked,
            probes=report.probes,
            unprobed=report.unprobed,
            errors=errors,
            batches_sent=active.builder.batches_enqueued,
        )
        logger.info(
            "job finished",
            extra={
                "job_id": active.job.job_id,
                "outcome": outcome,
                "alive": report.alive,
                "batches": active.builder.batches_enqueued,
            },
        )
        if outcome == "completed":
            self.state.last_successful_job_at = utc_iso(self._clock())
            self._persist_state()

    # --- spool ------------------------------------------------------------------------

    def _send(self, item: SpoolItem) -> dict[str, Any]:
        if item.kind == KIND_RESULTS:
            return self.client.results(item.job_id, item.payload)
        if item.kind == KIND_COMPLETE:
            return self.client.complete(item.job_id, item.payload)
        raise ValueError(f"unknown spool kind {item.kind}")

    def flush(self) -> int:
        """Entrega lo que haya vencido en el spool. Devuelve cuántos elementos salieron."""
        delivered = 0
        skip: set[str] = set()
        while True:
            item = self.spool.next_due(skip)
            if item is None:
                break
            try:
                response = self._send(item)
            except TransportError as exc:
                # Red caída: se aplaza este elemento y se deja de intentar el resto (todos
                # fallarían igual); el heartbeat detectará cuándo vuelve el servidor.
                delay = self._backoff(item.attempts + 1)
                self.spool.defer(item.id, delay, str(exc))
                self._flush_not_before = self._clock() + delay
                break
            except ApiError as exc:
                if exc.status in (401, 403):
                    # No se descarta nada: con otra credencial o tras re-habilitar se entrega.
                    self._handle_auth_error(exc)
                    self._flush_not_before = self.next_heartbeat_at
                    break
                if exc.retryable:
                    delay = self._backoff(item.attempts + 1, exc.retry_after)
                    self.spool.defer(item.id, delay, str(exc))
                    self._flush_not_before = self._clock() + delay
                    break
                if exc.status in _DISCARD_STATUSES or 400 <= exc.status < 500:
                    self.spool.discard(item, exc.code or f"http_{exc.status}")
                    continue
                skip.add(item.job_id)
                continue
            except ValueError as exc:
                self.spool.discard(item, f"invalid item: {exc}")
                continue
            self.spool.ack(item.id)
            delivered += 1
            if item.kind == KIND_RESULTS and response.get("cancel_requested") is True:
                active = self.active
                if active is not None and active.job.job_id == item.job_id:
                    logger.info("server requested cancellation", extra={"job_id": item.job_id})
                    active.scanner.request_cancel()
            if item.kind == KIND_COMPLETE:
                logger.info(
                    "job completion delivered",
                    extra={
                        "job_id": item.job_id,
                        "status": response.get("status"),
                        "duplicate": response.get("duplicate"),
                    },
                )
        return delivered

"""Sincronización por red de las fuentes oficiales del catálogo (Fase 6C.4). Opt-in.

Solo descarga si VULN_SOURCE_SYNC_ENABLED=true, solo desde la URL fija del servidor (la
oficial o VULN_SOURCE_URLS; nunca una URL que llegue del navegador) y siempre con el cliente
seguro de Threat Intelligence (app/threat_intel/http.py: SSRF, redirecciones, tamaño,
tiempos). Sin red, o si la fuente falla, Sentra sigue con el último catálogo válido.

NVD CVE API 2.0 (incremental):
- ventanas lastModStartDate/lastModEndDate de como mucho 120 días desde el cursor (la
  lastModEndDate de la última ventana aplicada) hasta ahora; sin cursor, VULN_NVD_INITIAL_DAYS
  hacia atrás (el histórico completo se importa de los ficheros de datos por la CLI);
- paginación resultsPerPage/startIndex; cada página se valida (startIndex pedido, número de
  resultados anunciado, totalResults estable). Al final de la ventana recibidos == totalResults
  o la ventana entera se descarta (nunca se aplica una ventana a medias);
- límite de NVD: 5 peticiones por 30 s sin API key y 50 con ella (limitador propio);
- 429/503/tiempo agotado/respuesta truncada: reintento con espera exponencial, respetando
  Retry-After (acotado), como mucho VULN_SOURCE_MAX_RETRIES;
- la API key (NVD_API_KEY o NVD_API_KEY_FILE) va solo en la cabecera apiKey al host de NVD;
  nunca en logs, auditoría, errores ni respuestas.

OSV: all.zip de cada ecosistema de VULN_OSV_ECOSYSTEMS con ETag y Last-Modified por URL
(304 = sin cambios). Cada ecosistema se aplica en su propia transacción.
"""

import logging
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from app.core.config import Settings, parse_name_list
from app.core.exceptions import CatalogError, VulnerabilitySourceConflictError
from app.db.locks import VULN_SOURCE_LOCK_KEYS, singleton_lock
from app.models.vulnerability import Vulnerability, VulnerabilitySource
from app.services import audit_service
from app.services.audit_service import Actor
from app.services.vulnerability_catalog_service import identifier_count
from app.services.vulnerability_source_service import (
    MAX_INVALID_RATIO,
    MIN_RECORDS_FOR_RATIO,
    SOURCE_DEFS,
    ApplyResult,
    ContentMeta,
    StageCounts,
    StagedImport,
    Stager,
    VulnerabilitySourceService,
    apply_stage,
    auto_sync_keys,
    source_base_url,
    source_def,
    stage_diff,
)
from app.threat_intel.config import ThreatIntelConfig
from app.threat_intel.http import FetchError, FetchResult, fetch
from app.vulnerabilities.adapters import SourceFormatError, nvd, osv

logger = logging.getLogger(__name__)

Fetcher = Callable[..., FetchResult]
SYSTEM = Actor("vulnerability-sources")
SOURCE_TARGET = "vulnerability_source"
# Espera base del reintento (se duplica en cada intento) y tope de una espera.
BACKOFF_BASE_SECONDS = 6.0
MAX_BACKOFF_SECONDS = 300.0
# Tras un fallo se reintenta antes que el intervalo normal.
RETRY_AFTER_FAILURE = timedelta(hours=1)
MAX_API_KEY_LENGTH = 128
# Errores de la fuente que merecen otro intento (no un error de configuración).
_RETRYABLE_FETCH = frozenset({"unavailable", "timeout"})
_RETRYABLE_FORMAT = frozenset({"incomplete_response", "invalid_json", "invalid_archive"})


def read_api_key(settings: Settings) -> str | None:
    """API key de NVD de la variable o del fichero del servidor. Nunca se registra."""
    if settings.nvd_api_key is not None:
        value = settings.nvd_api_key.get_secret_value().strip()
        if value:
            return value[:MAX_API_KEY_LENGTH]
    if settings.nvd_api_key_file:
        try:
            value = Path(settings.nvd_api_key_file).read_text(encoding="utf-8").strip()
        except OSError:
            # Sin detalles: la ruta puede revelar la estructura del servidor.
            logger.warning("NVD API key file could not be read")
            return None
        if value and len(value) <= MAX_API_KEY_LENGTH and value.isprintable():
            return value
        logger.warning("NVD API key file is empty or invalid")
    return None


class RateLimiter:
    """Como mucho `limit` peticiones en cualquier ventana de `window` segundos."""

    def __init__(
        self,
        limit: int,
        window: float,
        clock: Callable[[], float],
        sleep: Callable[[float], None],
    ) -> None:
        self._limit = max(limit, 1)
        self._window = window
        self._clock = clock
        self._sleep = sleep
        self._sent: deque[float] = deque()

    def wait(self) -> None:
        now = self._clock()
        while self._sent and now - self._sent[0] >= self._window:
            self._sent.popleft()
        if len(self._sent) >= self._limit:
            delay = self._window - (now - self._sent[0])
            if delay > 0:
                self._sleep(delay)
            now = self._clock()
            while self._sent and now - self._sent[0] >= self._window:
                self._sent.popleft()
        self._sent.append(self._clock())


@dataclass
class SyncOutcome:
    source: str
    status: str  # success | not_modified | partial | failed
    sync_id: int | None = None
    counts: dict[str, int] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None


class SourceSyncError(Exception):
    """Fallo de la sincronización con código estable y mensaje sin datos sensibles."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class _Totals:
    requests: int = 0
    seen: int = 0
    new: int = 0
    updated: int = 0
    unchanged: int = 0
    retired: int = 0
    invalid: int = 0
    skipped: int = 0
    assets_queued: int = 0
    skipped_reasons: dict[str, int] = field(default_factory=dict)

    def add(self, counts: StageCounts, unchanged: int, applied: ApplyResult) -> None:
        self.seen += counts.seen
        self.invalid += counts.invalid
        self.skipped += counts.skipped
        self.unchanged += unchanged
        self.new += applied.new
        self.updated += applied.updated
        self.retired += applied.retired
        self.assets_queued += applied.assets_queued
        for reason, number in counts.skipped_reasons.items():
            self.skipped_reasons[reason] = self.skipped_reasons.get(reason, 0) + number

    def as_dict(self) -> dict[str, int]:
        return {
            "requests": self.requests,
            "seen": self.seen,
            "new": self.new,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "retired": self.retired,
            "invalid": self.invalid,
            "skipped": self.skipped,
            "assets_queued": self.assets_queued,
        }


def _check_invalid_ratio(counts: StageCounts) -> None:
    if counts.seen >= MIN_RECORDS_FOR_RATIO and counts.invalid > counts.seen * MAX_INVALID_RATIO:
        raise SourceSyncError(
            "too_many_invalid",
            f"{counts.invalid} of {counts.seen} records are invalid; the source format may "
            "have changed",
        )


class VulnerabilitySourceSyncer:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        fetcher: Fetcher = fetch,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        lock_engine: Callable[[], Engine] | None = None,
    ) -> None:
        self._session = session
        self._settings = settings
        self._fetch = fetcher
        self._clock = clock
        self._sleep = sleep
        self._now = now
        self._service = VulnerabilitySourceService(session, settings)
        bind = cast(Engine, session.get_bind())
        self._lock_engine = lock_engine or (lambda: bind)
        policy = ThreatIntelConfig.from_settings(settings).fetch_policy()
        # Mismas defensas que Threat Intelligence; el tope de tamaño es el de estas fuentes.
        self._policy = replace(policy, max_bytes=settings.vuln_source_max_download_mb * 1024 * 1024)

    # --- Qué toca sincronizar -----------------------------------------------------------------

    def due_sources(self, now: datetime | None = None) -> list[str]:
        """Pedidas por un admin o vencidas de VULN_SOURCE_AUTO_SYNC (nada si está apagado)."""
        if not self._settings.vuln_source_sync_enabled:
            return []
        moment = now or self._now()
        rows = {
            s.source_key: s
            for s in self._session.scalars(
                select(VulnerabilitySource).where(
                    VulnerabilitySource.source_key.in_(list(SOURCE_DEFS))
                )
            )
        }
        due: list[str] = []
        auto = auto_sync_keys(self._settings)
        for key in SOURCE_DEFS:
            source = rows.get(key)
            if source is not None and source.adapter != SOURCE_DEFS[key].adapter:
                continue
            if (source is not None and source.sync_requested_at is not None) or (
                key in auto
                and (source is None or source.next_sync_at is None or source.next_sync_at <= moment)
            ):
                due.append(key)
        return due

    # --- Sincronización -------------------------------------------------------------------------

    def sync(self, key: str, trigger: str, actor: Actor, *, full: bool = False) -> SyncOutcome:
        defn = source_def(key)
        if not self._settings.vuln_source_sync_enabled:
            raise VulnerabilitySourceConflictError(
                "vulnerability_source_sync_disabled",
                "Network sync is disabled (VULN_SOURCE_SYNC_ENABLED=false); import files instead",
            )
        with singleton_lock(self._lock_engine, VULN_SOURCE_LOCK_KEYS[defn.key]) as acquired:
            if not acquired:
                raise VulnerabilitySourceConflictError(
                    "vulnerability_source_busy",
                    "Another import or sync of this source is running",
                )
            return self._sync_locked(key, trigger, actor, full)

    def _sync_locked(self, key: str, trigger: str, actor: Actor, full: bool) -> SyncOutcome:
        defn = source_def(key)
        source = self._service.ensure(defn, lock=True)
        started_at = self._now()
        started = time.perf_counter()
        state = dict(source.sync_state or {})
        full = full or bool(state.pop("full_requested", False))
        source.sync_state = state
        source.status = "syncing"
        source.last_attempt_at = started_at
        source.sync_requested_at = None
        source.sync_requested_by = None
        self._session.commit()
        totals = _Totals()
        windows: list[tuple[datetime, datetime]] = []
        try:
            if defn.adapter == "nvd":
                status = self._sync_nvd(defn.key, totals, windows, full)
            else:
                status = self._sync_osv(defn.key, totals)
        except SourceSyncError as exc:
            self._session.rollback()
            return self._fail(key, trigger, actor, started_at, started, totals, windows, exc)
        except Exception as exc:
            self._session.rollback()
            logger.exception("vulnerability source sync failed", extra={"source": key})
            return self._fail(
                key,
                trigger,
                actor,
                started_at,
                started,
                totals,
                windows,
                SourceSyncError("internal_error", type(exc).__name__),
            )
        return self._succeed(key, trigger, actor, started_at, started, totals, windows, status)

    def _record(
        self,
        source: VulnerabilitySource,
        trigger: str,
        actor: Actor,
        started_at: datetime,
        started: float,
        totals: _Totals,
        windows: list[tuple[datetime, datetime]],
        status: str,
        error: SourceSyncError | None = None,
    ) -> int:
        details: dict[str, Any] = {}
        if totals.skipped_reasons:
            details["skipped_reasons"] = dict(sorted(totals.skipped_reasons.items()))
        row = self._service.record_sync(
            source,
            kind="sync",
            trigger=trigger,
            actor=actor,
            started_at=started_at,
            started=started,
            status=status,
            requests=totals.requests,
            window=(windows[0][0], windows[-1][1]) if windows else (None, None),
            error_code=error.code if error else None,
            error_message=error.message if error else None,
            details=details,
        )
        row.records_seen = totals.seen
        row.records_new = totals.new
        row.records_updated = totals.updated
        row.records_unchanged = totals.unchanged
        row.records_retired = totals.retired
        row.records_invalid = totals.invalid
        row.records_skipped = totals.skipped
        row.assets_queued = totals.assets_queued
        return row.id

    def _source(self, key: str) -> VulnerabilitySource:
        source = self._service.row(key)
        if source is None:  # pragma: no cover - se creó al empezar
            raise SourceSyncError("internal_error", "source row missing")
        return source

    def _succeed(
        self,
        key: str,
        trigger: str,
        actor: Actor,
        started_at: datetime,
        started: float,
        totals: _Totals,
        windows: list[tuple[datetime, datetime]],
        status: str,
    ) -> SyncOutcome:
        source = self._source(key)
        now = self._now()
        sync_id = self._record(source, trigger, actor, started_at, started, totals, windows, status)
        source.status = "ready"
        source.last_success_at = now
        source.last_error = None
        source.last_error_message = None
        # "partial": quedan ventanas de NVD por traer; la siguiente vuelta sigue enseguida.
        source.next_sync_at = (
            now
            if status == "partial"
            else now + timedelta(hours=self._settings.vuln_source_sync_interval_hours)
        )
        source.updated_at = now
        audit_service.record(
            self._session,
            actor,
            "vulnerability_source_synced",
            target_type=SOURCE_TARGET,
            target_id=key,
            details={"result": status, "trigger": trigger, **totals.as_dict()},
            commit=False,
        )
        self._session.commit()
        return SyncOutcome(key, status, sync_id, totals.as_dict())

    def _fail(
        self,
        key: str,
        trigger: str,
        actor: Actor,
        started_at: datetime,
        started: float,
        totals: _Totals,
        windows: list[tuple[datetime, datetime]],
        error: SourceSyncError,
    ) -> SyncOutcome:
        """La fuente conserva su catálogo; se apunta el error y se reintenta antes."""
        source = self._source(key)
        now = self._now()
        sync_id = self._record(
            source, trigger, actor, started_at, started, totals, windows, "failed", error
        )
        source.status = "failed"
        source.last_error = error.code[:200]
        source.last_error_message = error.message[:300]
        source.next_sync_at = now + min(
            RETRY_AFTER_FAILURE, timedelta(hours=self._settings.vuln_source_sync_interval_hours)
        )
        source.updated_at = now
        audit_service.record(
            self._session,
            actor,
            "vulnerability_source_sync_failed",
            result=audit_service.FAILURE,
            target_type=SOURCE_TARGET,
            target_id=key,
            details={"error": error.code, "trigger": trigger},
            commit=False,
        )
        self._session.commit()
        logger.warning(
            "vulnerability source sync failed", extra={"source": key, "error": error.code}
        )
        return SyncOutcome(key, "failed", sync_id, totals.as_dict(), error.code, error.message)

    # --- Descarga con reintentos ------------------------------------------------------------

    def _download(
        self,
        url: str,
        totals: _Totals,
        limiter: RateLimiter | None,
        *,
        headers: dict[str, str] | None = None,
        etag: str | None = None,
        last_modified: str | None = None,
        parse: Callable[[bytes], Any] | None = None,
    ) -> tuple[FetchResult, Any]:
        """GET con reintentos. Devuelve (resultado, parse(cuerpo) o None si 304)."""
        attempts = self._settings.vuln_source_max_retries + 1
        last: SourceSyncError | None = None
        for attempt in range(attempts):
            if limiter is not None:
                limiter.wait()
            totals.requests += 1
            wait: float | None = None
            try:
                result = self._fetch(
                    url,
                    self._policy,
                    etag=etag,
                    last_modified=last_modified,
                    headers=headers or None,
                )
            except FetchError as exc:
                retryable = exc.code in _RETRYABLE_FETCH or exc.status in (429, 503)
                last = SourceSyncError(
                    f"fetch_{exc.code}" if exc.status is None else f"http_{exc.status}",
                    exc.message,
                )
                if not retryable:
                    raise last from None
                wait = exc.retry_after
            else:
                try:
                    if result.status == 304 or parse is None:
                        return result, None
                    body = result.body.read() if result.body is not None else b""
                    try:
                        return result, parse(body)
                    except SourceFormatError as exc:
                        last = SourceSyncError(f"source_{exc.code}", str(exc))
                        if exc.code not in _RETRYABLE_FORMAT:
                            raise last from None
                finally:
                    if parse is not None:
                        result.close()
            if attempt + 1 < attempts:
                backoff = min(BACKOFF_BASE_SECONDS * (2**attempt), MAX_BACKOFF_SECONDS)
                self._sleep(min(max(wait or 0.0, backoff), MAX_BACKOFF_SECONDS * 12))
        assert last is not None  # noqa: S101 (el bucle siempre hace al menos un intento)
        raise last

    # --- NVD ------------------------------------------------------------------------------------

    def _sync_nvd(
        self,
        key: str,
        totals: _Totals,
        applied_windows: list[tuple[datetime, datetime]],
        full: bool,
    ) -> str:
        settings = self._settings
        defn = source_def(key)
        base = source_base_url(defn, settings)
        api_key = read_api_key(settings)
        limiter = RateLimiter(
            nvd.RATE_WITH_KEY if api_key else nvd.RATE_WITHOUT_KEY,
            nvd.RATE_WINDOW_SECONDS,
            self._clock,
            self._sleep,
        )
        headers = {"apiKey": api_key} if api_key else None
        source = self._source(key)
        state = dict(source.sync_state or {})
        now = self._now()
        cursor: datetime | None = None
        if not full and state.get("nvd_cursor"):
            try:
                cursor = datetime.fromisoformat(state["nvd_cursor"])
            except ValueError:
                cursor = None
        earliest = now - timedelta(days=settings.vuln_nvd_initial_days)
        start = cursor if cursor is not None else earliest
        if start > now:
            start = now
        pages_left = settings.vuln_nvd_max_pages_per_run
        per_page = settings.vuln_nvd_results_per_page
        max_bytes = self._policy.max_bytes
        for window in nvd.windows(start, now):
            pages: list[nvd.NvdPage] = []
            start_index = 0
            total: int | None = None
            complete = False
            while pages_left > 0:
                url = nvd.page_url(base, start_index=start_index, per_page=per_page, window=window)
                _, page = self._download(
                    url,
                    totals,
                    limiter,
                    headers=headers,
                    parse=lambda raw: nvd.parse_page(raw, max_bytes),
                )
                pages_left -= 1
                assert isinstance(page, nvd.NvdPage)  # noqa: S101
                if page.start_index != start_index or (
                    total is not None and page.total_results != total
                ):
                    raise SourceSyncError(
                        "incomplete_response",
                        "NVD pagination changed during the sync; the window will be retried",
                    )
                total = page.total_results
                pages.append(page)
                start_index += page.results_per_page
                if start_index >= total or page.results_per_page == 0:
                    complete = True
                    break
            if not complete:
                # Sin páginas en esta ejecución: la ventana NO se aplica a medias.
                return "partial"
            received = sum(len(p.items) for p in pages)
            if received != (total or 0):
                raise SourceSyncError(
                    "incomplete_response",
                    f"NVD announced {total} results and {received} arrived",
                )
            self._apply_nvd_window(key, pages, totals)
            applied_windows.append(window)
            source = self._source(key)
            state = dict(source.sync_state or {})
            state["nvd_cursor"] = window[1].isoformat()
            source.sync_state = state
            self._session.commit()
        return "success"

    def _apply_nvd_window(self, key: str, pages: list[nvd.NvdPage], totals: _Totals) -> None:
        """Staging y aplicación de una ventana completa en UNA transacción."""
        source = self._service.ensure(source_def(key), lock=True)
        now = self._now()
        stager = Stager(self._session)
        offset = 0
        for page in pages:
            for item in nvd.iter_records(page, now, None, offset):
                stager.add(item)
            offset += len(page.items)
        counts = stager.finish()
        _check_invalid_ratio(counts)
        diff = stage_diff(self._session, source.id)
        staged = StagedImport(counts, diff, ContentMeta(nvd.FORMAT), "", 0)
        applied = apply_stage(self._session, self._service._catalog, source, now)
        totals.add(counts, diff.unchanged, applied)
        self._refresh_counts(source, staged, applied, now)

    def _refresh_counts(
        self,
        source: VulnerabilitySource,
        staged: StagedImport,
        applied: ApplyResult,
        now: datetime,
    ) -> None:
        if applied.new or applied.updated or applied.retired or source.revision == 0:
            source.revision += 1
            source.records = int(
                self._session.scalar(
                    select(func.count()).where(Vulnerability.source_id == source.id)
                )
                or 0
            )
            source.identifier_count = identifier_count(self._session, source.id)
        source.last_import_result = {
            "new": applied.new,
            "updated": applied.updated,
            "unchanged": staged.diff.unchanged,
            "retired": applied.retired,
            "invalid": staged.counts.invalid,
            "skipped": staged.counts.skipped,
            "assets_queued": applied.assets_queued,
        }
        source.updated_at = now

    # --- OSV ------------------------------------------------------------------------------------

    def _sync_osv(self, key: str, totals: _Totals) -> str:
        settings = self._settings
        defn = source_def(key)
        base = source_base_url(defn, settings)
        ecosystems = parse_name_list(settings.vuln_osv_ecosystems)
        any_changed = False
        for ecosystem in ecosystems:
            url = osv.download_url(base, ecosystem)
            source = self._source(key)
            state = dict(source.sync_state or {})
            cache = dict((state.get("osv") or {}).get(ecosystem) or {})
            has_data = source.records > 0
            result, _ = self._download(
                url,
                totals,
                None,
                etag=cache.get("etag") if has_data else None,
                last_modified=cache.get("last_modified") if has_data else None,
            )
            try:
                if result.status == 304 or (
                    has_data and result.sha256 is not None and result.sha256 == cache.get("sha256")
                ):
                    continue
                body = result.body.read() if result.body is not None else b""
            finally:
                result.close()
            source = self._service.ensure(defn, lock=True)
            now = self._now()
            try:
                staged = self._service.stage(
                    defn, body, source, retrieved_at=now, prefer_cve_records=ecosystem == "Ubuntu"
                )
            except CatalogError as exc:
                raise SourceSyncError(exc.code, exc.message) from None
            _check_invalid_ratio(staged.counts)
            applied = apply_stage(self._session, self._service._catalog, source, now)
            totals.add(staged.counts, staged.diff.unchanged, applied)
            self._refresh_counts(source, staged, applied, now)
            source = self._source(key)
            state = dict(source.sync_state or {})
            osv_state = dict(state.get("osv") or {})
            osv_state[ecosystem] = {
                "etag": (result.etag or "")[:256] or None,
                "last_modified": (result.last_modified or "")[:64] or None,
                "sha256": result.sha256,
                "synced_at": now.isoformat(),
            }
            state["osv"] = osv_state
            source.sync_state = state
            source.last_import_sha256 = result.sha256
            self._session.commit()
            any_changed = True
        return "success" if any_changed else "not_modified"

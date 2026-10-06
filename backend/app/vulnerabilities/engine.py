"""VulnerabilityEngine: evaluación por lotes con base de datos (Fase 5B).

Inventario -> normalización -> candidatos del catálogo -> match -> evidencia -> finding ->
riesgo. Cada paso reutiliza lo que ya existe en Sentra:
- inventario del agente (asset_inventories) y SO del activo: nunca un segundo inventario;
- candidatos por índice GIN (vulnerability_affected.match_keys && claves del activo): nunca
  "cada software contra cada CVE";
- exposición de Discovery (asset_ports) y contexto de negocio (4L) para la prioridad;
- cola del Risk Engine (request_recalculation) y AlertService (una alerta por activo).

Cuándo se evalúa: cola `asset_vulnerability_state.dirty_at` (inventario o SO cambiados,
puertos, contexto, catálogo actualizado, petición de un admin) y un refresco periódico.
Nunca en cada heartbeat. Un inventario idéntico al ya evaluado solo renueva last_seen_at.

Reglas de resolución (conservadoras: ante la duda, el finding sigue abierto):
- versión fuera de todos los rangos -> resolved_by_inventory_change;
- componente ausente en N capturas COMPLETAS consecutivas -> resolved_by_component_removal
  (inventario incompleto o sección fallida NO resuelve nada);
- el catálogo deja de describir el producto -> resolved_by_catalog_update;
- activo offline o inventario antiguo -> nunca resuelve (la evidencia se marca antigua).
Si el componente vulnerable vuelve, el finding se reabre (reopen_count) y puede alertar.

Aislamiento de fallos: cada activo en su SAVEPOINT; un fallo se cuenta en error_count y
vuelve a la cola. Un fallo del job nunca afecta a la API.
"""

import ipaddress
import logging
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import exists, literal, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.metrics import REGISTRY
from app.discovery.ports import parse_ports
from app.models.alert import AlertRule, AlertSeverity
from app.models.asset import Asset
from app.models.exposure import AssetPort, PortStateValue
from app.models.inventory import AssetInventory
from app.models.vulnerability import (
    AssetVulnerabilityState,
    Vulnerability,
    VulnerabilityAffected,
    VulnerabilityFinding,
    VulnerabilityFindingHistory,
)
from app.risk.queue import request_recalculation
from app.services import audit_service
from app.services.alert_service import AlertService, AlertThresholds
from app.services.asset_context_service import ContextValues, context_values
from app.services.audit_service import Actor
from app.vulnerabilities import priority as priority_mod
from app.vulnerabilities import workflow
from app.vulnerabilities.catalog import SEVERITY_RANK
from app.vulnerabilities.exposure import EXPOSURE_RANK, AssetExposure, assess
from app.vulnerabilities.matcher import (
    STATE_RANK,
    AffectedRule,
    AssetSoftware,
    MatchResult,
    VulnerabilityMatcher,
    build_asset_software,
)

logger = logging.getLogger(__name__)

SYSTEM_ACTOR = "sentra"
# Actor de auditoría de los cambios automáticos (caducidad de un riesgo aceptado).
SYSTEM = Actor(SYSTEM_ACTOR)
# Límite de lotes por pasada del job: el resto queda para la siguiente vuelta.
MAX_BATCHES = 10
# Cota defensiva de filas candidatas por activo. Si se alcanza, la evaluación no resuelve
# nada por ausencia (podría faltar un candidato) y lo registra.
MAX_CANDIDATES = 50_000
# Severidades que pueden alertar (siempre con evidencia confirmed/probable).
_ALERT_EXPOSED = frozenset({"observed", "internet_exposed"})


@dataclass(frozen=True)
class VulnerabilityConfig:
    enabled: bool = True
    batch_size: int = 50
    full_refresh: timedelta = timedelta(hours=24)
    stale_inventory: timedelta = timedelta(hours=72)
    missing_threshold: int = 2
    alert_enabled: bool = True
    alert_cooldown: timedelta = timedelta(hours=24)
    # Puertos que prueba discovery: solo esos pueden quedar "no observados".
    probed_ports: frozenset[int] = frozenset()
    max_candidates: int = MAX_CANDIDATES

    @classmethod
    def from_settings(cls, settings: Settings) -> "VulnerabilityConfig":
        try:
            probed = frozenset(parse_ports(settings.discovery_ports))
        except ValueError:
            probed = frozenset()
        return cls(
            enabled=settings.vuln_enabled,
            batch_size=settings.vuln_batch_size,
            full_refresh=timedelta(hours=settings.vuln_full_refresh_hours),
            stale_inventory=timedelta(hours=settings.vuln_stale_inventory_hours),
            missing_threshold=settings.vuln_missing_threshold,
            alert_enabled=settings.vuln_alert_enabled,
            alert_cooldown=timedelta(hours=settings.vuln_alert_cooldown_hours),
            probed_ports=probed,
        )


@dataclass
class VulnerabilityRun:
    assets: int = 0
    unchanged: int = 0
    created: int = 0
    updated: int = 0
    resolved: int = 0
    reopened: int = 0
    alerts: int = 0
    errors: int = 0
    failed_assets: list[int] = field(default_factory=list)

    def add(self, other: "VulnerabilityRun") -> None:
        for name in ("assets", "unchanged", "created", "updated", "resolved", "reopened"):
            setattr(self, name, getattr(self, name) + getattr(other, name))
        self.alerts += other.alerts
        self.errors += other.errors
        self.failed_assets.extend(other.failed_assets)

    def as_dict(self) -> dict[str, int]:
        return {
            "assets": self.assets,
            "unchanged": self.unchanged,
            "created": self.created,
            "updated": self.updated,
            "resolved": self.resolved,
            "reopened": self.reopened,
            "alerts": self.alerts,
            "errors": self.errors,
        }


@dataclass
class _AssetData:
    asset: Asset
    software: AssetSoftware
    software_present: bool
    exposure: AssetExposure
    context: ContextValues


def is_stale(observed_at: datetime | None, now: datetime, config: VulnerabilityConfig) -> bool:
    """Evidencia antigua: el inventario que la respalda es más viejo que el umbral."""
    return observed_at is None or now - observed_at > config.stale_inventory


def add_history(
    session: Session,
    finding: VulnerabilityFinding,
    action: str,
    now: datetime,
    *,
    actor: str = SYSTEM_ACTOR,
    actor_user_id: int | None = None,
    from_value: str | None = None,
    to_value: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    session.add(
        VulnerabilityFindingHistory(
            finding_id=finding.id,
            occurred_at=now,
            action=action,
            actor=actor[:64],
            actor_user_id=actor_user_id,
            from_value=from_value[:128] if from_value else from_value,
            to_value=to_value[:128] if to_value else to_value,
            details=details or None,
        )
    )


def review_basis(finding: VulnerabilityFinding, content_hash: str | None) -> dict[str, Any]:
    """Lo que vio una persona al decidir (falso positivo, riesgo aceptado, resolución)."""
    return {
        "installed_version": finding.installed_version,
        "match_state": finding.match_state,
        "content": content_hash,
    }


def _material_change(
    basis: Mapping[str, Any] | None, installed_version: str | None, content_hash: str
) -> bool:
    """Cambio material respecto a la decisión humana: otra versión u otro registro."""
    if not basis:
        return False
    return basis.get("installed_version") != installed_version or basis.get("content") not in (
        None,
        content_hash,
    )


class VulnerabilityEngine:
    def __init__(
        self,
        session: Session,
        config: VulnerabilityConfig,
        thresholds: AlertThresholds | None = None,
    ) -> None:
        self._session = session
        self._config = config
        self._alerts = AlertService(session, thresholds) if thresholds is not None else None
        self._matcher = VulnerabilityMatcher()

    # --- Selección de activos ----------------------------------------------------------------

    def seed_missing(self, limit: int = 1000) -> int:
        """Crea la fila (pendiente) de activos con agente que aún no tienen estado. Commit."""
        missing = (
            select(
                Asset.id,
                literal(datetime.now(UTC)).label("dirty_at"),
                literal("initial").label("dirty_reason"),
            )
            .where(
                Asset.agent_id.is_not(None),
                ~exists().where(AssetVulnerabilityState.asset_id == Asset.id),
            )
            .order_by(Asset.id)
            .limit(limit)
        )
        result = self._session.execute(
            insert(AssetVulnerabilityState)
            .from_select(["asset_id", "dirty_at", "dirty_reason"], missing)
            .on_conflict_do_nothing(index_elements=[AssetVulnerabilityState.asset_id])
        )
        self._session.commit()
        return int(getattr(result, "rowcount", 0) or 0)

    def process_dirty(
        self, now: datetime | None = None, max_batches: int = MAX_BATCHES
    ) -> VulnerabilityRun:
        """Evalúa la cola de pendientes por lotes. Commit por lote."""
        return self._process(
            [AssetVulnerabilityState.dirty_at.is_not(None)],
            [AssetVulnerabilityState.dirty_at],
            now,
            max_batches,
            force=False,
        )

    def process_refresh(
        self, now: datetime | None = None, max_batches: int = MAX_BATCHES
    ) -> VulnerabilityRun:
        """Reevalúa activos no evaluados desde hace VULN_FULL_REFRESH_HOURS. Commit por lote."""
        moment = now or datetime.now(UTC)
        return self._process(
            [
                AssetVulnerabilityState.dirty_at.is_(None),
                AssetVulnerabilityState.evaluated_at < moment - self._config.full_refresh,
            ],
            [AssetVulnerabilityState.evaluated_at],
            now,
            max_batches,
            force=True,
        )

    def evaluate(self, asset_ids: Sequence[int], now: datetime | None = None) -> VulnerabilityRun:
        """Evalúa ya estos activos (petición de un admin). Sin commit."""
        rows = list(
            self._session.scalars(
                select(AssetVulnerabilityState)
                .where(AssetVulnerabilityState.asset_id.in_(list(asset_ids)))
                .with_for_update()
            ).all()
        )
        found = {row.asset_id for row in rows}
        for asset_id in asset_ids:
            if asset_id not in found:
                row = AssetVulnerabilityState(asset_id=asset_id, product_keys=[])
                self._session.add(row)
                rows.append(row)
        self._session.flush()
        return self._evaluate_rows(rows, now or datetime.now(UTC), force=True)

    def _process(
        self,
        where: list[Any],
        order: list[Any],
        now: datetime | None,
        max_batches: int,
        *,
        force: bool,
    ) -> VulnerabilityRun:
        run = VulnerabilityRun()
        seen: set[int] = set()
        started = time.perf_counter()
        for _ in range(max_batches):
            moment = now or datetime.now(UTC)
            # SKIP LOCKED: varios workers (o la evaluación manual) no se pisan.
            rows = self._session.scalars(
                select(AssetVulnerabilityState)
                .where(
                    *where,
                    AssetVulnerabilityState.asset_id.not_in(seen) if seen else literal(True),
                )
                .order_by(*order, AssetVulnerabilityState.asset_id)
                .limit(self._config.batch_size)
                .with_for_update(skip_locked=True)
            ).all()
            if not rows:
                break
            seen.update(row.asset_id for row in rows)
            run.add(self._evaluate_rows(rows, moment, force=force))
            self._session.commit()
            if len(rows) < self._config.batch_size:
                break
        if run.assets or run.errors:
            REGISTRY.observe_vulnerabilities(run.as_dict(), time.perf_counter() - started)
        if run.created or run.resolved or run.reopened or run.errors:
            # Prefijo: "created" es un atributo reservado de LogRecord.
            logger.info(
                "vulnerability evaluation run",
                extra={f"findings_{k}": v for k, v in run.as_dict().items()},
            )
        return run

    # --- Evaluación ----------------------------------------------------------------------------

    def _evaluate_rows(
        self, rows: Sequence[AssetVulnerabilityState], now: datetime, *, force: bool
    ) -> VulnerabilityRun:
        run = VulnerabilityRun()
        data = self._load(rows)
        for row in rows:
            item = data.get(row.asset_id)
            if item is None:  # activo borrado entre la selección y la carga
                continue
            try:
                with self._session.begin_nested():
                    self._evaluate_asset(item, row, now, run, force=force)
                run.assets += 1
            except Exception as exc:
                run.errors += 1
                run.failed_assets.append(row.asset_id)
                logger.exception(
                    "vulnerability evaluation failed", extra={"asset_id": row.asset_id}
                )
                row.error_count = (row.error_count or 0) + 1
                row.last_error = type(exc).__name__[:200]
                row.dirty_at = now
        return run

    def _load(self, rows: Sequence[AssetVulnerabilityState]) -> dict[int, _AssetData]:
        """Entradas de todo el lote en pocas consultas (no una por activo)."""
        ids = [row.asset_id for row in rows]
        if not ids:
            return {}
        assets = list(self._session.scalars(select(Asset).where(Asset.id.in_(ids))))
        inventories = {
            inv.asset_id: inv
            for inv in self._session.scalars(
                select(AssetInventory).where(AssetInventory.asset_id.in_(ids))
            )
        }
        open_ports: dict[int, set[int]] = {}
        for asset_id, port in self._session.execute(
            select(AssetPort.asset_id, AssetPort.port).where(
                AssetPort.asset_id.in_(ids),
                AssetPort.state == PortStateValue.OPEN,
                AssetPort.protocol == "tcp",
            )
        ):
            open_ports.setdefault(asset_id, set()).add(port)
        contexts = context_values(self._session, assets)
        result: dict[int, _AssetData] = {}
        for asset in assets:
            inventory = inventories.get(asset.id)
            document = inventory.data if inventory is not None else None
            software = build_asset_software(
                os_name=asset.os_name,
                os_version=asset.os_version,
                inventory=document,
                collected_at=inventory.collected_at if inventory is not None else None,
            )
            raw_software = (document or {}).get("software")
            result[asset.id] = _AssetData(
                asset=asset,
                software=software,
                software_present=isinstance(raw_software, list) and bool(raw_software),
                exposure=AssetExposure(
                    observed_open=frozenset(open_ports.get(asset.id, ())),
                    listening=_listening_ports(document),
                    scanned=asset.exposure_baseline_at is not None,
                    probed=self._config.probed_ports,
                    internet_exposed=contexts[asset.id].internet_exposed,
                ),
                context=contexts[asset.id],
            )
        return result

    def _evaluate_asset(
        self,
        item: _AssetData,
        state: AssetVulnerabilityState,
        now: datetime,
        run: VulnerabilityRun,
        *,
        force: bool,
    ) -> None:
        asset, software = item.asset, item.software
        fingerprint = software.fingerprint()
        if (
            not force
            and state.dirty_reason == "inventory"
            and state.input_hash == fingerprint
            and not state.pending_removal
            and state.evaluated_at is not None
        ):
            # Inventario idéntico al evaluado: la evidencia sigue vigente, nada más cambia.
            self._session.execute(
                update(VulnerabilityFinding)
                .where(
                    VulnerabilityFinding.asset_id == asset.id,
                    VulnerabilityFinding.status != workflow.RESOLVED,
                )
                .values(last_seen_at=now, inventory_observed_at=software.collected_at)
            )
            self._finish(state, software, fingerprint, now, pending_removal=False)
            run.unchanged += 1
            return

        candidates, truncated = self._candidates(software)
        results = self._match(software, candidates)
        vulns = self._vulnerabilities({vuln_id for vuln_id, _ in results})
        findings = {
            (f.vulnerability_id, f.component_key): f
            for f in self._session.scalars(
                select(VulnerabilityFinding)
                .where(VulnerabilityFinding.asset_id == asset.id)
                .with_for_update()
            )
        }
        risk_changed = False
        alerts: list[tuple[VulnerabilityFinding, str]] = []
        new: list[tuple[VulnerabilityFinding, MatchResult]] = []

        for (vuln_id, component_key), result in results.items():
            vuln = vulns.get(vuln_id)
            if vuln is None:
                continue
            existing = findings.pop((vuln_id, component_key), None)
            assessment = assess(result.rule.service_ports, item.exposure)
            prio = priority_mod.calculate(
                priority_mod.PriorityInputs(
                    severity=vuln.severity,
                    match_state=result.state,
                    exposure_state=assessment.state,
                    criticality=item.context.criticality,
                    environment=item.context.environment,
                    data_sensitivity=item.context.data_sensitivity,
                )
            )
            evidence = result.evidence(software.collected_at)
            exposure_json = assessment.to_json(item.exposure.internet_exposed)
            if existing is None:
                if not result.active:
                    continue
                finding = VulnerabilityFinding(
                    asset_id=asset.id,
                    vulnerability_id=vuln.id,
                    component_key=component_key[:255],
                    component_type=result.component.type,
                    status=workflow.OPEN,
                    status_changed_at=now,
                    status_changed_by=SYSTEM_ACTOR,
                    source=result.component.source,
                    evidence_kind="reported",
                    first_seen_at=now,
                    created_at=now,
                    missing_count=0,
                    reopen_count=0,
                    version=1,
                )
                self._apply(finding, vuln, result, evidence, assessment.state, exposure_json, prio)
                finding.last_seen_at = now
                finding.evaluated_at = now
                finding.inventory_observed_at = software.collected_at
                finding.updated_at = now
                self._session.add(finding)
                new.append((finding, result))
                run.created += 1
                risk_changed = True
                if self._alert_worthy(finding):
                    alerts.append((finding, "new"))
                continue

            previous_version = existing.installed_version
            changed, reasons = self._update(
                existing, vuln, result, evidence, assessment.state, exposure_json, prio, now
            )
            if result.active:
                existing.last_seen_at = now
                existing.inventory_observed_at = software.collected_at
                existing.missing_count = 0
            existing.evaluated_at = now
            reopened = False
            if existing.status == workflow.RESOLVED and result.active:
                if existing.resolution != workflow.RESOLVED_MANUAL or _material_change(
                    existing.review_basis, result.installed_version, vuln.content_hash
                ):
                    self._reopen(existing, now, "reappeared")
                    reopened = True
            elif existing.status == workflow.FALSE_POSITIVE and result.active:
                if _material_change(
                    existing.review_basis, result.installed_version, vuln.content_hash
                ):
                    self._reopen(existing, now, "material_change")
                    reopened = True
            elif existing.status != workflow.RESOLVED and not result.active:
                # Misma versión instalada y ya no afectada: lo cambió el catálogo (rango
                # corregido), no el equipo.
                resolution = (
                    workflow.RESOLVED_BY_INVENTORY
                    if previous_version != result.installed_version
                    else workflow.RESOLVED_BY_CATALOG
                )
                self._resolve(existing, resolution, now, result)
                run.resolved += 1
                risk_changed = True
            if reopened:
                run.reopened += 1
                risk_changed = True
                if self._alert_worthy(existing):
                    alerts.append((existing, "reappeared"))
            elif changed:
                run.updated += 1
                risk_changed = True
                if "exposure" in reasons and self._alert_worthy(existing):
                    alerts.append((existing, "exposed"))
                elif "match_up" in reasons and self._alert_worthy(existing):
                    alerts.append((existing, "confirmed"))

        if new:
            self._session.flush()
            for finding, result in new:
                add_history(
                    self._session,
                    finding,
                    "created",
                    now,
                    to_value=finding.match_state,
                    details={"installed_version": result.installed_version},
                )

        pending_removal = False
        for finding in findings.values():
            if finding.status == workflow.RESOLVED:
                continue
            outcome = self._absent(finding, item, truncated, now)
            if outcome == "resolved":
                run.resolved += 1
                risk_changed = True
            elif outcome == "pending":
                pending_removal = True

        if alerts:
            run.alerts += self._raise(asset, alerts, now)
        self._maybe_clear_alert(asset, now)
        if risk_changed:
            request_recalculation(self._session, [asset.id])
        self._finish(state, software, fingerprint, now, pending_removal=pending_removal)

    def _candidates(self, software: AssetSoftware) -> tuple[Sequence[Any], bool]:
        keys = software.keys
        if not keys:
            return [], False
        # CTE MATERIALIZED: primero el índice GIN y después el orden. Con ORDER BY id + LIMIT
        # directos, PostgreSQL recorre la clave primaria filtrando fila a fila (todo el
        # catálogo por activo: ~40 ms con 100 000 registros frente a <1 ms).
        matching = (
            select(
                VulnerabilityAffected.id,
                VulnerabilityAffected.vulnerability_id,
                VulnerabilityAffected.match_keys,
                VulnerabilityAffected.definition,
            )
            .where(VulnerabilityAffected.match_keys.overlap(keys))
            .cte("matching")
            .prefix_with("MATERIALIZED")
        )
        rows = self._session.execute(
            select(
                matching.c.id,
                matching.c.vulnerability_id,
                matching.c.match_keys,
                matching.c.definition,
            )
            .order_by(matching.c.id)
            .limit(self._config.max_candidates + 1)
        ).all()
        truncated = len(rows) > self._config.max_candidates
        if truncated:
            logger.warning(
                "vulnerability candidates truncated", extra={"limit": self._config.max_candidates}
            )
        return rows[: self._config.max_candidates], truncated

    def _match(
        self, software: AssetSoftware, candidates: Sequence[Any]
    ) -> dict[tuple[int, str], MatchResult]:
        best: dict[tuple[int, str], MatchResult] = {}
        for _row_id, vuln_id, keys, definition in candidates:
            rule = AffectedRule.from_definition(definition)
            for key in keys:
                component = software.components.get(key)
                if component is None:
                    continue
                result = self._matcher.match(component, rule, software)
                if result is None:
                    continue
                current = best.get((vuln_id, key))
                if current is None or STATE_RANK[result.state] > STATE_RANK[current.state]:
                    best[(vuln_id, key)] = result
        # Linux: el mismo paquete puede casar como paquete (clave pkg:) y como aplicación
        # (clave name:). Gana la entrada de paquete, más precisa: un finding, no dos.
        packaged: dict[int, set[str]] = {}
        for (vuln_id, _), result in best.items():
            if result.component.type == "package":
                packaged.setdefault(vuln_id, set()).update(
                    i.name for i in result.component.instances
                )
        return {
            (vuln_id, key): result
            for (vuln_id, key), result in best.items()
            if not (
                result.component.type == "application"
                and any(i.name in packaged.get(vuln_id, ()) for i in result.component.instances)
            )
        }

    def _vulnerabilities(self, ids: Iterable[int]) -> dict[int, Vulnerability]:
        id_list = sorted(set(ids))
        if not id_list:
            return {}
        return {
            v.id: v
            for v in self._session.scalars(
                select(Vulnerability).where(Vulnerability.id.in_(id_list))
            )
        }

    def _apply(
        self,
        finding: VulnerabilityFinding,
        vuln: Vulnerability,
        result: MatchResult,
        evidence: dict[str, Any],
        exposure_state: str,
        exposure: dict[str, Any],
        prio: priority_mod.Priority,
    ) -> None:
        instance = result.instance
        finding.component_name = instance.name[:512]
        vendor = instance.publisher or result.component.vendor
        finding.component_vendor = vendor[:512] if vendor else None
        finding.installed_version = instance.version
        finding.fixed_version = result.rule.fixed_version
        finding.affected_range = result.rule.range_label() or None
        finding.vuln_external_id = vuln.external_id
        finding.title = vuln.title[:300]
        finding.severity = vuln.severity
        finding.severity_rank = SEVERITY_RANK.get(vuln.severity, 0)
        finding.cvss_score = vuln.cvss_score
        finding.match_state = result.state
        finding.confidence = result.confidence
        finding.rationale = result.rationale[:500]
        finding.evidence = evidence
        finding.exposure_state = exposure_state
        finding.exposure = exposure
        finding.priority_score = prio.score
        finding.priority_level = prio.level
        finding.priority_factors = list(prio.factors)

    def _update(
        self,
        finding: VulnerabilityFinding,
        vuln: Vulnerability,
        result: MatchResult,
        evidence: dict[str, Any],
        exposure_state: str,
        exposure: dict[str, Any],
        prio: priority_mod.Priority,
        now: datetime,
    ) -> tuple[bool, set[str]]:
        """Actualiza un finding existente; historial de cada cambio visible."""
        before: dict[str, Any] = {
            "version": finding.installed_version,
            "match": finding.match_state,
            "severity": finding.severity,
            "exposure": finding.exposure_state,
            "priority": finding.priority_score,
        }
        if not result.active and finding.status == workflow.RESOLVED:
            # Sigue sin afectar: solo la última evaluación.
            return False, set()
        self._apply(finding, vuln, result, evidence, exposure_state, exposure, prio)
        reasons: set[str] = set()
        if before["version"] != finding.installed_version:
            reasons.add("version")
            add_history(
                self._session,
                finding,
                "version_changed",
                now,
                from_value=before["version"],
                to_value=finding.installed_version,
            )
        if before["match"] != finding.match_state:
            up = STATE_RANK.get(finding.match_state, 0) > STATE_RANK.get(str(before["match"]), 0)
            reasons.add("match_up" if up else "match")
            add_history(
                self._session,
                finding,
                "match_changed",
                now,
                from_value=str(before["match"]),
                to_value=finding.match_state,
            )
        if before["severity"] != finding.severity:
            reasons.add("severity")
            add_history(
                self._session,
                finding,
                "severity_changed",
                now,
                from_value=str(before["severity"]),
                to_value=finding.severity,
                details={"record_version": vuln.record_version},
            )
        if before["exposure"] != finding.exposure_state:
            more = self._more_exposed(before["exposure"], exposure_state)
            reasons.add("exposure" if more else "exposure_down")
            add_history(
                self._session,
                finding,
                "exposure_changed",
                now,
                from_value=str(before["exposure"]),
                to_value=finding.exposure_state,
            )
        if reasons or before["priority"] != finding.priority_score:
            finding.version += 1
            finding.updated_at = now
        return bool(reasons), reasons

    @staticmethod
    def _more_exposed(before: Any, after: str) -> bool:
        return EXPOSURE_RANK.get(after, 0) > EXPOSURE_RANK.get(str(before), 0)

    def _reopen(self, finding: VulnerabilityFinding, now: datetime, why: str) -> None:
        previous = finding.status
        finding.status = workflow.OPEN
        finding.status_reason = None
        finding.status_changed_at = now
        finding.status_changed_by = SYSTEM_ACTOR
        finding.status_changed_by_user_id = None
        finding.resolution = None
        finding.resolved_at = None
        finding.accepted_until = None
        finding.review_basis = None
        finding.reopen_count += 1
        finding.missing_count = 0
        finding.version += 1
        finding.updated_at = now
        add_history(
            self._session,
            finding,
            "reopened",
            now,
            from_value=previous,
            to_value=workflow.OPEN,
            details={"reason": why, "installed_version": finding.installed_version},
        )

    def _resolve(
        self,
        finding: VulnerabilityFinding,
        resolution: str,
        now: datetime,
        result: MatchResult | None = None,
    ) -> None:
        previous = finding.status
        finding.status = workflow.RESOLVED
        finding.resolution = resolution
        finding.resolved_at = now
        finding.status_changed_at = now
        finding.status_changed_by = SYSTEM_ACTOR
        finding.status_changed_by_user_id = None
        finding.status_reason = None
        finding.accepted_until = None
        finding.evaluated_at = now
        if result is not None:
            finding.match_state = "not_affected"
            finding.confidence = result.confidence
            finding.rationale = result.rationale[:500]
        finding.version += 1
        finding.updated_at = now
        add_history(
            self._session,
            finding,
            "resolved",
            now,
            from_value=previous,
            to_value=workflow.RESOLVED,
            details={"resolution": resolution, "installed_version": finding.installed_version},
        )

    def _absent(
        self, finding: VulnerabilityFinding, item: _AssetData, truncated: bool, now: datetime
    ) -> str | None:
        """Finding sin resultado en esta evaluación: ¿desinstalado, catálogo o sin datos?"""
        component = item.software.components.get(finding.component_key)
        if component is not None:
            if truncated:
                return None
            # El producto sigue ahí pero ya no hay entrada del catálogo que lo describa.
            self._resolve(finding, workflow.RESOLVED_BY_CATALOG, now)
            return "resolved"
        if not self._removal_trustworthy(finding, item):
            # Inventario incompleto, sección fallida o activo sin datos: no se resuelve.
            return None
        finding.missing_count = (finding.missing_count or 0) + 1
        if finding.missing_count < self._config.missing_threshold:
            return "pending"
        self._resolve(finding, workflow.RESOLVED_BY_REMOVAL, now)
        return "resolved"

    @staticmethod
    def _removal_trustworthy(finding: VulnerabilityFinding, item: _AssetData) -> bool:
        software = item.software
        if finding.component_type == "os":
            # El SO no se "desinstala": solo cambia (otra clave) si cambia de familia.
            return software.platform is not None
        if software.complete is True:
            return True
        # Agentes anteriores a 5B no declaran completitud: una lista vacía puede ser una
        # sección fallida, así que solo una lista con contenido permite resolver.
        return software.complete is None and item.software_present

    # --- Alertas -------------------------------------------------------------------------------

    @staticmethod
    def _alert_worthy(finding: VulnerabilityFinding) -> bool:
        """Solo cambios relevantes: crítica confirmada, o alta/crítica (confirmada o probable)
        con el servicio afectado observado. Potenciales y desconocidas nunca alertan."""
        if finding.status not in workflow.ACTIVE_STATUSES:
            return False
        if finding.match_state == "confirmed" and finding.severity == "critical":
            return True
        return (
            finding.match_state in ("confirmed", "probable")
            and finding.severity in ("high", "critical")
            and finding.exposure_state in _ALERT_EXPOSED
        )

    def _raise(
        self, asset: Asset, alerts: Sequence[tuple[VulnerabilityFinding, str]], now: datetime
    ) -> int:
        if self._alerts is None or not self._config.alert_enabled:
            return 0
        fresh = [
            (finding, why)
            for finding, why in alerts
            if finding.alerted_at is None or now - finding.alerted_at >= self._config.alert_cooldown
        ]
        if not fresh:
            return 0
        fresh.sort(key=lambda pair: (-pair[0].priority_score, pair[0].vuln_external_id))
        lead, why = fresh[0]
        critical = any(
            f.severity == "critical" or f.exposure_state == "internet_exposed" for f, _ in fresh
        )
        more = f" (+{len(fresh) - 1} more)" if len(fresh) > 1 else ""
        reason = {
            "new": "detected",
            "reappeared": "reappeared",
            "exposed": "now exposed",
            "confirmed": "confirmed",
        }[why]
        self._alerts.raise_alert(
            asset,
            AlertRule.VULNERABILITY,
            AlertSeverity.CRITICAL if critical else AlertSeverity.WARNING,
            f"Vulnerability {lead.vuln_external_id} ({lead.severity}, {lead.match_state})"
            f" {reason} on {asset.display_name}: {lead.component_name}"
            f" {lead.installed_version or ''}".rstrip()
            + more,
            now,
            {
                "finding_id": str(lead.public_id),
                "vulnerability_id": lead.vuln_external_id,
                "severity": lead.severity,
                "match_state": lead.match_state,
                "exposure_state": lead.exposure_state,
                "reason": why,
                "findings": len(fresh),
            },
        )
        for finding, _ in fresh:
            finding.alerted_at = now
        return 1

    def _maybe_clear_alert(self, asset: Asset, now: datetime) -> None:
        """Resuelve la alerta del activo cuando ya no queda nada que la justifique."""
        if self._alerts is None:
            return
        self._session.flush()
        remaining = self._session.scalar(
            select(
                exists().where(
                    VulnerabilityFinding.asset_id == asset.id,
                    VulnerabilityFinding.status.in_(sorted(workflow.ACTIVE_STATUSES)),
                    VulnerabilityFinding.match_state.in_(("confirmed", "probable")),
                    VulnerabilityFinding.severity.in_(("high", "critical")),
                )
            )
        )
        if not remaining:
            self._alerts.resolve_rule(asset, AlertRule.VULNERABILITY, now)

    # --- Estado del activo ----------------------------------------------------------------------

    def _finish(
        self,
        state: AssetVulnerabilityState,
        software: AssetSoftware,
        fingerprint: str,
        now: datetime,
        *,
        pending_removal: bool,
    ) -> None:
        state.input_hash = fingerprint
        state.evaluated_at = now
        state.inventory_collected_at = software.collected_at
        state.inventory_complete = software.complete
        state.product_keys = software.keys
        state.components = len(software.components)
        state.pending_removal = pending_removal
        state.dirty_at = None
        state.dirty_reason = None
        state.error_count = 0
        state.last_error = None

    # --- Riesgos aceptados que caducan ------------------------------------------------------------

    def expire_accepted(self, now: datetime | None = None, limit: int = 500) -> list[int]:
        """Riesgos aceptados con fecha de caducidad vencida vuelven a open. Sin commit.

        Devuelve los ids de los findings reabiertos (la ruta/CLI audita cada uno).
        """
        moment = now or datetime.now(UTC)
        rows = self._session.scalars(
            select(VulnerabilityFinding)
            .where(
                VulnerabilityFinding.status == workflow.ACCEPTED_RISK,
                VulnerabilityFinding.accepted_until.is_not(None),
                VulnerabilityFinding.accepted_until <= moment,
            )
            .order_by(VulnerabilityFinding.accepted_until)
            .limit(limit)
            .with_for_update(skip_locked=True)
        ).all()
        for finding in rows:
            expired_at = finding.accepted_until
            finding.status = workflow.OPEN
            finding.status_reason = None
            finding.status_changed_at = moment
            finding.status_changed_by = SYSTEM_ACTOR
            finding.status_changed_by_user_id = None
            finding.accepted_until = None
            finding.review_basis = None
            finding.version += 1
            finding.updated_at = moment
            add_history(
                self._session,
                finding,
                "risk_acceptance_expired",
                moment,
                from_value=workflow.ACCEPTED_RISK,
                to_value=workflow.OPEN,
                details={"accepted_until": expired_at.isoformat() if expired_at else None},
            )
        if rows:
            request_recalculation(self._session, {f.asset_id for f in rows})
            _audit_expired(self._session, rows)
        return [f.id for f in rows]

    def expire_accepted_audited(self, now: datetime | None = None) -> int:
        """expire_accepted + auditoría (actor "sentra") en la misma transacción. Commit."""
        expired = self.expire_accepted(now)
        self._session.commit()
        return len(expired)


def _audit_expired(session: Session, findings: Sequence[VulnerabilityFinding]) -> None:
    for finding in findings:
        audit_service.record(
            session,
            SYSTEM,
            "vulnerability_risk_acceptance_expired",
            target_type="vulnerability_finding",
            target_id=finding.public_id,
            details={"vulnerability": finding.vuln_external_id, "to": workflow.OPEN},
            commit=False,
        )


def _listening_ports(document: Mapping[str, Any] | None) -> frozenset[int]:
    """Puertos TCP en escucha del último inventario, sin los ligados solo a loopback."""
    ports: set[int] = set()
    for connection in (document or {}).get("connections") or []:
        if not isinstance(connection, dict) or connection.get("status") != "listen":
            continue
        if (connection.get("protocol") or "tcp") != "tcp":
            continue
        port = connection.get("local_port")
        if not isinstance(port, int) or not 0 < port < 65536:
            continue
        address = connection.get("local_address")
        if isinstance(address, str):
            try:
                if ipaddress.ip_address(address).is_loopback:
                    continue
            except ValueError:
                pass
        ports.add(port)
    return frozenset(ports)

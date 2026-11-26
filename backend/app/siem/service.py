"""Servicio del dashboard para la integración SIEM (Fase 7F.1).

Catálogo de fuentes (alta, cambios, retirada; auditado), importación manual de ficheros
exportados, listado de eventos y agregados. La lectura de eventos exige siem:evidence en la
ruta; los agregados (siem:read) nunca devuelven contenido de los eventos.
"""

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import (
    SensorNotFoundError,
    SiemConflictError,
    SiemEventNotFoundError,
    SiemSourceNotFoundError,
    SiemValidationError,
)
from app.models.asset import Asset
from app.models.siem import SiemBatch, SiemEvent, SiemEventLink, SiemSource
from app.models.site import Sensor, Site
from app.schemas.siem import (
    SiemAssetRef,
    SiemAttribution,
    SiemAttributionCandidate,
    SiemBatchAccepted,
    SiemConnectorList,
    SiemConnectorRead,
    SiemCount,
    SiemEventDetail,
    SiemEventLinkRead,
    SiemEventList,
    SiemEventRead,
    SiemImportRequest,
    SiemOverview,
    SiemSourceCreate,
    SiemSourceList,
    SiemSourceRead,
    SiemSourceUpdate,
)
from app.services import audit_service
from app.services.audit_service import Actor
from app.siem.catalog import TRANSPORT_SENSOR, Connector, connectors, get_connector
from app.siem.contract import RawRecord
from app.siem.ingest import Analyzer, SiemIngest, effective_retention_days
from app.siem.status import source_status

SOURCE_STATES = ("disabled", "configured", "healthy", "degraded", "offline", "error")


def connector_read(connector: Connector) -> SiemConnectorRead:
    return SiemConnectorRead(
        source_type=connector.source_type,
        title=connector.title,
        version=connector.version,
        transports=list(connector.transports),
        sensor_input=connector.sensor_input,
        description=connector.description,
        severity_policy=dict(connector.severity_policy),
        severity_policy_doc=connector.severity_policy_doc,
        event_types=list(connector.event_types),
        sensitive_fields=list(connector.sensitive_fields),
        validation=connector.validation,
        formats=list(connector.formats),
    )


def _config_summary(source: SiemSource) -> dict[str, Any]:
    """Lo que se audita de una fuente: configuración aprobada, nunca eventos."""
    return {
        "name": source.name,
        "source_type": source.source_type,
        "transport": source.transport,
        "input_name": source.input_name,
        "enabled": source.enabled,
        "retention_days": source.retention_days,
        "max_events_per_minute": source.max_events_per_minute,
        "config": source.config,
        "revision": source.revision,
    }


class SiemService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    # --- catálogo de conectores ---------------------------------------------------------

    @staticmethod
    def list_connectors() -> SiemConnectorList:
        return SiemConnectorList(items=[connector_read(c) for c in connectors()])

    # --- fuentes ------------------------------------------------------------------------

    def _source(self, public_id: UUID, lock: bool = False) -> SiemSource:
        query = select(SiemSource).where(SiemSource.public_id == public_id)
        if lock:
            query = query.with_for_update()
        source = self._session.scalar(query)
        if source is None:
            raise SiemSourceNotFoundError("SIEM source not found")
        return source

    def _read(
        self, source: SiemSource, site: Site, sensor: Sensor | None, now: datetime
    ) -> SiemSourceRead:
        connector = get_connector(source.source_type)
        state, reasons = source_status(source, sensor, self._settings, now)
        policy = dict(connector.severity_policy) if connector else {}
        override = (source.config or {}).get("severity_policy") or {}
        policy.update({k: v for k, v in override.items() if k in policy})
        return SiemSourceRead(
            source_id=source.public_id,
            name=source.name,
            source_type=source.source_type,
            connector_title=connector.title if connector else None,
            connector_version=source.connector_version,
            transport=source.transport,
            site_id=site.public_id,
            site_name=site.name,
            sensor_id=sensor.public_id if sensor else None,
            sensor_name=sensor.name if sensor else None,
            input_name=source.input_name,
            enabled=source.enabled,
            revision=source.revision,
            status=state,
            status_reasons=reasons,
            config=dict(source.config or {}),
            effective_severity_policy=policy,
            retention_days=source.retention_days,
            effective_retention_days=effective_retention_days(source, self._settings),
            max_events_per_minute=source.max_events_per_minute,
            events_received=source.events_received,
            events_accepted=source.events_accepted,
            events_rejected=source.events_rejected,
            events_duplicate=source.events_duplicate,
            events_dropped=source.events_dropped,
            last_success_at=source.last_success_at,
            last_event_at=source.last_event_at,
            lag_seconds=source.lag_seconds,
            last_error_code=source.last_error_code,
            last_error_at=source.last_error_at,
            reported_state=source.reported_state,
            reported_at=source.reported_at,
            created_by=source.created_by,
            updated_by=source.updated_by,
            created_at=source.created_at,
            updated_at=source.updated_at,
        )

    def list_sources(self, site_id: int | None) -> SiemSourceList:
        query = (
            select(SiemSource, Site, Sensor)
            .join(Site, Site.id == SiemSource.site_id)
            .outerjoin(Sensor, Sensor.id == SiemSource.sensor_id)
            .order_by(Site.name, SiemSource.name)
        )
        if site_id is not None:
            query = query.where(SiemSource.site_id == site_id)
        now = datetime.now(UTC)
        return SiemSourceList(
            items=[
                self._read(s, site, sensor, now)
                for s, site, sensor in self._session.execute(query).all()
            ]
        )

    def get_source(self, public_id: UUID) -> SiemSourceRead:
        source = self._source(public_id)
        return self._read_one(source)

    def _read_one(self, source: SiemSource) -> SiemSourceRead:
        site = self._session.get(Site, source.site_id)
        sensor = self._session.get(Sensor, source.sensor_id) if source.sensor_id else None
        assert site is not None  # noqa: S101 (FK RESTRICT)
        return self._read(source, site, sensor, datetime.now(UTC))

    def _sensor_for(self, site: Site, sensor_id: UUID | None) -> Sensor:
        if sensor_id is None:
            raise SiemValidationError(
                "siem_sensor_required", "A sensor-transport source needs the receiving sensor"
            )
        sensor = self._session.scalar(select(Sensor).where(Sensor.public_id == sensor_id))
        if sensor is None:
            raise SensorNotFoundError("Sensor not found")
        if sensor.site_id != site.id:
            # Una fuente de un site nunca la recibe un sensor de otro: su credencial no
            # podría escribir en ella y el aislamiento por site se rompería.
            raise SiemValidationError(
                "siem_sensor_other_site", "The sensor belongs to another site"
            )
        if sensor.status == "revoked":
            raise SiemConflictError("siem_sensor_revoked", "The sensor has been revoked")
        return sensor

    @staticmethod
    def _check_config(connector: Connector, config: dict[str, Any]) -> dict[str, Any]:
        policy = config.get("severity_policy") or {}
        unknown = sorted(set(policy) - set(connector.severity_policy))
        if unknown:
            raise SiemValidationError(
                "siem_severity_policy_key", f"Unknown severity policy keys: {', '.join(unknown)}"
            )
        types = config.get("event_types") or []
        if connector.event_types:
            bad = sorted(set(types) - set(connector.event_types))
            if bad:
                raise SiemValidationError(
                    "siem_event_type_unknown", f"Unknown event types: {', '.join(bad)}"
                )
        elif types:
            raise SiemValidationError(
                "siem_event_type_unknown", "This connector has no event type filter"
            )
        return {"severity_policy": dict(policy), "event_types": sorted(set(types))}

    def create_source(self, body: SiemSourceCreate, actor: Actor) -> SiemSourceRead:
        session = self._session
        connector = get_connector(body.source_type)
        if connector is None:
            raise SiemValidationError("siem_unknown_connector", "Unknown SIEM connector")
        if body.transport not in connector.transports:
            raise SiemValidationError(
                "siem_transport_unsupported", "The connector does not support that transport"
            )
        site = session.scalar(select(Site).where(Site.public_id == body.site_id))
        if site is None:
            raise SiemValidationError("siem_site_not_found", "Site not found")
        sensor: Sensor | None = None
        if body.transport == TRANSPORT_SENSOR:
            sensor = self._sensor_for(site, body.sensor_id)
            if not body.input_name:
                raise SiemValidationError(
                    "siem_input_required",
                    "Name the input alias declared in the sensor configuration",
                )
        elif body.sensor_id is not None or body.input_name is not None:
            raise SiemValidationError(
                "siem_upload_no_sensor", "An upload source has no sensor or input"
            )
        self._unique(site.id, body.name, sensor, body.input_name, None)
        source = SiemSource(
            site_id=site.id,
            sensor_id=sensor.id if sensor else None,
            source_type=connector.source_type,
            name=body.name,
            transport=body.transport,
            input_name=body.input_name if sensor else None,
            connector_version=connector.version,
            enabled=body.enabled,
            revision=1,
            config=self._check_config(connector, body.config.model_dump()),
            retention_days=body.retention_days,
            max_events_per_minute=body.max_events_per_minute
            or self._settings.siem_default_events_per_minute,
            created_by=actor.name[:64],
            updated_by=actor.name[:64],
        )
        session.add(source)
        session.flush()
        audit_service.record(
            session,
            actor,
            "siem_source_created",
            target_type="siem_source",
            target_id=source.public_id,
            details={"to": _config_summary(source), "site": str(site.public_id)},
            commit=False,
        )
        session.commit()
        session.refresh(source)
        return self._read(source, site, sensor, datetime.now(UTC))

    def _unique(
        self,
        site_id: int,
        name: str,
        sensor: Sensor | None,
        input_name: str | None,
        exclude: int | None,
    ) -> None:
        clash = select(SiemSource.id).where(SiemSource.site_id == site_id, SiemSource.name == name)
        if exclude is not None:
            clash = clash.where(SiemSource.id != exclude)
        if self._session.scalar(clash) is not None:
            raise SiemConflictError("siem_source_name_taken", "A source with that name exists")
        if sensor is not None and input_name:
            same_input = select(SiemSource.id).where(
                SiemSource.sensor_id == sensor.id, SiemSource.input_name == input_name
            )
            if exclude is not None:
                same_input = same_input.where(SiemSource.id != exclude)
            if self._session.scalar(same_input) is not None:
                raise SiemConflictError(
                    "siem_input_taken", "That sensor input already feeds another source"
                )

    def update_source(
        self, public_id: UUID, body: SiemSourceUpdate, actor: Actor
    ) -> SiemSourceRead:
        session = self._session
        source = self._source(public_id, lock=True)
        if body.expected_revision != source.revision:
            raise SiemConflictError(
                "siem_source_changed",
                "The source changed since it was read",
                [{"revision": source.revision}],
            )
        connector = get_connector(source.source_type)
        if connector is None:
            raise SiemValidationError("siem_unknown_connector", "Unknown SIEM connector")
        before = _config_summary(source)
        site = session.get(Site, source.site_id)
        assert site is not None  # noqa: S101
        sensor = session.get(Sensor, source.sensor_id) if source.sensor_id else None
        if source.transport == TRANSPORT_SENSOR and body.sensor_id is not None:
            sensor = self._sensor_for(site, body.sensor_id)
            source.sensor_id = sensor.id
        if source.transport != TRANSPORT_SENSOR and (body.sensor_id or body.input_name):
            raise SiemValidationError(
                "siem_upload_no_sensor", "An upload source has no sensor or input"
            )
        if body.input_name is not None:
            source.input_name = body.input_name
        if body.name is not None:
            source.name = body.name
        self._unique(site.id, source.name, sensor, source.input_name, source.id)
        if body.enabled is not None:
            if body.enabled and source.transport == TRANSPORT_SENSOR and sensor is None:
                raise SiemValidationError(
                    "siem_sensor_required", "Assign a sensor before enabling the source"
                )
            source.enabled = body.enabled
        if body.clear_retention:
            source.retention_days = None
        elif body.retention_days is not None:
            source.retention_days = body.retention_days
        if body.max_events_per_minute is not None:
            source.max_events_per_minute = body.max_events_per_minute
        if body.config is not None:
            source.config = self._check_config(connector, body.config.model_dump())
        source.revision += 1
        source.updated_by = actor.name[:64]
        source.updated_at = datetime.now(UTC)
        audit_service.record(
            session,
            actor,
            "siem_source_changed",
            target_type="siem_source",
            target_id=source.public_id,
            details={"from": before, "to": _config_summary(source)},
            commit=False,
        )
        session.commit()
        session.refresh(source)
        return self._read(source, site, sensor, datetime.now(UTC))

    def delete_source(self, public_id: UUID, actor: Actor) -> None:
        """Retira una fuente deshabilitada y, con ella, sus eventos (ON DELETE CASCADE).

        Exigir que esté deshabilitada evita borrar por error una fuente activa: primero se
        deshabilita (el sensor deja de enviar), después se retira.
        """
        session = self._session
        source = self._source(public_id, lock=True)
        if source.enabled:
            raise SiemConflictError("siem_source_enabled", "Disable the source before deleting it")
        events = session.scalar(
            select(func.count()).select_from(SiemEvent).where(SiemEvent.source_id == source.id)
        )
        audit_service.record(
            session,
            actor,
            "siem_source_deleted",
            target_type="siem_source",
            target_id=source.public_id,
            details={"from": _config_summary(source), "events_deleted": int(events or 0)},
            commit=False,
        )
        session.delete(source)
        session.commit()

    # --- importación manual -------------------------------------------------------------

    def import_records(
        self,
        public_id: UUID,
        body: SiemImportRequest,
        actor: Actor,
        analyzers: tuple[Analyzer, ...] = (),
    ) -> SiemBatchAccepted:
        """Importa un fichero exportado en una fuente `upload` habilitada.

        El batch_id se deriva del contenido (uuid5 de su SHA-256): reimportar el mismo
        fichero es idempotente. Las líneas vacías se ignoran; cada línea es un registro.
        """
        session = self._session
        source = self._source(public_id, lock=True)
        if source.transport != "upload":
            raise SiemConflictError(
                "siem_source_not_upload", "Only upload sources accept manual imports"
            )
        if not source.enabled:
            raise SiemConflictError("siem_source_disabled", "The source is disabled")
        lines = [line for line in body.content.splitlines() if line.strip()]
        if not lines:
            raise SiemValidationError("siem_import_empty", "The file has no records")
        if len(lines) > self._settings.siem_upload_max_records:
            raise SiemValidationError(
                "siem_import_too_many",
                f"At most {self._settings.siem_upload_max_records} records per import",
            )
        digest = hashlib.sha256(body.content.encode("utf-8", "surrogatepass")).hexdigest()
        batch_id = uuid.uuid5(uuid.NAMESPACE_URL, f"sentra-siem-import:{source.public_id}:{digest}")
        now = datetime.now(UTC)
        records = [
            RawRecord(
                raw=line,
                transport="upload",
                reference=f"upload:{digest[:16]}#{index + 1}",
                record_id=None,
                collected_at=now,
            )
            for index, line in enumerate(lines)
        ]
        result = SiemIngest(session, self._settings, analyzers).process(
            source, batch_id, records, origin="upload"
        )
        audit_service.record(
            session,
            actor,
            "siem_import",
            target_type="siem_source",
            target_id=source.public_id,
            details={
                "filename": body.filename,
                "sha256": digest,
                "records": result.records,
                "accepted": result.accepted,
                "duplicates": result.duplicates,
                "rejected": result.rejected,
                "duplicate_import": result.duplicate,
            },
        )
        return result

    # --- eventos ------------------------------------------------------------------------

    def _event_rows(self, query: Select[SiemEvent, SiemSource, Site, Asset]) -> list[SiemEventRead]:
        rows = self._session.execute(query).all()
        assets = self._candidate_assets([row[0] for row in rows])
        return [self._event_read(e, s, site, a, assets) for e, s, site, a in rows]

    def _candidate_assets(self, events: list[SiemEvent]) -> dict[int, Asset]:
        """Activos candidatos de la atribución (ids internos → public_id y nombre)."""
        ids = {
            int(c["asset_id"])
            for event in events
            for c in (event.attribution or {}).get("candidates") or []
            if isinstance(c, dict) and isinstance(c.get("asset_id"), int)
        }
        if not ids:
            return {}
        return {a.id: a for a in self._session.scalars(select(Asset).where(Asset.id.in_(ids)))}

    @staticmethod
    def _attribution(event: SiemEvent, assets: dict[int, Asset]) -> SiemAttribution | None:
        raw = event.attribution
        if not isinstance(raw, dict):
            return None
        candidates = []
        for item in raw.get("candidates") or []:
            if not isinstance(item, dict):
                continue
            asset = assets.get(item.get("asset_id") or 0)
            candidates.append(
                SiemAttributionCandidate(
                    # Un activo borrado después: el candidato se muestra sin enlace.
                    asset_id=asset.public_id if asset else None,
                    asset_name=asset.display_name if asset else None,
                    role=str(item.get("role")),
                    method=str(item.get("method")),
                    confidence=str(item.get("confidence")),
                    value=str(item.get("value"))[:255],
                )
            )
        return SiemAttribution(
            verdict=str(raw.get("verdict") or "insufficient_evidence"),
            candidates=candidates,
            ambiguous=len(raw.get("ambiguous") or []),
            origin=str(raw["origin"]) if isinstance(raw.get("origin"), str) else None,
        )

    @staticmethod
    def _event_query() -> Select[SiemEvent, SiemSource, Site, Asset]:
        return (
            select(SiemEvent, SiemSource, Site, Asset)
            .join(SiemSource, SiemSource.id == SiemEvent.source_id)
            .join(Site, Site.id == SiemEvent.site_id)
            .outerjoin(Asset, Asset.id == SiemEvent.asset_id)
        )

    @staticmethod
    def _event_read(
        event: SiemEvent,
        source: SiemSource,
        site: Site,
        asset: Asset | None,
        assets: dict[int, Asset],
        detail: bool = False,
        links: list[SiemEventLinkRead] | None = None,
    ) -> SiemEventRead:
        values: dict[str, Any] = {
            "event_id": event.event_id,
            "schema_version": event.schema_version,
            "normalization_version": event.normalization_version,
            "source_id": source.public_id,
            "source_name": source.name,
            "source_type": event.source_type,
            "site_id": site.public_id,
            "event_type": event.event_type,
            "category": event.category,
            "timestamp": event.observed_at,
            "collected_at": event.collected_at,
            "received_at": event.received_at,
            "time_quality": event.time_quality,
            "severity": event.severity,
            "source_severity": event.source_severity,
            "confidence": event.confidence,
            "hostname": event.hostname,
            "source_ip": event.src_ip,
            "destination_ip": event.dst_ip,
            "source_port": event.src_port,
            "destination_port": event.dst_port,
            "protocol": event.protocol,
            "username": event.username,
            "process_name": event.process_name,
            "action": event.action,
            "outcome": event.outcome,
            "signature_id": event.signature_id,
            "rule_id": event.rule_id,
            "message": event.message,
            "tags": list(event.tags or []),
            "mitre_techniques": list(event.mitre_techniques or []),
            "external_id": event.external_id,
            "flow_ref": event.flow_ref,
            "raw_reference": event.raw_reference,
            "evidence_hash": event.evidence_hash,
            "asset": SiemAssetRef(asset_id=asset.public_id, name=asset.display_name)
            if asset is not None
            else None,
            "attribution": SiemService._attribution(event, assets),
        }
        if detail:
            return SiemEventDetail(
                **values, raw_excerpt=event.raw_excerpt, data=event.data, links=links or []
            )
        return SiemEventRead(**values)

    def list_events(
        self,
        site_id: int | None,
        source_id: UUID | None,
        event_type: str | None,
        since: datetime | None,
        until: datetime | None,
        limit: int,
        offset: int,
    ) -> SiemEventList:
        query = self._event_query()
        count = select(func.count()).select_from(SiemEvent)
        conditions = []
        if site_id is not None:
            conditions.append(SiemEvent.site_id == site_id)
        if source_id is not None:
            conditions.append(
                SiemEvent.source_id.in_(
                    select(SiemSource.id).where(SiemSource.public_id == source_id)
                )
            )
        if event_type is not None:
            conditions.append(SiemEvent.event_type == event_type)
        if since is not None:
            conditions.append(SiemEvent.observed_at >= since)
        if until is not None:
            conditions.append(SiemEvent.observed_at <= until)
        query = query.where(*conditions).order_by(SiemEvent.observed_at.desc(), SiemEvent.id.desc())
        total = int(self._session.scalar(count.where(*conditions)) or 0)
        items = self._event_rows(query.limit(limit).offset(offset))
        return SiemEventList(items=items, total=total, limit=limit, offset=offset)

    def get_event(self, event_id: UUID) -> SiemEventDetail:
        row = self._session.execute(
            self._event_query().where(SiemEvent.event_id == event_id)
        ).first()
        if row is None:
            raise SiemEventNotFoundError("SIEM event not found")
        event, source, site, asset = row
        links = [
            SiemEventLinkRead(
                kind=link.kind,
                target_ref=link.target_ref,
                method=link.method,
                confidence=link.confidence,
                explanation=str((link.details or {}).get("explanation") or ""),
                created_at=link.created_at,
            )
            for link in self._session.scalars(
                select(SiemEventLink)
                .where(SiemEventLink.event_id == event.id)
                .order_by(SiemEventLink.id)
                .limit(50)
            )
        ]
        result = self._event_read(
            event, source, site, asset, self._candidate_assets([event]), True, links
        )
        assert isinstance(result, SiemEventDetail)  # noqa: S101
        return result

    # --- agregados ----------------------------------------------------------------------

    def overview(self, site_id: int | None, hours: int) -> SiemOverview:
        since = datetime.now(UTC) - timedelta(hours=hours)
        sources = self.list_sources(site_id).items
        by_status = dict.fromkeys(SOURCE_STATES, 0)
        for source in sources:
            by_status[source.status] += 1
        scope = [SiemEvent.received_at >= since]
        batch_scope = [SiemBatch.received_at >= since]
        if site_id is not None:
            scope.append(SiemEvent.site_id == site_id)
            batch_scope.append(SiemBatch.site_id == site_id)

        def counts(column: Any) -> list[SiemCount]:
            return [
                SiemCount(key=str(key), count=int(value))
                for key, value in self._session.execute(
                    select(column, func.count())
                    .where(*scope)
                    .group_by(column)
                    .order_by(func.count().desc())
                    .limit(20)
                ).all()
            ]

        events, last = self._session.execute(
            select(func.count(), func.max(SiemEvent.received_at)).where(*scope)
        ).one()
        rejected, duplicates = self._session.execute(
            select(
                func.coalesce(func.sum(SiemBatch.rejected), 0),
                func.coalesce(func.sum(SiemBatch.duplicates), 0),
            ).where(*batch_scope)
        ).one()
        return SiemOverview(
            window_hours=hours,
            sources_total=len(sources),
            sources_by_status=by_status,
            events=int(events),
            rejected=int(rejected),
            duplicates=int(duplicates),
            by_source_type=counts(SiemEvent.source_type),
            by_severity=counts(SiemEvent.severity),
            by_category=counts(SiemEvent.category),
            lagging_sources=sum(1 for s in sources if "lag" in s.status_reasons),
            last_event_received_at=last,
        )

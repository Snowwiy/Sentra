"""Matching de indicadores (IOCs) contra datos que Sentra YA tiene (Fase 5C).

Solo coincidencias EXACTAS (o pertenencia a un CIDR) con telemetría local existente:
- auth_source_ip: IP de origen de inicios de sesión (system_events.data.IpAddress, eventos
  4624/4625 de Windows);
- connection_remote_ip: IP remota de conexiones establecidas del último inventario;
- asset_address: IP principal de un activo conocido;
- asset_name: hostname o DNS inverso de un activo (visibilidad parcial: Sentra no recoge
  consultas DNS, así que un dominio malicioso solo casa si ES el nombre de un activo).
Hashes, URLs y emails no se pueden casar: el agente no recoge esos datos (la UI lo dice como
"unsupported"). Nunca hay coincidencias difusas, por subcadena ni por similitud.

Un match NO afirma un compromiso: dice "este dato local coincide con un indicador que la
fuente X clasifica como Y". El análisis lo hace una persona.

Cómo escala (sin bucles por IOC):
- incremental hacia delante: eventos nuevos (cursor por id) e inventarios recibidos desde la
  última vuelta (cursor por received_at). Cada lote se compara de una vez con TODOS los
  indicadores activos con un JOIN por índice (igualdad sobre value_normalized y GiST para
  CIDR) a partir de arrays (unnest), no una consulta por indicador;
- retroactivo: los indicadores nuevos o cambiados (pending_match) se comparan una vez con lo
  que ya existía (eventos de los últimos RETRO_LOOKBACK, inventarios actuales y activos);
- barrido de activos (IP y nombre) como mucho cada ASSET_SWEEP_EVERY.
"""

import ipaddress
import logging
import re
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.metrics import REGISTRY
from app.detection.signals import SignalKind, SourceType
from app.models.asset import Asset
from app.models.detection import DetectionSignal
from app.models.inventory import AssetInventory
from app.models.threat_intel import (
    ThreatIndicator,
    ThreatIntelCursor,
    ThreatIntelMatch,
    ThreatIntelSource,
)
from app.risk.queue import request_recalculation
from app.services import audit_service
from app.services.audit_service import Actor
from app.threat_intel.config import ThreatIntelConfig
from app.threat_intel.indicators import CONFIDENCE_RANK, lower_confidence

logger = logging.getLogger(__name__)

SYSTEM = Actor("threat-intel")
AUTH_SOURCE_IP = "auth_source_ip"
CONNECTION_REMOTE_IP = "connection_remote_ip"
ASSET_ADDRESS = "asset_address"
ASSET_NAME = "asset_name"
OBSERVATION_TYPES = (AUTH_SOURCE_IP, CONNECTION_REMOTE_IP, ASSET_ADDRESS, ASSET_NAME)
FIELDS = {
    AUTH_SOURCE_IP: "system_events.data.IpAddress",
    CONNECTION_REMOTE_IP: "inventory.connections.remote_address",
    ASSET_ADDRESS: "assets.primary_ip",
    ASSET_NAME: "assets.hostname",
}
EVENT_BATCH = 5000
MAX_EVENT_BATCHES = 10
RETRO_BATCH = 2000
RETRO_LOOKBACK = timedelta(days=30)
# Pares (activo, IP) como mucho en una pasada retroactiva; si hay más, se toman los más
# recientes y se avisa en el log (los nuevos llegan igualmente por el camino incremental).
RETRO_MAX_PAIRS = 200_000
ASSET_SWEEP_EVERY = timedelta(hours=1)
UPSERT_CHUNK = 500
# Auditoría: una entrada por match NUEVO hasta este límite por vuelta; el resto se resume.
MAX_AUDITED_MATCHES = 50
# Señales al motor de detección (política THREAT_INTEL_DETECTION_POLICY).
SIGNAL_COOLDOWN = timedelta(hours=24)
SIGNAL_RECENT = timedelta(days=7)
_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
_ACTIVE_INDICATOR = (
    "NOT i.revoked AND i.classification <> 'benign' "
    "AND (i.valid_until IS NULL OR i.valid_until > :now) "
    "AND (i.valid_from IS NULL OR i.valid_from <= :now) "
    "AND s.enabled AND s.archived_at IS NULL"
)


def normalize_ip(raw: object) -> str | None:
    """IP observada en forma canónica; None si no es útil para casar.

    Loopback, sin especificar, link-local y multicast nunca son un IOC accionable (y el
    evento 4624 trae "-" o "127.0.0.1" en logons locales).
    """
    if not isinstance(raw, str) or not raw or len(raw) > 64:
        return None
    try:
        address = ipaddress.ip_address(raw.strip().split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if (
        address.is_loopback
        or address.is_unspecified
        or address.is_link_local
        or address.is_multicast
    ):
        return None
    return address.compressed


def normalize_name(raw: object) -> str | None:
    if not isinstance(raw, str):
        return None
    name = raw.strip().rstrip(".").lower()
    return name if _NAME.match(name) and not name.replace(".", "").isdigit() else None


@dataclass
class Observation:
    asset_id: int
    observation_type: str
    value: str
    first: datetime
    last: datetime
    count: int = 1
    event_id: int | None = None
    event_public_id: uuid.UUID | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def is_ip(self) -> bool:
        return self.observation_type != ASSET_NAME


@dataclass
class MatchRun:
    created: int = 0
    updated: int = 0
    signals: int = 0
    linked: int = 0
    retro_indicators: int = 0
    events: int = 0
    inventories: int = 0
    assets: set[int] = field(default_factory=set)

    def as_dict(self) -> dict[str, int]:
        return {
            "created": self.created,
            "updated": self.updated,
            "signals": self.signals,
            "linked": self.linked,
            "retro_indicators": self.retro_indicators,
            "events": self.events,
            "inventories": self.inventories,
        }


@dataclass(frozen=True)
class _Candidate:
    index: int
    indicator_id: int
    indicator_type: str
    classification: str
    confidence: str
    trust: str


class ThreatIntelMatcher:
    def __init__(self, session: Session, config: ThreatIntelConfig) -> None:
        self._session = session
        self._config = config

    # --- Cursores --------------------------------------------------------------------------------

    def _cursor(self, name: str, now: datetime) -> ThreatIntelCursor:
        cursor = self._session.get(ThreatIntelCursor, name)
        if cursor is None:
            # Primera vez: el camino incremental empieza AHORA. Lo anterior lo cubre el
            # matching retroactivo de cada indicador (pending_match) con su ventana.
            position = 0
            if name == "events":
                position = int(self._session.scalar(text("SELECT max(id) FROM system_events")) or 0)
            cursor = ThreatIntelCursor(
                name=name, position=position, position_at=now, updated_at=now
            )
            self._session.add(cursor)
            self._session.flush()
        return cursor

    # --- Coincidencias ---------------------------------------------------------------------------

    def _candidates(
        self,
        observations: Sequence[Observation],
        now: datetime,
        only: Sequence[int] | None,
    ) -> list[_Candidate]:
        """Indicadores activos que coinciden con alguna observación (consultas por conjuntos)."""
        result: list[_Candidate] = []
        # psycopg prepara la sentencia tras 5 ejecuciones y PostgreSQL puede pasar a un plan
        # genérico que no conoce el tamaño de los arrays: medido, de 30 ms a ~1 s por lote.
        # Solo para esta transacción (SET LOCAL): no se filtra a otras conexiones del pool.
        self._session.execute(text("SET LOCAL plan_cache_mode = force_custom_plan"))
        restrict = " AND i.id = ANY(:only)" if only is not None else ""
        common = {"now": now, "only": list(only or [])}
        groups = (
            ([o for o in observations if o.is_ip], ("ipv4", "ipv6")),
            ([o for o in observations if not o.is_ip], ("domain", "hostname")),
        )
        index_of = {id(o): n for n, o in enumerate(observations)}
        for group, types in groups:
            if not group:
                continue
            idx = [index_of[id(o)] for o in group]
            values = [o.value for o in group]
            params = {**common, "idx": idx, "vals": values, "types": list(types)}
            rows = self._session.execute(
                text(
                    "SELECT o.idx, i.id, i.indicator_type, i.classification, i.confidence, "  # noqa: S608
                    "s.trust FROM unnest(CAST(:idx AS int[]), CAST(:vals AS text[])) "
                    "AS o(idx, value) JOIN threat_indicators i ON i.value_normalized = o.value "
                    "JOIN threat_intel_sources s ON s.id = i.source_id "
                    f"WHERE i.indicator_type = ANY(:types) AND {_ACTIVE_INDICATOR}{restrict}"
                ),
                params,
            ).all()
            result.extend(_Candidate(*row) for row in rows)
            if types[0] == "ipv4":
                rows = self._session.execute(
                    text(
                        "SELECT o.idx, i.id, i.indicator_type, i.classification, i.confidence, "  # noqa: S608
                        "s.trust FROM unnest(CAST(:idx AS int[]), CAST(:vals AS inet[])) "
                        "AS o(idx, value) JOIN threat_indicators i ON i.network >>= o.value "
                        "JOIN threat_intel_sources s ON s.id = i.source_id "
                        f"WHERE i.network IS NOT NULL AND {_ACTIVE_INDICATOR}{restrict}"
                    ),
                    params,
                ).all()
                result.extend(_Candidate(*row) for row in rows)
        return result

    def _upsert(
        self,
        observations: Sequence[Observation],
        candidates: Sequence[_Candidate],
        now: datetime,
        run: MatchRun,
        *,
        additive: bool,
    ) -> list[tuple[int, uuid.UUID, int, int]]:
        """Crea o actualiza matches. Devuelve los NUEVOS (id, public_id, asset, indicator)."""
        rows: dict[tuple[int, int, str, str], dict[str, Any]] = {}
        for candidate in candidates:
            obs = observations[candidate.index]
            confidence = candidate.confidence
            if candidate.indicator_type == "cidr" or obs.observation_type == ASSET_NAME:
                confidence = lower_confidence(confidence)
            key = (candidate.indicator_id, obs.asset_id, obs.observation_type, obs.value)
            current = rows.get(key)
            if current is not None:
                # La misma coincidencia dos veces en el lote: se agregan.
                current["observation_count"] += obs.count
                current["first_observed_at"] = min(current["first_observed_at"], obs.first)
                if obs.last > current["last_observed_at"]:
                    current.update(
                        last_observed_at=obs.last,
                        event_id=obs.event_id,
                        event_public_id=obs.event_public_id,
                        evidence=obs.evidence,
                    )
                continue
            rows[key] = {
                "public_id": uuid.uuid4(),
                "indicator_id": candidate.indicator_id,
                "asset_id": obs.asset_id,
                "observation_type": obs.observation_type,
                "observed_value": obs.value[:1024],
                "observed_field": FIELDS[obs.observation_type],
                "event_id": obs.event_id,
                "event_public_id": obs.event_public_id,
                "first_observed_at": obs.first,
                "last_observed_at": obs.last,
                "observation_count": obs.count,
                "classification": candidate.classification,
                "indicator_confidence": candidate.confidence,
                "source_trust": candidate.trust,
                "match_confidence": confidence,
                "status": "open",
                "status_changed_at": now,
                "status_changed_by": SYSTEM.name,
                "evidence": obs.evidence,
                "version": 1,
                "matched_at": now,
                "updated_at": now,
            }
        created: list[tuple[int, uuid.UUID, int, int]] = []
        values = list(rows.values())
        table = ThreatIntelMatch.__table__
        for start in range(0, len(values), UPSERT_CHUNK):
            stmt = insert(ThreatIntelMatch).values(values[start : start + UPSERT_CHUNK])
            excluded = stmt.excluded
            newer = excluded.last_observed_at > table.c.last_observed_at
            count = (
                table.c.observation_count + excluded.observation_count
                if additive
                else func.greatest(table.c.observation_count, excluded.observation_count)
            )
            upsert = stmt.on_conflict_do_update(
                constraint="uq_threat_intel_match",
                set_={
                    "first_observed_at": func.least(
                        table.c.first_observed_at, excluded.first_observed_at
                    ),
                    "last_observed_at": func.greatest(
                        table.c.last_observed_at, excluded.last_observed_at
                    ),
                    "observation_count": count,
                    "event_id": func.coalesce(excluded.event_id, table.c.event_id),
                    "event_public_id": func.coalesce(
                        excluded.event_public_id, table.c.event_public_id
                    ),
                    "evidence": text(
                        "CASE WHEN excluded.last_observed_at > threat_intel_matches."
                        "last_observed_at THEN excluded.evidence ELSE threat_intel_matches."
                        "evidence END"
                    ),
                    # Lo que la fuente dice AHORA del indicador (puede haberse reclasificado).
                    "classification": excluded.classification,
                    "indicator_confidence": excluded.indicator_confidence,
                    "source_trust": excluded.source_trust,
                    "match_confidence": excluded.match_confidence,
                    "version": text(
                        "threat_intel_matches.version + CASE WHEN excluded.last_observed_at > "
                        "threat_intel_matches.last_observed_at THEN 1 ELSE 0 END"
                    ),
                    "updated_at": excluded.updated_at,
                },
                where=newer | (table.c.observation_count != excluded.observation_count),
            ).returning(
                table.c.id,
                table.c.public_id,
                table.c.asset_id,
                table.c.indicator_id,
                text("(xmax = 0) AS inserted"),
            )
            for match_id, public_id, asset_id, indicator_id, inserted in self._session.execute(
                upsert
            ):
                run.assets.add(asset_id)
                if inserted:
                    run.created += 1
                    created.append((match_id, public_id, asset_id, indicator_id))
                else:
                    run.updated += 1
        return created

    def _process(
        self,
        observations: Sequence[Observation],
        now: datetime,
        run: MatchRun,
        *,
        additive: bool,
        only: Sequence[int] | None = None,
    ) -> list[tuple[int, uuid.UUID, int, int]]:
        if not observations:
            return []
        candidates = self._candidates(observations, now, only)
        if not candidates:
            return []
        return self._upsert(observations, candidates, now, run, additive=additive)

    # --- Fuentes de observaciones -----------------------------------------------------------------

    def _event_observations(self, rows: Iterable[Any]) -> list[Observation]:
        grouped: dict[tuple[int, str], Observation] = {}
        for event_id, asset_id, public_id, raw_ip, code, logon_type, occurred_at in rows:
            ip = normalize_ip(raw_ip)
            if ip is None:
                continue
            key = (asset_id, ip)
            obs = grouped.get(key)
            evidence = {"event_code": code, "logon_type": (logon_type or None)}
            if obs is None:
                grouped[key] = Observation(
                    asset_id,
                    AUTH_SOURCE_IP,
                    ip,
                    occurred_at,
                    occurred_at,
                    1,
                    event_id,
                    public_id,
                    evidence,
                )
                continue
            obs.count += 1
            obs.first = min(obs.first, occurred_at)
            if occurred_at >= obs.last:
                obs.last = occurred_at
                obs.event_id, obs.event_public_id, obs.evidence = event_id, public_id, evidence
        return list(grouped.values())

    def _connection_observations(self, rows: Iterable[Any]) -> list[Observation]:
        grouped: dict[tuple[int, str], Observation] = {}
        for asset_id, raw_ip, remote_port, local_port, process, protocol, received_at in rows:
            ip = normalize_ip(raw_ip)
            if ip is None:
                continue
            evidence = {
                "protocol": protocol if protocol in ("tcp", "udp") else None,
                "remote_port": remote_port if isinstance(remote_port, int) else None,
                "local_port": local_port if isinstance(local_port, int) else None,
                "process_name": process[:255] if isinstance(process, str) else None,
            }
            key = (asset_id, ip)
            if key in grouped:
                continue  # varias conexiones a la misma IP en el mismo inventario: una
            grouped[key] = Observation(
                asset_id, CONNECTION_REMOTE_IP, ip, received_at, received_at, 1, evidence=evidence
            )
        return list(grouped.values())

    _CONNECTIONS_SQL = (
        "SELECT inv.asset_id, c->>'remote_address', "
        "CASE WHEN jsonb_typeof(c->'remote_port') = 'number' THEN (c->>'remote_port')::int END, "
        "CASE WHEN jsonb_typeof(c->'local_port') = 'number' THEN (c->>'local_port')::int END, "
        "c->>'process_name', c->>'protocol', inv.received_at "
        "FROM asset_inventories inv "
        "CROSS JOIN LATERAL jsonb_array_elements("
        "CASE WHEN jsonb_typeof(inv.data->'connections') = 'array' "
        "THEN inv.data->'connections' ELSE '[]'::jsonb END) c "
        "WHERE c->>'status' = 'established' AND c ? 'remote_address'"
    )

    def _asset_observations(self) -> list[Observation]:
        result: list[Observation] = []
        for (
            asset_id,
            primary_ip,
            hostname,
            reverse_dns,
            last_seen,
            created_at,
        ) in self._session.execute(
            select(
                Asset.id,
                Asset.primary_ip,
                Asset.hostname,
                Asset.reverse_dns,
                Asset.last_seen_at,
                Asset.created_at,
            )
        ):
            seen = last_seen or created_at
            ip = normalize_ip(primary_ip)
            if ip is not None:
                result.append(Observation(asset_id, ASSET_ADDRESS, ip, seen, seen))
            names = {normalize_name(hostname), normalize_name(reverse_dns)}
            for name in sorted(n for n in names if n is not None):
                result.append(Observation(asset_id, ASSET_NAME, name, seen, seen))
        return result

    # --- Pasadas ---------------------------------------------------------------------------------

    def forward_events(self, now: datetime, run: MatchRun) -> list[tuple[int, uuid.UUID, int, int]]:
        cursor = self._cursor("events", now)
        created: list[tuple[int, uuid.UUID, int, int]] = []
        for _ in range(MAX_EVENT_BATCHES):
            upper = int(self._session.scalar(text("SELECT max(id) FROM system_events")) or 0)
            if upper <= cursor.position:
                break
            rows = self._session.execute(
                text(
                    "SELECT id, asset_id, public_id, data->>'IpAddress', event_code, "
                    "data->>'LogonType', occurred_at FROM system_events "
                    "WHERE id > :after AND id <= :upper AND data ? 'IpAddress' "
                    "ORDER BY id LIMIT :limit"
                ),
                {"after": cursor.position, "upper": upper, "limit": EVENT_BATCH},
            ).all()
            run.events += len(rows)
            created += self._process(self._event_observations(rows), now, run, additive=True)
            # Sin filas con IP en el tramo: se avanza hasta el máximo visto.
            cursor.position = rows[-1][0] if len(rows) == EVENT_BATCH else upper
            cursor.updated_at = now
            if len(rows) < EVENT_BATCH:
                break
        return created

    def forward_inventories(
        self, now: datetime, run: MatchRun
    ) -> list[tuple[int, uuid.UUID, int, int]]:
        cursor = self._cursor("inventories", now)
        since = cursor.position_at or now
        upper = self._session.scalar(select(func.max(AssetInventory.received_at)))
        if upper is None or upper <= since:
            return []
        rows = self._session.execute(
            text(
                self._CONNECTIONS_SQL
                + " AND inv.received_at > :since AND inv.received_at <= :upper"
            ),
            {"since": since, "upper": upper},
        ).all()
        run.inventories += len({row[0] for row in rows})
        created = self._process(self._connection_observations(rows), now, run, additive=True)
        cursor.position_at = upper
        cursor.updated_at = now
        return created

    def sweep_assets(self, now: datetime, run: MatchRun) -> list[tuple[int, uuid.UUID, int, int]]:
        cursor = self._cursor("assets", now)
        if (
            cursor.position_at is not None
            and now - cursor.position_at < ASSET_SWEEP_EVERY
            and cursor.position
        ):
            return []
        created = self._process(self._asset_observations(), now, run, additive=False)
        cursor.position = 1
        cursor.position_at = now
        cursor.updated_at = now
        return created

    def retro(self, now: datetime, run: MatchRun) -> list[tuple[int, uuid.UUID, int, int]]:
        """Indicadores nuevos o cambiados contra datos ya existentes (una pasada por lote)."""
        pending = list(
            self._session.scalars(
                select(ThreatIndicator.id)
                .where(ThreatIndicator.pending_match)
                .order_by(ThreatIndicator.id)
                .limit(RETRO_BATCH)
            )
        )
        if not pending:
            return []
        run.retro_indicators += len(pending)
        types = set(
            self._session.scalars(
                select(ThreatIndicator.indicator_type)
                .distinct()
                .where(ThreatIndicator.id.in_(pending))
            )
        )
        created: list[tuple[int, uuid.UUID, int, int]] = []
        if types & {"ipv4", "ipv6", "cidr"}:
            since = now - RETRO_LOOKBACK
            rows = self._session.execute(
                text(
                    "SELECT max(id), asset_id, NULL, data->>'IpAddress' AS ip, "
                    "max(event_code), NULL, max(occurred_at), min(occurred_at), count(*) "
                    "FROM system_events WHERE data ? 'IpAddress' AND occurred_at >= :since "
                    "GROUP BY asset_id, data->>'IpAddress' "
                    "ORDER BY max(occurred_at) DESC LIMIT :limit"
                ),
                {"since": since, "limit": RETRO_MAX_PAIRS},
            ).all()
            if len(rows) == RETRO_MAX_PAIRS:
                logger.warning("threat intel retro matching truncated", extra={"pairs": len(rows)})
            observations: list[Observation] = []
            for event_id, asset_id, _, raw_ip, code, _, last, first, count in rows:
                ip = normalize_ip(raw_ip)
                if ip is not None:
                    observations.append(
                        Observation(
                            asset_id,
                            AUTH_SOURCE_IP,
                            ip,
                            first,
                            last,
                            int(count),
                            event_id,
                            None,
                            {"event_code": code},
                        )
                    )
            # Retroactivo: el recuento es el total en la ventana, no se suma a lo ya contado.
            created += self._process(observations, now, run, additive=False, only=pending)
            created += self._process(
                self._connection_observations(self._session.execute(text(self._CONNECTIONS_SQL))),
                now,
                run,
                additive=False,
                only=pending,
            )
        created += self._process(self._asset_observations(), now, run, additive=False, only=pending)
        self._session.execute(
            update(ThreatIndicator)
            .where(ThreatIndicator.id.in_(pending))
            .values(pending_match=False)
        )
        return created

    # --- Efectos ---------------------------------------------------------------------------------

    def _fill_event_public_ids(self) -> None:
        """Los matches retroactivos guardan el id del evento; aquí su id público."""
        self._session.execute(
            text(
                "UPDATE threat_intel_matches m SET event_public_id = e.public_id "
                "FROM system_events e WHERE m.event_id = e.id AND m.event_public_id IS NULL"
            )
        )

    def _refresh_indicators(self, indicator_ids: Iterable[int], now: datetime) -> None:
        ids = sorted(set(indicator_ids))
        if not ids:
            return
        self._session.execute(
            text(
                "UPDATE threat_indicators i SET match_count = c.n, last_matched_at = :now "
                "FROM (SELECT indicator_id, count(*) AS n FROM threat_intel_matches "
                "WHERE indicator_id = ANY(:ids) GROUP BY indicator_id) c "
                "WHERE i.id = c.indicator_id"
            ),
            {"ids": ids, "now": now},
        )

    def _audit_created(self, created: Sequence[tuple[int, uuid.UUID, int, int]]) -> None:
        for _, public_id, asset_id, indicator_id in created[:MAX_AUDITED_MATCHES]:
            audit_service.record(
                self._session,
                SYSTEM,
                "threat_intel_match_created",
                target_type="threat_match",
                target_id=public_id,
                details={"asset_id": asset_id, "indicator_id": indicator_id},
                commit=False,
            )
        if len(created) > MAX_AUDITED_MATCHES:
            audit_service.record(
                self._session,
                SYSTEM,
                "threat_intel_match_created",
                target_type="threat_match",
                details={"omitted": len(created) - MAX_AUDITED_MATCHES, "total": len(created)},
                commit=False,
            )

    def _policy_allows(self, classification: str, confidence: str) -> bool:
        policy = self._config.detection_policy
        if policy == "off" or classification != "malicious":
            return False
        if policy == "high_confidence_malicious":
            return CONFIDENCE_RANK.get(confidence, 0) >= CONFIDENCE_RANK["high"]
        return True

    def emit_signals(self, match_ids: Iterable[int], now: datetime, run: MatchRun) -> None:
        """Señal THREAT_INTEL_MATCH al motor de detección solo si la política lo permite.

        Solo matches con evidencia de eventos o conexiones (no la IP o el nombre del propio
        activo, que no es "actividad"), no descartados, observados hace poco y como mucho una
        señal por match cada SIGNAL_COOLDOWN. La regla TI-001 deduplica por indicador.
        """
        ids = sorted(set(match_ids))
        if not ids or self._config.detection_policy == "off":
            return
        rows = self._session.execute(
            select(ThreatIntelMatch, ThreatIndicator, ThreatIntelSource)
            .join(ThreatIndicator, ThreatIndicator.id == ThreatIntelMatch.indicator_id)
            .join(ThreatIntelSource, ThreatIntelSource.id == ThreatIndicator.source_id)
            .where(
                ThreatIntelMatch.id.in_(ids),
                ThreatIntelMatch.status != "dismissed",
                ThreatIntelMatch.observation_type.in_((AUTH_SOURCE_IP, CONNECTION_REMOTE_IP)),
                ThreatIntelMatch.last_observed_at >= now - SIGNAL_RECENT,
                (ThreatIntelMatch.signal_emitted_at.is_(None))
                | (ThreatIntelMatch.signal_emitted_at < now - SIGNAL_COOLDOWN),
            )
        ).all()
        for match, indicator, source in rows:
            if not self._policy_allows(match.classification, match.match_confidence):
                continue
            self._session.add(
                DetectionSignal(
                    asset_id=match.asset_id,
                    kind=SignalKind.THREAT_INTEL_MATCH.value,
                    subject=f"ioc:{indicator.public_id}",
                    occurred_at=match.last_observed_at,
                    source_type=SourceType.THREAT_INTEL.value,
                    source_id=str(match.public_id),
                    data={
                        "match_id": str(match.public_id),
                        "indicator_id": str(indicator.public_id),
                        "indicator_type": indicator.indicator_type,
                        "indicator_value": indicator.value_normalized[:255],
                        "classification": match.classification,
                        "match_confidence": match.match_confidence,
                        "source": source.name[:200],
                        "source_trust": source.trust,
                        "observation_type": match.observation_type,
                        "observed_value": match.observed_value[:255],
                        "observation_count": match.observation_count,
                    },
                    created_at=now,
                )
            )
            match.signal_emitted_at = now
            run.signals += 1

    def link_detections(self, run: MatchRun) -> None:
        """Enlaza cada match con la detección TI-001 que generó su señal (por dedup key)."""
        result = self._session.execute(
            text(
                "UPDATE threat_intel_matches m SET detection_id = d.id "
                "FROM threat_indicators i, detections d "
                "WHERE m.detection_id IS NULL AND m.signal_emitted_at IS NOT NULL "
                "AND i.id = m.indicator_id AND d.asset_id = m.asset_id AND d.rule_id = 'TI-001' "
                "AND d.dedup_key = 'ioc:' || i.public_id::text"
            )
        )
        run.linked += int(getattr(result, "rowcount", 0) or 0)

    # --- Vuelta completa -------------------------------------------------------------------------

    def run(self, now: datetime | None = None) -> MatchRun:
        now = now or datetime.now(UTC)
        run = MatchRun()
        created: list[tuple[int, uuid.UUID, int, int]] = []
        touched: list[int] = []
        for stage in (self.retro, self.forward_events, self.forward_inventories, self.sweep_assets):
            new = stage(now, run)
            created += new
            self._session.flush()
        self._fill_event_public_ids()
        if run.assets:
            touched = list(
                self._session.scalars(
                    select(ThreatIntelMatch.id).where(
                        ThreatIntelMatch.asset_id.in_(sorted(run.assets)),
                        ThreatIntelMatch.updated_at == now,
                    )
                )
            )
            self._refresh_indicators(
                self._session.scalars(
                    select(ThreatIntelMatch.indicator_id).where(ThreatIntelMatch.id.in_(touched))
                ),
                now,
            )
            request_recalculation(self._session, sorted(run.assets))
        self._audit_created(created)
        self.emit_signals(touched, now, run)
        self.link_detections(run)
        self._session.commit()
        REGISTRY.observe_threat_matches({"created": run.created, "updated": run.updated})
        if run.created or run.signals:
            # Prefijo: "created" es un atributo reservado de LogRecord.
            logger.info(
                "threat intel matching",
                extra={f"matches_{key}": value for key, value in run.as_dict().items()},
            )
        return run

"""Lectura de Advanced Network Discovery (Fase 6A): perfiles y observaciones.

La vista de red puede tener miles de direcciones por site: todo se filtra, ordena y pagina en
PostgreSQL (nunca se carga la tabla entera en el navegador ni en memoria del proceso). La
"última observación por (site, IP)" usa DISTINCT ON sobre el índice
ix_discovery_observations_site_address.
"""

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import Select, cast, func, or_, select
from sqlalchemy.dialects.postgresql import INET, distinct_on
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import DiscoveryOptionsError
from app.discovery.ports import SERVICE_HINTS
from app.discovery.profiles import DEFAULT_PROFILE, caps, profiles
from app.models.asset import Asset
from app.models.discovery import DiscoveryJob, DiscoveryObservation
from app.models.site import Sensor, Site
from app.schemas.discovery import (
    DiscoveryLimitsRead,
    DiscoveryProfileRead,
    DiscoveryProfilesRead,
    ObservationChange,
    ObservationEvidence,
    ObservationList,
    ObservationRead,
    PortHint,
)

METHODS = ("icmp", "tcp", "arp", "dns")
REACHABILITY = ("responded", "no_response", "unknown")


@dataclass(frozen=True)
class ObservationFilters:
    job_id: UUID | None = None
    site_id: UUID | None = None
    network: str | None = None
    sensor_id: UUID | None = None
    executor: str | None = None
    method: str | None = None
    reachability: str | None = None
    q: str | None = None
    latest: bool = False


def profiles_read(settings: Settings, can_tune: bool) -> DiscoveryProfilesRead:
    return DiscoveryProfilesRead(
        default_profile=DEFAULT_PROFILE,
        can_tune=can_tune,
        caps=DiscoveryLimitsRead(**caps(settings).as_dict()),
        profiles=[
            DiscoveryProfileRead(
                name=p.name,
                label=p.label,
                description=p.description,
                ports=list(p.ports),
                icmp=p.icmp,
                tcp=bool(p.ports),
                arp=p.arp,
                reverse_dns=p.reverse_dns,
                forward_dns=p.forward_dns,
                limits=DiscoveryLimitsRead(**p.limits.as_dict()),
            )
            for p in profiles(settings).values()
        ],
    )


def _invalid(message: str) -> DiscoveryOptionsError:
    return DiscoveryOptionsError("discovery_filter_invalid", message)


class ObservationService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def _where(self, query: Select[Any], f: ObservationFilters) -> Select[Any]:
        obs = DiscoveryObservation
        if f.job_id is not None:
            job = self._session.scalar(
                select(DiscoveryJob.id).where(DiscoveryJob.public_id == f.job_id)
            )
            # Un job inexistente devuelve una lista vacía: no se confirma ni niega nada más.
            query = query.where(obs.job_id == (job if job is not None else -1))
        if f.site_id is not None:
            site = self._session.scalar(select(Site.id).where(Site.public_id == f.site_id))
            query = query.where(obs.site_id == (site if site is not None else -1))
        if f.sensor_id is not None:
            sensor = self._session.scalar(select(Sensor.id).where(Sensor.public_id == f.sensor_id))
            query = query.where(obs.sensor_id == (sensor if sensor is not None else -1))
        if f.executor is not None:
            if f.executor not in ("local", "sensor"):
                raise _invalid("executor must be local or sensor")
            query = query.where(obs.executor == f.executor)
        if f.method is not None:
            if f.method not in METHODS:
                raise _invalid(f"method must be one of {', '.join(METHODS)}")
            query = query.where(obs.methods.contains([f.method]))
        if f.reachability is not None:
            if f.reachability not in REACHABILITY:
                raise _invalid(f"reachability must be one of {', '.join(REACHABILITY)}")
            query = query.where(obs.reachability == f.reachability)
        if f.network is not None:
            try:
                network = ipaddress.ip_network(f.network.strip(), strict=False)
            except ValueError as exc:
                raise _invalid("network must be a CIDR") from exc
            # Comparación en el servidor con el tipo inet de PostgreSQL (la columna es texto
            # canónico validado al escribir, así que el cast nunca falla).
            query = query.where(cast(obs.address, INET).op("<<=")(cast(str(network), INET)))
        if f.q:
            text = f.q.strip()
            if len(text) > 100:
                raise _invalid("q is limited to 100 characters")
            if text:
                # Escapado de comodines: el texto del usuario se busca literal.
                pattern = (
                    "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
                )
                query = query.where(
                    or_(
                        obs.address.ilike(pattern, escape="\\"),
                        obs.hostname.ilike(pattern, escape="\\"),
                        obs.reverse_dns.ilike(pattern, escape="\\"),
                        obs.mac.ilike(pattern, escape="\\"),
                    )
                )
        return query

    def search(self, filters: ObservationFilters, limit: int, offset: int) -> ObservationList:
        obs = DiscoveryObservation
        base = self._where(select(obs), filters)
        if filters.latest:
            # Última observación de cada (site, IP): la vista de red. Los filtros se aplican
            # antes, así "última que respondió vía icmp" es lo que el usuario pidió.
            latest = (
                base.ext(distinct_on(obs.site_id, obs.address))
                .order_by(obs.site_id, obs.address, obs.observed_at.desc(), obs.id.desc())
                .subquery()
            )
            total = int(self._session.scalar(select(func.count()).select_from(latest)) or 0)
            rows = self._session.scalars(
                select(obs)
                .join(latest, latest.c.id == obs.id)
                .order_by(obs.observed_at.desc(), obs.id.desc())
                .limit(limit)
                .offset(offset)
            ).all()
        else:
            total = int(
                self._session.scalar(select(func.count()).select_from(base.subquery())) or 0
            )
            rows = self._session.scalars(
                base.order_by(
                    obs.reachability,
                    cast(obs.address, INET),
                    obs.id,
                )
                .limit(limit)
                .offset(offset)
            ).all()
        return ObservationList(items=self._reads(rows), total=total, limit=limit, offset=offset)

    def _reads(self, rows: Sequence[DiscoveryObservation]) -> list[ObservationRead]:
        if not rows:
            return []
        session = self._session
        jobs = {
            row.id: row.public_id
            for row in session.execute(
                select(DiscoveryJob.id, DiscoveryJob.public_id).where(
                    DiscoveryJob.id.in_({r.job_id for r in rows})
                )
            )
        }
        sites = {
            row.id: (row.public_id, row.name)
            for row in session.execute(
                select(Site.id, Site.public_id, Site.name).where(
                    Site.id.in_({r.site_id for r in rows})
                )
            )
        }
        sensor_ids = {r.sensor_id for r in rows if r.sensor_id is not None}
        sensors = (
            {
                row.id: (row.public_id, row.name)
                for row in session.execute(
                    select(Sensor.id, Sensor.public_id, Sensor.name).where(
                        Sensor.id.in_(sensor_ids)
                    )
                )
            }
            if sensor_ids
            else {}
        )
        asset_ids = {r.asset_id for r in rows if r.asset_id is not None}
        assets = (
            {
                row.id: row.public_id
                for row in session.execute(
                    select(Asset.id, Asset.public_id).where(Asset.id.in_(asset_ids))
                )
            }
            if asset_ids
            else {}
        )
        items = []
        for r in rows:
            sensor = sensors.get(r.sensor_id) if r.sensor_id is not None else None
            items.append(
                ObservationRead(
                    observation_id=r.public_id,
                    job_id=jobs[r.job_id],
                    site_id=sites[r.site_id][0],
                    site_name=sites[r.site_id][1],
                    executor="sensor" if r.executor == "sensor" else "local",
                    sensor_id=sensor[0] if sensor else None,
                    sensor_name=sensor[1] if sensor else None,
                    asset_id=assets.get(r.asset_id) if r.asset_id is not None else None,
                    address=r.address,
                    mac=r.mac,
                    hostname=r.hostname,
                    reverse_dns=r.reverse_dns,
                    forward_dns_match=r.forward_dns_match,
                    open_ports=list(r.open_ports or []),
                    # Pista IANA por número de puerto: siempre inferida, nunca confirmada.
                    port_hints=[
                        PortHint(port=p, hint=SERVICE_HINTS[p])
                        for p in r.open_ports or []
                        if p in SERVICE_HINTS
                    ],
                    methods=list(r.methods or []),
                    reachability=r.reachability,
                    rtt_ms=r.rtt_ms,
                    confidence=r.confidence,
                    evidence=[ObservationEvidence.model_validate(e) for e in r.evidence or []],
                    changes=[ObservationChange.model_validate(c) for c in r.changes or []],
                    profile=r.profile,
                    observed_at=r.observed_at,
                )
            )
        return items

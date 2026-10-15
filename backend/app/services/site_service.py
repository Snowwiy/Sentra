"""Sites y redes autorizadas (Fase 5F, docs/sites.md).

Reglas:
- Multi-site NO es multi-tenant: un único Sentra, RBAC global, sin aislamiento por cliente.
- Siempre existe un site por defecto ("Local"): contiene los datos anteriores a 5F y es el
  único donde corre el discovery del propio servidor. No se deshabilita, archiva ni borra.
- Un site con datos nunca se borra: se archiva (evidencia histórica intacta). Solo un site
  recién creado y sin nada asociado admite DELETE.
- Las redes de un site pueden solaparse con las de OTRO site (192.168.1.0/24 en dos sedes),
  nunca entre sí dentro del mismo site (ambigüedad sobre qué red cubre una dirección).
- Validación de CIDR con las mismas reglas que el discovery local (sin /0, multicast,
  reservadas, públicas solo con DISCOVERY_ALLOW_PUBLIC_NETWORKS y tope de hosts).
"""

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import ColumnElement, delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import (
    AssetLifecycleConflictError,
    NotFoundError,
    SiteConflictError,
    SiteNetworkNotFoundError,
    SiteNotFoundError,
    SiteValidationError,
)
from app.discovery.targets import TargetError, parse_network, validate_network
from app.models.asset import Asset
from app.models.discovery import DiscoveryJob
from app.models.enrollment import AgentEnrollmentToken
from app.models.site import (
    OPEN_SENSOR_JOB_STATUSES,
    Sensor,
    SensorEnrollmentToken,
    SensorJob,
    Site,
    SiteNetwork,
)
from app.schemas.site import (
    AssetSiteChange,
    SiteArchive,
    SiteCreate,
    SiteList,
    SiteNetworkCreate,
    SiteNetworkList,
    SiteNetworkRead,
    SiteNetworkUpdate,
    SiteRead,
    SiteUpdate,
)
from app.services import audit_service
from app.services.audit_service import Actor


def default_site_id(session: Session) -> int:
    """Id interno del site por defecto (siempre existe: lo crea la migración 0032)."""
    site_id = session.scalar(select(Site.id).where(Site.is_default))
    if site_id is None:  # pragma: no cover - solo con la base manipulada a mano
        raise RuntimeError("default site missing; run alembic upgrade head")
    return int(site_id)


def resolve_site(session: Session, public_id: UUID | None) -> int | None:
    """Filtro `site_id` de la API → id interno. None = todos los sites. 404 si no existe."""
    if public_id is None:
        return None
    site_id = session.scalar(select(Site.id).where(Site.public_id == public_id))
    if site_id is None:
        raise SiteNotFoundError("Site not found")
    return int(site_id)


def in_site(column: Any, site_id: int | None) -> ColumnElement[bool] | None:
    """Condición "la fila pertenece a un activo del site" (subconsulta, sin JOIN ni N+1).

    `column` es la FK a assets.id de la tabla filtrada (alerts.asset_id, detections.asset_id...).
    Los datos de seguridad no duplican el site: lo heredan de su activo.
    """
    if site_id is None:
        return None
    condition: ColumnElement[bool] = column.in_(select(Asset.id).where(Asset.site_id == site_id))
    return condition


@dataclass(frozen=True)
class SiteRef:
    public_id: UUID
    name: str


def site_refs(session: Session) -> dict[int, SiteRef]:
    """id interno → (uuid, nombre) de todos los sites en UNA consulta (son pocos)."""
    return {
        row.id: SiteRef(row.public_id, row.name)
        for row in session.execute(select(Site.id, Site.public_id, Site.name))
    }


def _slugify(name: str) -> str:
    text = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", text).strip("-")[:63]
    return slug or "site"


def _check_timezone(value: str) -> str:
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise SiteValidationError(
            "site_timezone_invalid", f"Unknown timezone {value!r} (use an IANA name)"
        ) from exc
    return value


class SiteService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    # --- lectura -----------------------------------------------------------------------------

    def _counts(self, site_ids: list[int]) -> dict[str, dict[int, int]]:
        """Activos, sensores (no revocados) y redes por site: tres GROUP BY, sin N+1."""
        if not site_ids:
            return {"assets": {}, "sensors": {}, "networks": {}}

        def grouped(column: Any, *where: Any) -> dict[int, int]:
            return {
                int(site): int(count)
                for site, count in self._session.execute(
                    select(column, func.count())
                    .where(column.in_(site_ids), *where)
                    .group_by(column)
                )
            }

        return {
            "assets": grouped(Asset.site_id, Asset.archived_at.is_(None)),
            "sensors": grouped(Sensor.site_id, Sensor.status != "revoked"),
            "networks": grouped(SiteNetwork.site_id),
        }

    def _read(self, site: Site, counts: dict[str, dict[int, int]] | None = None) -> SiteRead:
        counts = counts if counts is not None else self._counts([site.id])
        return SiteRead(
            site_id=site.public_id,
            name=site.name,
            slug=site.slug,
            description=site.description,
            location_label=site.location_label,
            timezone=site.timezone,
            status=site.status,
            is_default=site.is_default,
            version=site.version,
            created_at=site.created_at,
            updated_at=site.updated_at,
            archived_at=site.archived_at,
            asset_count=counts["assets"].get(site.id, 0),
            sensor_count=counts["sensors"].get(site.id, 0),
            network_count=counts["networks"].get(site.id, 0),
        )

    def list(self) -> SiteList:
        sites = self._session.scalars(
            select(Site).order_by(Site.is_default.desc(), func.lower(Site.name), Site.id)
        ).all()
        counts = self._counts([s.id for s in sites])
        return SiteList(items=[self._read(s, counts) for s in sites])

    def get_row(self, public_id: UUID, *, lock: bool = False) -> Site:
        stmt = select(Site).where(Site.public_id == public_id)
        if lock:
            stmt = stmt.with_for_update()
        site = self._session.scalar(stmt)
        if site is None:
            raise SiteNotFoundError("Site not found")
        return site

    def get(self, public_id: UUID) -> SiteRead:
        return self._read(self.get_row(public_id))

    # --- escritura ---------------------------------------------------------------------------

    def create(self, body: SiteCreate, actor: Actor) -> SiteRead:
        slug = body.slug or _slugify(body.name)
        site = Site(
            name=body.name,
            slug=slug,
            description=body.description,
            location_label=body.location_label,
            timezone=_check_timezone(body.timezone),
            status="active",
            is_default=False,
            version=1,
            created_by=actor.name[:64],
        )
        self._session.add(site)
        try:
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise SiteConflictError(
                "site_slug_taken", f"A site with slug {slug!r} already exists"
            ) from exc
        audit_service.record(
            self._session,
            actor,
            "site_created",
            target_type="site",
            target_id=site.public_id,
            details={"name": site.name, "slug": site.slug},
            commit=False,
        )
        self._session.commit()
        return self._read(site)

    @staticmethod
    def _check_version(site: Site, version: int) -> None:
        if site.version != version:
            raise SiteConflictError(
                "site_conflict",
                "The site changed since it was loaded; reload and retry",
                [{"current_version": site.version, "status": site.status}],
            )

    def update(self, public_id: UUID, body: SiteUpdate, actor: Actor) -> SiteRead:
        site = self.get_row(public_id, lock=True)
        self._check_version(site, body.version)
        if site.status == "archived":
            raise SiteConflictError("site_archived", "Restore the site before editing it")
        changes: dict[str, Any] = {}
        for field in ("name", "description", "location_label", "timezone"):
            value = getattr(body, field)
            if value is None or value == getattr(site, field):
                continue
            if field == "timezone":
                _check_timezone(value)
            changes[field] = value
        if body.status is not None and body.status != site.status:
            if site.is_default and body.status != "active":
                raise SiteConflictError(
                    "site_default_protected", "The default site cannot be disabled"
                )
            changes["status"] = body.status
        if not changes:
            return self._read(site)
        for field, value in changes.items():
            setattr(site, field, value)
        site.version += 1
        if changes.get("status") == "disabled":
            # Un site deshabilitado no recibe trabajo nuevo y lo pendiente se cancela: un
            # sensor conectado deja de recibir jobs en su siguiente poll (comportamiento
            # determinista, ver docs/distributed-sensors.md).
            cancel_site_jobs(self._session, site.id, "site_disabled")
        audit_service.record(
            self._session,
            actor,
            "site_updated",
            target_type="site",
            target_id=site.public_id,
            # Solo nombres de campos y el estado: los textos libres no van a la auditoría.
            details={"fields": sorted(changes), "status": site.status},
            commit=False,
        )
        self._session.commit()
        return self._read(site)

    def archive(self, public_id: UUID, body: SiteArchive, actor: Actor) -> SiteRead:
        site = self.get_row(public_id, lock=True)
        self._check_version(site, body.version)
        if site.is_default:
            raise SiteConflictError("site_default_protected", "The default site cannot be archived")
        if site.status == "archived":
            return self._read(site)
        site.status = "archived"
        site.archived_at = datetime.now(UTC)
        site.archive_reason = body.reason
        site.version += 1
        cancel_site_jobs(self._session, site.id, "site_archived")
        audit_service.record(
            self._session,
            actor,
            "site_archived",
            target_type="site",
            target_id=site.public_id,
            commit=False,
        )
        self._session.commit()
        return self._read(site)

    def restore(self, public_id: UUID, version: int, actor: Actor) -> SiteRead:
        site = self.get_row(public_id, lock=True)
        self._check_version(site, version)
        if site.status != "archived":
            raise SiteConflictError("site_not_archived", "The site is not archived")
        site.status = "active"
        site.archived_at = None
        site.archive_reason = None
        site.version += 1
        audit_service.record(
            self._session,
            actor,
            "site_restored",
            target_type="site",
            target_id=site.public_id,
            commit=False,
        )
        self._session.commit()
        return self._read(site)

    def data_counts(self, site_id: int) -> dict[str, int]:
        """Lo que impide borrar un site: cualquier dato o evidencia asociada."""
        checks: dict[str, Any] = {
            "assets": select(func.count()).select_from(Asset).where(Asset.site_id == site_id),
            "sensors": select(func.count()).select_from(Sensor).where(Sensor.site_id == site_id),
            "sensor_jobs": select(func.count())
            .select_from(SensorJob)
            .where(SensorJob.site_id == site_id),
            "discovery_jobs": select(func.count())
            .select_from(DiscoveryJob)
            .where(DiscoveryJob.site_id == site_id),
            "sensor_enrollment_tokens": select(func.count())
            .select_from(SensorEnrollmentToken)
            .where(SensorEnrollmentToken.site_id == site_id),
            "agent_enrollment_tokens": select(func.count())
            .select_from(AgentEnrollmentToken)
            .where(AgentEnrollmentToken.site_id == site_id),
        }
        return {name: int(self._session.scalar(q) or 0) for name, q in checks.items()}

    def delete(self, public_id: UUID, version: int, actor: Actor) -> None:
        site = self.get_row(public_id, lock=True)
        self._check_version(site, version)
        if site.is_default:
            raise SiteConflictError("site_default_protected", "The default site cannot be deleted")
        counts = {k: v for k, v in self.data_counts(site.id).items() if v}
        if counts:
            # Preservar evidencia: con cualquier dato asociado solo cabe archivar.
            raise SiteConflictError(
                "site_has_data",
                "The site has associated data; archive it instead",
                [{"counts": counts}],
            )
        site_public = site.public_id
        self._session.execute(delete(SiteNetwork).where(SiteNetwork.site_id == site.id))
        self._session.delete(site)
        audit_service.record(
            self._session,
            actor,
            "site_deleted",
            target_type="site",
            target_id=site_public,
            commit=False,
        )
        self._session.commit()

    # --- redes -------------------------------------------------------------------------------

    def _network_read(self, row: SiteNetwork, site_public: UUID) -> SiteNetworkRead:
        network = ipaddress.ip_network(row.cidr)
        return SiteNetworkRead(
            network_id=row.public_id,
            site_id=site_public,
            cidr=row.cidr,
            name=row.name,
            enabled=row.enabled,
            host_count=network.num_addresses
            if network.num_addresses <= 2
            else network.num_addresses - (2 if network.version == 4 else 1),
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def networks(self, public_id: UUID) -> SiteNetworkList:
        site = self.get_row(public_id)
        rows = self._session.scalars(
            select(SiteNetwork).where(SiteNetwork.site_id == site.id).order_by(SiteNetwork.cidr)
        ).all()
        return SiteNetworkList(items=[self._network_read(r, site.public_id) for r in rows])

    def validate_cidr(self, cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        """Mismas reglas que DISCOVERY_ALLOWED_NETWORKS (app/discovery/targets.py)."""
        try:
            return validate_network(
                parse_network(cidr.strip()),
                self._settings.discovery_max_hosts_per_network,
                self._settings.discovery_allow_public_networks,
            )
        except TargetError as exc:
            raise SiteValidationError("site_network_invalid", str(exc)) from exc

    def add_network(
        self, public_id: UUID, body: SiteNetworkCreate, actor: Actor
    ) -> SiteNetworkRead:
        site = self.get_row(public_id, lock=True)
        if site.status == "archived":
            raise SiteConflictError("site_archived", "Restore the site before editing it")
        network = self.validate_cidr(body.cidr)
        existing = self._session.scalars(
            select(SiteNetwork).where(SiteNetwork.site_id == site.id)
        ).all()
        for other in existing:
            other_net = ipaddress.ip_network(other.cidr)
            if other_net.version == network.version and network.overlaps(other_net):
                # Dentro de un site, dos redes que se solapan harían ambiguo qué red cubre una
                # dirección (y duplicarían sondas). Entre sites distintos es lo normal.
                raise SiteConflictError(
                    "site_network_overlap",
                    f"{network} overlaps {other_net} already configured in this site",
                    [{"overlaps": str(other_net)}],
                )
        row = SiteNetwork(
            site_id=site.id,
            cidr=str(network),
            name=body.name,
            enabled=body.enabled,
            created_by=actor.name[:64],
        )
        self._session.add(row)
        self._session.flush()
        audit_service.record(
            self._session,
            actor,
            "site_network_created",
            target_type="site",
            target_id=site.public_id,
            details={"cidr": row.cidr, "enabled": row.enabled},
            commit=False,
        )
        self._session.commit()
        self._session.refresh(row)
        return self._network_read(row, site.public_id)

    def _network_row(self, site: Site, network_id: UUID) -> SiteNetwork:
        row = self._session.scalar(
            select(SiteNetwork)
            .where(SiteNetwork.public_id == network_id, SiteNetwork.site_id == site.id)
            .with_for_update()
        )
        if row is None:
            # La red de OTRO site responde igual que una inexistente (sin IDOR).
            raise SiteNetworkNotFoundError("Network not found")
        return row

    def update_network(
        self, public_id: UUID, network_id: UUID, body: SiteNetworkUpdate, actor: Actor
    ) -> SiteNetworkRead:
        site = self.get_row(public_id, lock=True)
        row = self._network_row(site, network_id)
        changed: list[str] = []
        if body.name is not None and body.name != row.name:
            row.name = body.name
            changed.append("name")
        if body.enabled is not None and body.enabled != row.enabled:
            row.enabled = body.enabled
            changed.append("enabled")
        if changed:
            audit_service.record(
                self._session,
                actor,
                "site_network_updated",
                target_type="site",
                target_id=site.public_id,
                details={"cidr": row.cidr, "fields": changed, "enabled": row.enabled},
                commit=False,
            )
        self._session.commit()
        self._session.refresh(row)
        return self._network_read(row, site.public_id)

    def remove_network(self, public_id: UUID, network_id: UUID, actor: Actor) -> None:
        site = self.get_row(public_id, lock=True)
        row = self._network_row(site, network_id)
        cidr = row.cidr
        # Una red es configuración, no evidencia: los jobs y activos ya vistos conservan su
        # target y su discovery_network. Desde ahora ningún sensor puede escanearla.
        self._session.delete(row)
        audit_service.record(
            self._session,
            actor,
            "site_network_removed",
            target_type="site",
            target_id=site.public_id,
            details={"cidr": cidr},
            commit=False,
        )
        self._session.commit()


def enabled_networks(session: Session, site_id: int) -> list[str]:
    return list(
        session.scalars(
            select(SiteNetwork.cidr)
            .where(SiteNetwork.site_id == site_id, SiteNetwork.enabled.is_(True))
            .order_by(SiteNetwork.cidr)
        )
    )


def cancel_site_jobs(session: Session, site_id: int, reason: str) -> int:
    """Cancela los jobs de sensor abiertos de un site (deshabilitado o archivado). Sin commit."""
    from app.services.sensor_service import cancel_jobs

    ids = list(
        session.scalars(
            select(SensorJob.id).where(
                SensorJob.site_id == site_id, SensorJob.status.in_(OPEN_SENSOR_JOB_STATUSES)
            )
        )
    )
    return cancel_jobs(session, ids, reason)


def move_asset(session: Session, asset_public: UUID, body: AssetSiteChange, actor: Actor) -> Asset:
    """Mueve un activo de site (solo admin, auditado). Sin commit.

    Es la única forma de que un activo cambie de site: ni un agente que re-enrola ni un
    sensor pueden hacerlo. Útil si un equipo se trasladó de sede o se enroló en el site
    equivocado; después ya puede reconciliarse con activos del site nuevo.
    """
    asset = session.scalar(select(Asset).where(Asset.public_id == asset_public).with_for_update())
    if asset is None:
        raise NotFoundError("Asset not found")
    if asset.lifecycle_version != body.version:
        raise AssetLifecycleConflictError(
            "Asset changed since it was loaded; reload and retry",
            [{"version": asset.lifecycle_version, "archived": asset.is_archived}],
        )
    site = session.scalar(select(Site).where(Site.public_id == body.site_id))
    if site is None:
        raise SiteNotFoundError("Site not found")
    if site.status != "active":
        raise SiteConflictError("site_not_active", f"Site is {site.status}")
    previous = session.get(Site, asset.site_id)
    if asset.site_id == site.id:
        return asset
    asset.site_id = site.id
    asset.lifecycle_version += 1
    # La presencia de red medida en el site anterior no dice nada del nuevo: el siguiente
    # discovery del site nuevo empieza de cero (sin falsos "desaparecido").
    asset.network_misses = 0
    audit_service.record(
        session,
        actor,
        "asset_site_changed",
        target_type="asset",
        target_id=asset.public_id,
        details={
            "from_site_id": str(previous.public_id) if previous else None,
            "to_site_id": str(site.public_id),
            "reason": body.reason,
        },
        commit=False,
    )
    return asset

"""Identidad de dispositivos (Fase 7B.2, docs/device-identity-wifi.md).

Reúne lo que ya saben las fuentes existentes (agente, DHCP, DNS, mDNS, NetBIOS, SSDP/UPnP,
HTTP/TLS, OUI, Wi-Fi y las decisiones manuales) en una ficha por niveles: nombre,
fabricante, tipo y sistema operativo se evalúan por separado, cada uno con su fuente,
vigencia y estado. No vuelve a clasificar: lee la conclusión de classify.identify y su
evidencia, y solo decide cuánto se puede afirmar.

Reglas que protegen frente a fusiones falsas:
- una MAC con el bit localmente administrado (privada/aleatoria) no identifica a un equipo:
  sin agente ni asociación manual, el activo queda `identity_unresolved`;
- las sugerencias de "es el mismo dispositivo" necesitan evidencia fuerte o media (identidad
  de máquina, linaje de agente, MAC que el propio agente declara, MAC universal o MAC del
  historial). La IP, el OUI, el SO o un nombre parecido nunca bastan solos: con DHCP la
  misma IP es otro equipo cada semana y un nombre se copia;
- nada se fusiona solo. Una asociación manual (AssetIdentityLink) la decide un admin tras
  una vista previa, queda auditada y se deshace con exactitud.
"""

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import String, and_, func, or_, select, true
from sqlalchemy.orm import Session

from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    SentraError,
    WlanClientNotFoundError,
)
from app.discovery.classify import AGENT_HOSTNAME, AGENT_OS
from app.discovery.device_types import ClassificationConfidence
from app.discovery.probes import normalize_mac
from app.models.asset import Asset
from app.models.asset_lineage import AssetAgentLineage
from app.models.dhcp import AssetIdentityHistory
from app.models.identity_link import AssetIdentityLink
from app.models.inventory import AssetInventory
from app.models.wlan import WlanAgentReport, WlanClient
from app.schemas.identity import (
    AddressChange,
    AssetIdentityProfile,
    CandidateEvidence,
    IdentityAssetRef,
    IdentityCandidate,
    IdentityCandidateList,
    IdentityComparison,
    IdentityGap,
    IdentityLinkCreate,
    IdentityLinkList,
    IdentityLinkPreview,
    IdentityLinkRead,
    IdentityLinkRequest,
    IdentitySource,
    IdentityTier,
    MacProfile,
)
from app.services import audit_service
from app.services.agent_management_service import agent_platform
from app.services.asset_lifecycle_policy import has_managed_history
from app.services.asset_lifecycle_service import AssetLifecycleService
from app.services.audit_service import Actor
from app.services.identification import NAME_STALE_DAYS, network_adapter_vendor, source_seen_times
from app.services.identity_rules import identity_state, is_universal_mac, mac_profile
from app.services.reconciliation import interface_identity

logger = logging.getLogger(__name__)

MAX_CANDIDATES = 10
MAX_POOL = 60
MAX_ADDRESSES = 50
MAX_LINKS = 100
STALE_AFTER = timedelta(days=NAME_STALE_DAYS)

# Fuerza de cada motivo de coincidencia. Los "weak" solo apoyan: nunca crean un candidato.
STRENGTH: dict[str, str] = {
    "same_machine_id": "strong",
    "same_agent_lineage": "strong",
    "manual_link": "strong",
    "agent_reported_mac": "strong",
    "same_universal_mac": "medium",
    "mac_in_history": "medium",
    "same_device_name": "weak",
    "same_ip": "weak",
    "same_vendor": "weak",
    "same_os": "weak",
}
_RANK = {"strong": 0, "medium": 1, "weak": 2}
# Clases de nombre (classify) que identifican a un equipo concreto; "generic" no.
_SPECIFIC_NAME_KINDS = ("agent", "device", "dhcp", "dns")


class IdentityLinkValidationError(SentraError):
    status_code = 422
    code = "identity_link_invalid"


class IdentityLinkRefusedError(ConflictError):
    code = "identity_link_refused"


class IdentityLinkNotFoundError(NotFoundError):
    code = "identity_link_not_found"


# --- Ficha por niveles ----------------------------------------------------------------------


def _freshness(when: datetime | None, now: datetime, stale: bool | None = None) -> str:
    if stale:
        return "stale"
    if when is None:
        return "unknown"
    return "stale" if now - when > STALE_AFTER else "fresh"


def _name_tier(asset: Asset, seen: dict[str, datetime], now: datetime) -> IdentityTier:
    names = [n for n in asset.observed_names or [] if isinstance(n, dict)]
    selected = next((n for n in names if n.get("selected")), None)
    alternatives = [
        IdentitySource(
            source=str(n.get("source")),
            value=str(n.get("value")) if n.get("value") is not None else None,
            seen_at=seen.get(str(n.get("source"))),
            freshness=_freshness(seen.get(str(n.get("source"))), now, bool(n.get("stale"))),
        )
        for n in names
        if n is not selected
    ]
    if selected is None:
        return IdentityTier(
            value=None,
            source=None,
            state="unresolved",
            reasons=["no_name_source"],
            alternatives=alternatives,
        )
    source = str(selected.get("source"))
    kind = selected.get("kind")
    reasons: list[str] = []
    if kind == "agent" or source == AGENT_HOSTNAME:
        state, reasons = "confirmed", ["agent_reported"]
    elif selected.get("stale"):
        state, reasons = "unresolved", ["stale_source"]
    elif kind in _SPECIFIC_NAME_KINDS:
        state, reasons = "probable", [f"{kind}_name"]
        if selected.get("confirmed"):
            reasons.append("corroborated")
    else:
        state, reasons = "unresolved", ["generic_name"]
    return IdentityTier(
        value=str(selected.get("value")),
        source=source,
        state=state,
        reasons=reasons,
        alternatives=alternatives,
    )


def _evidence_source(asset: Asset, *candidates: str) -> str | None:
    for item in asset.classification_evidence or []:
        if isinstance(item, dict) and item.get("source") in candidates:
            return str(item["source"])
    return None


def _vendor_tier(asset: Asset, mac: MacProfile) -> IdentityTier:
    nic = mac.nic_vendor
    alternatives = (
        [IdentitySource(source="mac_vendor", value=nic, seen_at=None, freshness="unknown")]
        if nic and asset.device_vendor
        else []
    )
    if asset.device_vendor:
        # Marca del equipo deducida de lo que anuncia (UPnP, mDNS, web, nombre): probable.
        source = _evidence_source(asset, "upnp", "mdns_service", "web", "ssdp") or "fingerprint"
        return IdentityTier(
            value=asset.device_vendor,
            source=source,
            state="probable",
            reasons=["device_announced"],
            alternatives=alternatives,
        )
    if nic:
        # El OUI es el fabricante de la tarjeta de red, que no siempre es la marca del equipo.
        return IdentityTier(
            value=nic,
            source="mac_vendor",
            state="probable",
            reasons=["network_adapter_only"],
            alternatives=[],
        )
    reason = "random_mac" if mac.randomized else "no_vendor_evidence"
    return IdentityTier(
        value=None, source=None, state="unresolved", reasons=[reason], alternatives=[]
    )


def _type_tier(asset: Asset) -> IdentityTier:
    reasons = [asset.device_type_reason] if asset.device_type_reason else []
    if asset.manual_device_type:
        return IdentityTier(
            value=asset.manual_device_type,
            source="manual",
            state="confirmed",
            reasons=["manual_type", *reasons],
            alternatives=[],
        )
    if not asset.device_type:
        return IdentityTier(
            value=None,
            source=None,
            state="unresolved",
            reasons=["no_type_evidence"],
            alternatives=[],
        )
    confidence = asset.classification_confidence
    state = (
        "probable"
        if confidence in (ClassificationConfidence.HIGH, ClassificationConfidence.MEDIUM)
        else "unresolved"
    )
    return IdentityTier(
        value=asset.device_type,
        source="classification",
        state=state,
        reasons=[f"confidence_{confidence.value if confidence else 'none'}", *reasons],
        alternatives=[],
    )


def _os_tier(asset: Asset) -> IdentityTier:
    if asset.is_managed and asset.os_name:
        value = " ".join(x for x in (asset.os_name, asset.os_version) if x)
        return IdentityTier(
            value=value,
            source=AGENT_OS,
            state="confirmed",
            reasons=["agent_reported"],
            alternatives=[],
        )
    if asset.probable_os:
        return IdentityTier(
            value=asset.probable_os,
            source="inference",
            state="probable",
            reasons=["network_fingerprint"],
            alternatives=[],
        )
    return IdentityTier(
        value=None, source=None, state="unresolved", reasons=["no_os_evidence"], alternatives=[]
    )


def _model_tier(asset: Asset) -> IdentityTier:
    """Modelo: solo el que declara el equipo (UPnP, mDNS) o un código de modelo respaldado por
    el fabricante deducido por otra vía (app/discovery/classify.py)."""
    if not asset.device_model:
        return IdentityTier(
            value=None,
            source=None,
            state="unresolved",
            reasons=["no_model_evidence"],
            alternatives=[],
        )
    source = _evidence_source(asset, "upnp", "mdns_service", "web") or "name_model_code"
    return IdentityTier(
        value=asset.device_model,
        source=source,
        state="probable",
        reasons=["device_announced" if source != "name_model_code" else "model_code_confirmed"],
        alternatives=[],
    )


def _assigned_name_tier(asset: Asset) -> IdentityTier:
    """Nombre que fijó un admin: confirmado y por encima de cualquier nombre deducido."""
    if not asset.custom_label:
        return IdentityTier(
            value=None, source=None, state="unresolved", reasons=["no_admin_label"], alternatives=[]
        )
    return IdentityTier(
        value=asset.custom_label,
        source="admin",
        state="confirmed",
        reasons=["admin_label"],
        alternatives=(
            [
                IdentitySource(
                    source=f"admin:{asset.custom_label_updated_by}",
                    value=asset.custom_label,
                    seen_at=asset.custom_label_updated_at,
                    freshness="fresh",
                )
            ]
            if asset.custom_label_updated_by
            else []
        ),
    )


_DHCP_HINT = (
    "Importe la lista de clientes DHCP del router (CSV ip,mac,hostname) en Red > DHCP: es una"
    " fuente de solo lectura y verificable."
)


def identity_gaps(
    asset: Asset, mac: MacProfile, tiers: dict[str, IdentityTier]
) -> list[IdentityGap]:
    """Qué falta para identificar el equipo y cómo conseguirlo (Fase 7B-Fix1)."""
    gaps: list[IdentityGap] = []
    if mac.randomized and not asset.is_managed:
        gaps.append(
            IdentityGap(
                field="stable_identity",
                code="private_mac",
                detail=(
                    "MAC privada: puede cambiar por red o con el tiempo y no se usa para fusionar"
                    " registros. Asocie el cliente Wi-Fi a mano o instale el agente."
                ),
            )
        )
    if tiers["name"].state == "unresolved" and not asset.custom_label:
        gaps.append(
            IdentityGap(
                field="name",
                code="no_specific_name",
                detail=_DHCP_HINT + " Un admin también puede asignarle un nombre.",
            )
        )
    if tiers["vendor"].state == "unresolved" or (
        tiers["vendor"].reasons == ["network_adapter_only"]
    ):
        gaps.append(
            IdentityGap(
                field="vendor",
                code="private_mac" if mac.randomized else "nic_vendor_only",
                detail=(
                    "Sin fabricante: la MAC privada no tiene OUI."
                    if mac.randomized
                    else "Solo se conoce el fabricante de la tarjeta de red (OUI), no la marca"
                    " del equipo."
                )
                + " La marca la aportan mDNS, SSDP/UPnP o la web del propio equipo.",
            )
        )
    if tiers["model"].state == "unresolved":
        gaps.append(
            IdentityGap(
                field="model",
                code="no_model_evidence",
                detail=(
                    "Ningún anuncio del equipo (UPnP, mDNS _device-info) declara el modelo, ni"
                    " hay un código de modelo respaldado por el fabricante."
                ),
            )
        )
    if tiers["device_type"].state == "unresolved":
        gaps.append(
            IdentityGap(
                field="device_type",
                code="no_type_evidence",
                detail="Un admin puede fijar el tipo a mano; manda sobre la clasificación.",
            )
        )
    if tiers["os"].state == "unresolved" and not asset.is_managed:
        gaps.append(
            IdentityGap(
                field="os",
                code="no_os_evidence",
                detail="Desde la red no se demuestra el sistema operativo sin el agente.",
            )
        )
    return gaps


# --- Servicio -------------------------------------------------------------------------------


@dataclass
class _PairEvidence:
    items: list[CandidateEvidence] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)

    def add(self, code: str, detail: str | None = None) -> None:
        if all(i.code != code for i in self.items):
            self.items.append(CandidateEvidence(code=code, strength=STRENGTH[code], detail=detail))

    @property
    def strength(self) -> str | None:
        """Fuerza del candidato, o None si la evidencia no basta para sugerirlo."""
        strengths = {i.strength for i in self.items}
        if "strong" in strengths:
            return "strong"
        if "medium" in strengths:
            return "medium"
        codes = {i.code for i in self.items}
        # Dos señales débiles independientes, y una de ellas un nombre propio del equipo:
        # la IP, el OUI o el SO por sí solos no sugieren a nadie.
        if "same_device_name" in codes and len(codes) >= 2:
            return "weak"
        return None


@dataclass
class _Facts:
    """Lo que hace falta de un activo para compararlo (cargado una vez por consulta)."""

    asset: Asset
    agents: set[UUID]
    reported_macs: set[str]
    mac_history: set[str]
    ip_history: set[str]
    name: str | None


def _bare(name: str | None) -> str | None:
    value = (name or "").strip().rstrip(".").split(".", 1)[0].lower()
    return value or None


def _selected_name(asset: Asset) -> str | None:
    for item in asset.observed_names or []:
        if isinstance(item, dict) and item.get("selected"):
            if item.get("kind") in _SPECIFIC_NAME_KINDS and not item.get("stale"):
                return _bare(str(item.get("value")))
            return None
    return _bare(asset.hostname) if asset.is_managed else None


def _platform(asset: Asset) -> str | None:
    if asset.os_name:
        return agent_platform(asset.os_name)
    return None


class DeviceIdentityService:
    def __init__(self, session: Session, heartbeat_timeout: timedelta) -> None:
        self._session = session
        self._timeout = heartbeat_timeout

    # --- lectura ----------------------------------------------------------------------------

    def _asset(self, public_id: UUID, *, lock: bool = False) -> Asset:
        stmt = select(Asset).where(Asset.public_id == public_id)
        if lock:
            stmt = stmt.with_for_update()
        asset = self._session.scalar(stmt)
        if asset is None:
            raise NotFoundError("Asset not found")
        return asset

    def _ref(self, asset: Asset) -> IdentityAssetRef:
        return IdentityAssetRef(
            asset_id=asset.public_id,
            display_name=asset.display_name,
            primary_ip=asset.primary_ip,
            mac_address=asset.mac_address,
            managed=asset.is_managed,
            archived=asset.archived_at is not None,
            last_seen_at=asset.last_seen_at or asset.last_network_seen_at,
        )

    def _sources(self, asset: Asset, now: datetime) -> list[IdentitySource]:
        seen = source_seen_times(asset)
        items = [
            IdentitySource(source=s, value=None, seen_at=t, freshness=_freshness(t, now))
            for s, t in sorted(seen.items(), key=lambda x: x[1], reverse=True)
        ]
        if asset.is_managed and asset.last_seen_at:
            items.insert(
                0,
                IdentitySource(
                    source="agent",
                    value=asset.agent_version,
                    seen_at=asset.last_seen_at,
                    freshness=_freshness(asset.last_seen_at, now),
                ),
            )
        if asset.last_network_seen_at:
            items.append(
                IdentitySource(
                    source="discovery",
                    value=asset.primary_ip,
                    seen_at=asset.last_network_seen_at,
                    freshness=_freshness(asset.last_network_seen_at, now),
                )
            )
        for client in self._session.scalars(
            select(WlanClient)
            .where(WlanClient.asset_id == asset.id)
            .order_by(WlanClient.last_seen_at.desc())
            .limit(5)
        ):
            items.append(
                IdentitySource(
                    source=f"wlan_{client.correlation_basis or 'observation'}",
                    value=client.ssid,
                    seen_at=client.last_seen_at,
                    freshness=_freshness(client.last_seen_at, now),
                )
            )
        return items

    def profile(self, public_id: UUID) -> AssetIdentityProfile:
        asset = self._asset(public_id)
        now = datetime.now(UTC)
        mac = mac_profile(asset.mac_address, network_adapter_vendor(asset))
        sources = self._sources(asset, now)
        state, reasons = identity_state(asset, mac, sources)
        history = self._session.scalars(
            select(AssetIdentityHistory)
            .where(
                AssetIdentityHistory.asset_id == asset.id,
                AssetIdentityHistory.field.in_(("ip", "mac")),
            )
            .order_by(AssetIdentityHistory.observed_at.desc(), AssetIdentityHistory.id.desc())
            .limit(MAX_ADDRESSES)
        ).all()
        links = self._links(
            or_(
                AssetIdentityLink.target_asset_id == asset.id,
                AssetIdentityLink.alias_asset_id == asset.id,
            )
        )
        if state == "identity_unresolved" and any(
            link.active and link.alias_asset_id == asset.public_id for link in links
        ):
            # Un admin asoció este registro a un dispositivo conocido: ya no está sin resolver.
            state, reasons = "probable", ["manual_link"]
        tiers = {
            "name": _name_tier(asset, source_seen_times(asset), now),
            "vendor": _vendor_tier(asset, mac),
            "device_type": _type_tier(asset),
            "os": _os_tier(asset),
            "model": _model_tier(asset),
            "assigned_name": _assigned_name_tier(asset),
        }
        return AssetIdentityProfile(
            **tiers,
            missing=identity_gaps(asset, mac, tiers),
            asset_id=asset.public_id,
            display_name=asset.display_name,
            custom_label=asset.custom_label,
            managed=asset.is_managed,
            archived=asset.archived_at is not None,
            state=state,
            reasons=reasons,
            mac=mac,
            sources=sources,
            addresses=[
                AddressChange(
                    field=h.field,
                    old_value=h.old_value,
                    new_value=h.new_value,
                    source=h.source,
                    observed_at=h.observed_at,
                )
                for h in history
            ],
            links=links,
        )

    # --- comparación y sugerencias --------------------------------------------------------

    def _facts(self, assets: Sequence[Asset]) -> dict[int, _Facts]:
        ids = [a.id for a in assets]
        if not ids:
            return {}
        agents: dict[int, set[UUID]] = {i: set() for i in ids}
        for asset in assets:
            if asset.agent_id is not None:
                agents[asset.id].add(asset.agent_id)
        for asset_id, agent_id in self._session.execute(
            select(AssetAgentLineage.asset_id, AssetAgentLineage.agent_id).where(
                AssetAgentLineage.asset_id.in_(ids)
            )
        ):
            agents[asset_id].add(agent_id)
        reported: dict[int, set[str]] = {i: set() for i in ids}
        for asset_id, interfaces in self._session.execute(
            select(AssetInventory.asset_id, AssetInventory.data["interfaces"]).where(
                AssetInventory.asset_id.in_(ids)
            )
        ):
            if isinstance(interfaces, list):
                reported[asset_id] |= interface_identity(interfaces)[1]
        for asset_id, interfaces in self._session.execute(
            select(WlanAgentReport.asset_id, WlanAgentReport.interfaces).where(
                WlanAgentReport.asset_id.in_(ids)
            )
        ):
            # El agente declara la MAC (también la privada) que usa su interfaz Wi-Fi.
            for item in interfaces or []:
                mac = normalize_mac(item.get("mac")) if isinstance(item, dict) else None
                if mac:
                    reported[asset_id].add(mac)
        macs: dict[int, set[str]] = {i: set() for i in ids}
        addresses: dict[int, set[str]] = {i: set() for i in ids}
        for asset_id, kind, old, new in self._session.execute(
            select(
                AssetIdentityHistory.asset_id,
                AssetIdentityHistory.field,
                AssetIdentityHistory.old_value,
                AssetIdentityHistory.new_value,
            ).where(
                AssetIdentityHistory.asset_id.in_(ids),
                AssetIdentityHistory.field.in_(("ip", "mac")),
            )
        ):
            target = macs if kind == "mac" else addresses
            target[asset_id] |= {v.lower() for v in (old, new) if v}
        return {
            a.id: _Facts(
                asset=a,
                agents=agents[a.id],
                reported_macs=reported[a.id],
                mac_history=macs[a.id] - ({a.mac_address} if a.mac_address else set()),
                ip_history=addresses[a.id] | {a.primary_ip},
                name=_selected_name(a),
            )
            for a in assets
        }

    def _linked_pairs(self, ids: Iterable[int]) -> set[frozenset[int]]:
        ids = list(ids)
        rows = self._session.execute(
            select(AssetIdentityLink.target_asset_id, AssetIdentityLink.alias_asset_id).where(
                AssetIdentityLink.kind == "asset_alias",
                AssetIdentityLink.revoked_at.is_(None),
                or_(
                    AssetIdentityLink.target_asset_id.in_(ids),
                    AssetIdentityLink.alias_asset_id.in_(ids),
                ),
            )
        ).all()
        return {frozenset((t, a)) for t, a in rows if a is not None}

    @staticmethod
    def _pair(a: _Facts, b: _Facts, linked: set[frozenset[int]]) -> _PairEvidence:
        x, y = a.asset, b.asset
        result = _PairEvidence()
        if x.machine_id_hash and y.machine_id_hash:
            if x.machine_id_hash == y.machine_id_hash:
                result.add("same_machine_id")
            else:
                result.conflicts.append("machine_id_mismatch")
        if a.agents & b.agents:
            result.add("same_agent_lineage")
        if frozenset((x.id, y.id)) in linked:
            result.add("manual_link")
        if (y.mac_address and y.mac_address in a.reported_macs) or (
            x.mac_address and x.mac_address in b.reported_macs
        ):
            result.add("agent_reported_mac", "La MAC la declara el agente del otro registro")
        if x.mac_address and x.mac_address == y.mac_address:
            if is_universal_mac(x.mac_address):
                result.add("same_universal_mac")
        elif is_universal_mac(x.mac_address) and is_universal_mac(y.mac_address):
            # Dos MACs de fábrica distintas: dos tarjetas (o dos equipos). Solo lo anota.
            result.conflicts.append("different_universal_mac")
        if (y.mac_address and y.mac_address in a.mac_history) or (
            x.mac_address and x.mac_address in b.mac_history
        ):
            result.add("mac_in_history")
        if a.name and a.name == b.name:
            result.add("same_device_name", a.name)
        if a.ip_history & b.ip_history:
            result.add("same_ip")
        vendor_x = x.device_vendor or network_adapter_vendor(x)
        if vendor_x and vendor_x == (y.device_vendor or network_adapter_vendor(y)):
            result.add("same_vendor")
        platforms = {_platform(x), _platform(y)}
        if None not in platforms and len(platforms) == 1:
            result.add("same_os")
        elif None not in platforms:
            result.conflicts.append("platform_mismatch")
        return result

    def _pool(self, asset: Asset, facts: _Facts) -> Sequence[Asset]:
        """Activos del mismo site que comparten algún identificador con `asset`.

        La IP entra en la búsqueda (para poder explicar una reutilización) pero no decide:
        el candidato lo decide _PairEvidence.strength.
        """
        macs = sorted(
            {m for m in (asset.mac_address,) if m} | facts.reported_macs | facts.mac_history
        )
        conditions: list[Any] = [Asset.primary_ip.in_(sorted(facts.ip_history))]
        if asset.machine_id_hash:
            conditions.append(Asset.machine_id_hash == asset.machine_id_hash)
        if macs:
            conditions.append(Asset.mac_address.in_(macs))
        if asset.mac_address:
            conditions.append(
                Asset.id.in_(
                    select(AssetIdentityHistory.asset_id).where(
                        AssetIdentityHistory.field == "mac",
                        or_(
                            AssetIdentityHistory.old_value == asset.mac_address,
                            AssetIdentityHistory.new_value == asset.mac_address,
                        ),
                    )
                )
            )
        if asset.mac_address:
            # Agentes que declaran esta MAC en su inventario o en su informe Wi-Fi (también
            # en el formato de Windows, con guiones).
            forms = (asset.mac_address, asset.mac_address.replace(":", "-"))
            inventory = func.lower(AssetInventory.data["interfaces"].astext)
            wifi = func.lower(func.cast(WlanAgentReport.interfaces, String))
            conditions.append(
                Asset.id.in_(
                    select(AssetInventory.asset_id).where(
                        or_(*(inventory.contains(f) for f in forms))
                    )
                )
            )
            conditions.append(
                Asset.id.in_(
                    select(WlanAgentReport.asset_id).where(or_(*(wifi.contains(f) for f in forms)))
                )
            )
        if facts.agents:
            agents = sorted(facts.agents)
            conditions.append(Asset.agent_id.in_(agents))
            conditions.append(
                Asset.id.in_(
                    select(AssetAgentLineage.asset_id).where(AssetAgentLineage.agent_id.in_(agents))
                )
            )
        if facts.name:
            conditions.append(func.lower(Asset.hostname) == facts.name)
            conditions.append(func.lower(Asset.device_name) == facts.name)
        linked = select(AssetIdentityLink.alias_asset_id).where(
            AssetIdentityLink.target_asset_id == asset.id, AssetIdentityLink.revoked_at.is_(None)
        )
        conditions.append(Asset.id.in_(linked))
        conditions.append(
            Asset.id.in_(
                select(AssetIdentityLink.target_asset_id).where(
                    AssetIdentityLink.alias_asset_id == asset.id,
                    AssetIdentityLink.revoked_at.is_(None),
                )
            )
        )
        return self._session.scalars(
            select(Asset)
            # Fase 5F: nunca se compara entre sites.
            .where(Asset.id != asset.id, Asset.site_id == asset.site_id, or_(*conditions))
            .order_by(Asset.last_seen_at.desc().nulls_last(), Asset.id)
            .limit(MAX_POOL)
        ).all()

    def candidates(self, public_id: UUID) -> IdentityCandidateList:
        """Registros que podrían ser este mismo dispositivo. Solo sugiere."""
        asset = self._asset(public_id)
        mine = self._facts([asset])[asset.id]
        pool = self._pool(asset, mine)
        facts = self._facts(pool)
        linked = self._linked_pairs([asset.id])
        items: list[IdentityCandidate] = []
        for other in pool:
            evidence = self._pair(mine, facts[other.id], linked)
            strength = evidence.strength
            if strength is None:
                continue
            items.append(
                IdentityCandidate(
                    asset=self._ref(other),
                    strength=strength,
                    evidence=sorted(evidence.items, key=lambda e: _RANK[e.strength]),
                )
            )
        items.sort(key=lambda c: (_RANK[c.strength], c.asset.archived))
        return IdentityCandidateList(items=items[:MAX_CANDIDATES])

    def compare(self, left_id: UUID, right_id: UUID) -> IdentityComparison:
        """Clasifica un par de registros (p. ej. el duplicado 192.168.50.66) con su evidencia."""
        left, right = self._asset(left_id), self._asset(right_id)
        if left.id == right.id:
            raise IdentityLinkValidationError("Compare two different assets")
        if left.site_id != right.site_id:
            # Nunca se emparejan registros de sites distintos (Fase 5F).
            return self._comparison(
                left,
                right,
                "distinct_records",
                "none",
                _PairEvidence(conflicts=["different_site"]),
                "Los registros pertenecen a sites distintos: Sentra nunca los empareja.",
                [],
            )
        facts = self._facts([left, right])
        evidence = self._pair(facts[left.id], facts[right.id], self._linked_pairs([left.id]))
        strength = evidence.strength
        codes = {i.code for i in evidence.items}
        managed = (has_managed_history(left), has_managed_history(right))
        if all(managed) and strength in ("strong", "medium"):
            newer, older = sorted(
                (left, right), key=lambda a: (a.first_seen_at, a.id), reverse=True
            )
            lifecycle = AssetLifecycleService(self._session, self._timeout)
            assessment = lifecycle._assess_pair(newer, older)
            action = "reconcile" if assessment.reconcilable else "none"
            return self._comparison(
                left,
                right,
                "same_agent_reinstalled",
                action,
                evidence,
                "Los dos registros tuvieron agente y comparten identidad de máquina, linaje o"
                " MAC: es una reinstalación. Se resuelve con la reconciliación (5C.2), que"
                " conserva el historial.",
                assessment.blockers,
            )
        if strength in ("strong", "medium"):
            if left.archived_at is not None or right.archived_at is not None:
                return self._comparison(
                    left,
                    right,
                    "historical_asset",
                    "none",
                    evidence,
                    "Uno de los registros está archivado y es el pasado del otro.",
                    [],
                )
            return self._comparison(
                left,
                right,
                "reconcilable_identity",
                "link_alias",
                evidence,
                "La evidencia apunta al mismo dispositivo. Un admin puede asociar el registro"
                " descubierto al conocido (se archiva, no se borra).",
                [],
            )
        if "same_ip" in codes:
            return self._comparison(
                left,
                right,
                "ip_reuse",
                "none",
                evidence,
                "Solo coinciden en la IP (y quizá en señales débiles): con DHCP es habitual que"
                " otro equipo reciba la misma dirección. No se asocian.",
                [],
            )
        return self._comparison(
            left,
            right,
            "distinct_records",
            "none",
            evidence,
            "No hay evidencia de que sean el mismo dispositivo.",
            [],
        )

    def _comparison(
        self,
        left: Asset,
        right: Asset,
        classification: str,
        action: str,
        evidence: _PairEvidence,
        explanation: str,
        blockers: list[str],
    ) -> IdentityComparison:
        return IdentityComparison(
            left=self._ref(left),
            right=self._ref(right),
            classification=classification,
            recommended_action=action,
            evidence=sorted(evidence.items, key=lambda e: _RANK[e.strength]),
            conflicts=evidence.conflicts,
            explanation=explanation,
            reconcile_blockers=blockers,
        )

    # --- asociaciones manuales ------------------------------------------------------------

    def _links(self, condition: Any) -> list[IdentityLinkRead]:
        rows = self._session.scalars(
            select(AssetIdentityLink)
            .where(condition)
            .order_by(AssetIdentityLink.created_at.desc(), AssetIdentityLink.id.desc())
            .limit(MAX_LINKS)
        ).all()
        asset_ids = {r.target_asset_id for r in rows} | {
            r.alias_asset_id for r in rows if r.alias_asset_id
        }
        assets = {
            a.id: a for a in self._session.scalars(select(Asset).where(Asset.id.in_(asset_ids)))
        }
        clients = dict(
            self._session.execute(
                select(WlanClient.id, WlanClient.public_id).where(
                    WlanClient.id.in_({r.wlan_client_id for r in rows if r.wlan_client_id})
                )
            ).all()
        )
        out: list[IdentityLinkRead] = []
        for row in rows:
            target = assets[row.target_asset_id]
            alias = assets.get(row.alias_asset_id) if row.alias_asset_id else None
            out.append(
                IdentityLinkRead(
                    link_id=row.public_id,
                    kind=row.kind,
                    target_asset_id=target.public_id,
                    target_name=target.display_name,
                    alias_asset_id=alias.public_id if alias else None,
                    alias_name=alias.display_name if alias else None,
                    wlan_client_id=clients.get(row.wlan_client_id) if row.wlan_client_id else None,
                    mac=row.mac,
                    reason=row.reason,
                    evidence=row.evidence,
                    active=row.revoked_at is None,
                    created_by=row.created_by,
                    created_at=row.created_at,
                    revoked_by=row.revoked_by,
                    revoked_at=row.revoked_at,
                    revoke_reason=row.revoke_reason,
                )
            )
        return out

    def list_links(
        self, asset_id: UUID | None, wlan_client_id: UUID | None, active: bool | None
    ) -> IdentityLinkList:
        conditions: list[Any] = []
        if asset_id is not None:
            asset = self._asset(asset_id)
            conditions.append(
                or_(
                    AssetIdentityLink.target_asset_id == asset.id,
                    AssetIdentityLink.alias_asset_id == asset.id,
                )
            )
        if wlan_client_id is not None:
            client = self._client(wlan_client_id)
            conditions.append(AssetIdentityLink.wlan_client_id == client.id)
        if active is True:
            conditions.append(AssetIdentityLink.revoked_at.is_(None))
        elif active is False:
            conditions.append(AssetIdentityLink.revoked_at.is_not(None))
        return IdentityLinkList(items=self._links(and_(true(), *conditions)))

    def _client(self, public_id: UUID, *, lock: bool = False) -> WlanClient:
        stmt = select(WlanClient).where(WlanClient.public_id == public_id)
        if lock:
            stmt = stmt.with_for_update()
        client = self._session.scalar(stmt)
        if client is None:
            raise WlanClientNotFoundError("Wireless client not found")
        return client

    def _active_link(self, **where: int) -> AssetIdentityLink | None:
        stmt = select(AssetIdentityLink).where(AssetIdentityLink.revoked_at.is_(None))
        for column, value in where.items():
            stmt = stmt.where(getattr(AssetIdentityLink, column) == value)
        return self._session.scalars(stmt.limit(1)).first()

    def _plan(
        self, body: IdentityLinkRequest, *, lock: bool = False
    ) -> tuple[Asset, Asset | None, WlanClient | None, IdentityLinkPreview]:
        target = self._asset(body.target_asset_id, lock=lock)
        alias: Asset | None = None
        client: WlanClient | None = None
        blockers: list[str] = []
        effects: list[str] = []
        evidence: list[CandidateEvidence] = []
        mac: str | None = None
        if target.archived_at is not None:
            blockers.append("target_archived")
        if body.kind == "asset_alias":
            if body.alias_asset_id is None or body.wlan_client_id is not None:
                raise IdentityLinkValidationError("asset_alias needs alias_asset_id only")
            alias = self._asset(body.alias_asset_id, lock=lock)
            mac = alias.mac_address
            if alias.id == target.id:
                blockers.append("same_asset")
            if alias.site_id != target.site_id:
                blockers.append("different_site")
            if alias.agent_id is not None or has_managed_history(alias):
                # Un registro con agente se resuelve con la reconciliación 5C.2 (mueve el
                # agente y deja linaje), nunca archivándolo como alias.
                blockers.append("alias_has_agent")
            if self._active_link(alias_asset_id=alias.id) is not None:
                blockers.append("alias_already_linked")
            if alias.id != target.id and alias.site_id == target.site_id:
                facts = self._facts([target, alias])
                pair = self._pair(facts[target.id], facts[alias.id], set())
                evidence = sorted(pair.items, key=lambda e: _RANK[e.strength])
            effects = ["map_mac_to_target"] if mac else []
            effects += ["archive_alias" if alias.archived_at is None else "alias_already_archived"]
            effects.append("keep_alias_history")
        else:
            if body.wlan_client_id is None or body.alias_asset_id is not None:
                raise IdentityLinkValidationError("wlan_client needs wlan_client_id only")
            client = self._client(body.wlan_client_id, lock=lock)
            mac = client.mac
            if client.site_id != target.site_id:
                blockers.append("different_site")
            if client.correlation_basis == "agent_self":
                # El propio agente del equipo informa de esta conexión: es la evidencia más
                # fuerte que existe y una asociación manual no la sustituye.
                blockers.append("client_confirmed_by_agent")
            if self._active_link(wlan_client_id=client.id) is not None:
                blockers.append("client_already_linked")
            effects = ["client_identity_manual"]
            if client.asset_id is not None and client.asset_id != target.id:
                effects.append("replaces_previous_correlation")
        preview = IdentityLinkPreview(
            kind=body.kind,
            target=self._ref(target),
            alias=self._ref(alias) if alias else None,
            wlan_client_id=client.public_id if client else None,
            mac=mac,
            allowed=not blockers,
            blockers=blockers,
            evidence=evidence,
            effects=effects,
        )
        return target, alias, client, preview

    def preview(self, body: IdentityLinkRequest) -> IdentityLinkPreview:
        return self._plan(body)[3]

    def create(self, body: IdentityLinkCreate, actor: Actor) -> IdentityLinkRead:
        session = self._session
        target, alias, client, preview = self._plan(body, lock=True)
        if not preview.allowed:
            raise IdentityLinkRefusedError(
                "The association is not allowed", details=[{"blockers": preview.blockers}]
            )
        now = datetime.now(UTC)
        reason = " ".join(body.reason.split())[:500]
        previous: dict[str, Any] = {}
        snapshot: dict[str, Any] = {"evidence": [e.model_dump() for e in preview.evidence]}
        if alias is not None:
            previous = {
                "archived_at": alias.archived_at.isoformat() if alias.archived_at else None,
                "archived_by": alias.archived_by,
                "archive_reason": alias.archive_reason,
            }
            snapshot["alias"] = {
                "display_name": alias.display_name,
                "primary_ip": alias.primary_ip,
                "mac_address": alias.mac_address,
            }
            if alias.archived_at is None:
                alias.archived_at = now
                alias.archived_by = actor.name[:64]
                alias.archive_reason = f"Asociado a {target.display_name}: {reason}"[:500]
                alias.lifecycle_version += 1
                # Marca exacta para que revocar solo desarchive lo que archivó la asociación.
                snapshot["archived_by_link_at"] = now.isoformat()
        elif client is not None:
            old = session.get(Asset, client.asset_id) if client.asset_id else None
            previous = {
                "asset_id": str(old.public_id) if old else None,
                "identity_confidence": client.identity_confidence,
                "correlation_basis": client.correlation_basis,
            }
            snapshot["client"] = {"mac": client.mac, "ssid": client.ssid, "bssid": client.bssid}
            client.asset_id = target.id
            client.identity_confidence = "confirmed"
            client.correlation_basis = "manual"
        link = AssetIdentityLink(
            site_id=target.site_id,
            kind=body.kind,
            target_asset_id=target.id,
            alias_asset_id=alias.id if alias else None,
            wlan_client_id=client.id if client else None,
            mac=preview.mac,
            reason=reason,
            evidence=snapshot,
            previous_state=previous,
            created_by=actor.name[:64],
            created_at=now,
        )
        session.add(link)
        session.flush()
        audit_service.record(
            session,
            actor,
            "identity_link_created",
            target_type="asset",
            target_id=target.public_id,
            details={
                "link": str(link.public_id),
                "kind": body.kind,
                "alias": str(alias.public_id) if alias else None,
                "wlan_client": str(client.public_id) if client else None,
                "mac": preview.mac,
                "reason": reason,
            },
            commit=False,
        )
        session.commit()
        return self._links(AssetIdentityLink.id == link.id)[0]

    def revoke(self, link_id: UUID, reason: str, actor: Actor) -> IdentityLinkRead:
        """Deshace la asociación: solo revierte lo que ella misma cambió."""
        session = self._session
        link = session.scalar(
            select(AssetIdentityLink)
            .where(AssetIdentityLink.public_id == link_id)
            .with_for_update()
        )
        if link is None:
            raise IdentityLinkNotFoundError("Identity association not found")
        if link.revoked_at is not None:
            raise IdentityLinkRefusedError("The association is already revoked")
        now = datetime.now(UTC)
        restored: list[str] = []
        if link.kind == "asset_alias" and link.alias_asset_id is not None:
            alias = session.scalar(
                select(Asset).where(Asset.id == link.alias_asset_id).with_for_update()
            )
            marker = link.evidence.get("archived_by_link_at")
            if (
                alias is not None
                and marker
                and alias.archived_at is not None
                and alias.archived_at.isoformat() == marker
            ):
                alias.archived_at = None
                alias.archived_by = None
                alias.archive_reason = None
                alias.lifecycle_version += 1
                restored.append("alias_restored")
        elif link.kind == "wlan_client" and link.wlan_client_id is not None:
            client = session.scalar(
                select(WlanClient).where(WlanClient.id == link.wlan_client_id).with_for_update()
            )
            if (
                client is not None
                and client.correlation_basis == "manual"
                and client.asset_id == link.target_asset_id
            ):
                previous = link.previous_state
                old_id = previous.get("asset_id")
                old = (
                    session.scalar(select(Asset).where(Asset.public_id == UUID(old_id)))
                    if old_id
                    else None
                )
                client.asset_id = old.id if old else None
                client.identity_confidence = (
                    previous.get("identity_confidence") or "observation_only"
                    if old
                    else "observation_only"
                )
                client.correlation_basis = previous.get("correlation_basis") if old else None
                restored.append("client_restored")
        link.revoked_at = now
        link.revoked_by = actor.name[:64]
        link.revoke_reason = " ".join(reason.split())[:500]
        audit_service.record(
            session,
            actor,
            "identity_link_revoked",
            target_type="identity_link",
            target_id=link.public_id,
            details={"reason": link.revoke_reason, "restored": restored},
            commit=False,
        )
        session.commit()
        return self._links(AssetIdentityLink.id == link.id)[0]


def alias_mac_targets(session: Session, site_id: int) -> dict[str, int]:
    """MAC asociada a mano -> id del activo destino, para el emparejamiento del discovery."""
    return {
        mac: target
        for mac, target in session.execute(
            select(AssetIdentityLink.mac, AssetIdentityLink.target_asset_id).where(
                AssetIdentityLink.site_id == site_id,
                AssetIdentityLink.kind == "asset_alias",
                AssetIdentityLink.revoked_at.is_(None),
                AssetIdentityLink.mac.is_not(None),
            )
        )
        if mac
    }

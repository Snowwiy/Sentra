"""Reglas puras de identidad de dispositivos (Fase 7B.2), sin consultas ni dependencias de
servicios: las usan la ficha (device_identity.py) y el listado de activos (asset_service.py),
así la tabla y la ficha nunca discrepan sobre si un equipo está identificado.
"""

from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.discovery import oui
from app.models.asset import Asset
from app.models.identity_link import AssetIdentityLink
from app.schemas.identity import IdentitySource, MacProfile

# --- MAC ------------------------------------------------------------------------------------


def mac_profile(mac: str | None, nic_vendor: str | None = None) -> MacProfile:
    """Qué dice una MAC de la identidad del equipo (sin consultar nada)."""
    digits = oui.mac_hex(mac)
    if digits is None:
        return MacProfile(
            mac=mac, kind="none", randomized=False, slap_quadrant=None, nic_vendor=None
        )
    first = int(digits[:2], 16)
    if first & 0x01:
        kind = "multicast"
    elif digits[:6] in oui.KNOWN_LOCAL_PREFIXES:
        kind = "virtual"
    elif first & 0x02:
        kind = "local"
    else:
        kind = "universal"
    quadrant = None
    if kind == "local":
        # IEEE 802c: los bits 0x08 (Y) y 0x04 (Z) del primer octeto dan el cuadrante SLAP.
        quadrant = {0x08: "eli", 0x0C: "sai", 0x00: "aai", 0x04: "reserved"}[first & 0x0C]
    return MacProfile(
        mac=mac,
        kind=kind,
        randomized=kind == "local",
        slap_quadrant=quadrant,
        nic_vendor=nic_vendor if kind == "universal" else None,
    )


def is_universal_mac(mac: str | None) -> bool:
    return mac_profile(mac).kind == "universal"


def identity_state(
    asset: Asset, mac: MacProfile, sources: Sequence[IdentitySource]
) -> tuple[str, list[str]]:
    """confirmed / probable / identity_unresolved y por qué."""
    if asset.is_managed:
        return "confirmed", ["agent_identity"]
    if mac.kind == "local":
        # Sin agente, una MAC privada no prueba nada: otro móvil puede usar la misma y este
        # cambiará la suya en otra red o al caducar.
        return "identity_unresolved", ["random_mac"]
    if mac.kind in ("none", "multicast"):
        return "identity_unresolved", ["no_stable_identifier"]
    reasons = ["virtual_mac" if mac.kind == "virtual" else "universal_mac"]
    if sources and all(s.freshness == "stale" for s in sources):
        reasons.append("stale_sources_only")
    return "probable", reasons


def linked_aliases(session: Session, asset_ids: Sequence[int]) -> set[int]:
    """Activos de la lista que un admin asoció como alias de otro (asociación activa)."""
    if not asset_ids:
        return set()
    return {
        int(row)
        for row in session.scalars(
            select(AssetIdentityLink.alias_asset_id).where(
                AssetIdentityLink.alias_asset_id.in_(list(asset_ids)),
                AssetIdentityLink.revoked_at.is_(None),
            )
        )
        if row is not None
    }

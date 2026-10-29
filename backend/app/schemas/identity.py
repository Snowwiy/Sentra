"""Contratos de identidad de dispositivos (Fase 7B.2, docs/device-identity-wifi.md)."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from app.schemas.common import RequestModel, ResponseModel

MacKind = Literal["universal", "local", "multicast", "virtual", "none"]
# Cuadrante SLAP (IEEE 802c) de una MAC local: AAI la asigna un administrador, ELI/SAI
# dependen de un protocolo y "reserved" queda libre. Las MACs privadas de
# Windows, Android, iOS y macOS caen en cualquiera: el cuadrante no las identifica.
SlapQuadrant = Literal["eli", "sai", "aai", "reserved"]
IdentityState = Literal["confirmed", "probable", "identity_unresolved"]
TierState = Literal["confirmed", "probable", "unresolved"]
Freshness = Literal["fresh", "stale", "unknown"]
Strength = Literal["strong", "medium", "weak"]
CandidateReason = Literal[
    "same_machine_id",
    "same_agent_lineage",
    "manual_link",
    "agent_reported_mac",
    "same_universal_mac",
    "mac_in_history",
    "same_device_name",
    "same_ip",
    "same_vendor",
    "same_os",
]
Classification = Literal[
    "same_agent_reinstalled",
    "historical_asset",
    "ip_reuse",
    "reconcilable_identity",
    "distinct_records",
]
RecommendedAction = Literal["reconcile", "link_alias", "none"]
LinkKind = Literal["asset_alias", "wlan_client"]
LinkBlocker = Literal[
    "same_asset",
    "different_site",
    "target_archived",
    "alias_has_agent",
    "alias_already_linked",
    "client_already_linked",
    "client_confirmed_by_agent",
]


class MacProfile(ResponseModel):
    mac: str | None
    kind: MacKind
    # True si la MAC no identifica a un equipo físico (bit localmente administrado).
    randomized: bool
    slap_quadrant: SlapQuadrant | None
    # Fabricante de la NIC según el OUI (solo para MACs universales).
    nic_vendor: str | None


class IdentitySource(ResponseModel):
    source: str
    value: str | None
    seen_at: datetime | None
    freshness: Freshness


class IdentityTier(ResponseModel):
    value: str | None
    source: str | None
    state: TierState
    reasons: list[str]
    alternatives: list[IdentitySource]


# Fase 7B-Fix1: qué falta para identificar el equipo y cómo conseguirlo.
IdentityGapField = Literal["name", "vendor", "model", "device_type", "os", "stable_identity"]


class IdentityGap(ResponseModel):
    field: IdentityGapField
    code: str
    detail: str


class AddressChange(ResponseModel):
    field: Literal["ip", "mac"]
    old_value: str | None
    new_value: str | None
    source: str
    observed_at: datetime


class IdentityLinkRead(ResponseModel):
    link_id: UUID
    kind: LinkKind
    target_asset_id: UUID
    target_name: str
    alias_asset_id: UUID | None
    alias_name: str | None
    wlan_client_id: UUID | None
    mac: str | None
    reason: str
    evidence: dict[str, object]
    active: bool
    created_by: str
    created_at: datetime
    revoked_by: str | None
    revoked_at: datetime | None
    revoke_reason: str | None


class AssetIdentityProfile(ResponseModel):
    asset_id: UUID
    display_name: str
    custom_label: str | None
    managed: bool
    archived: bool
    state: IdentityState
    reasons: list[str]
    mac: MacProfile
    name: IdentityTier
    vendor: IdentityTier
    device_type: IdentityTier
    os: IdentityTier
    # Fase 7B-Fix1: modelo, nombre asignado por un admin (manda sobre lo deducido) y lo que
    # falta. El fabricante de la NIC sigue en `mac.nic_vendor`, separado del de `vendor`.
    model: IdentityTier
    assigned_name: IdentityTier
    missing: list[IdentityGap]
    sources: list[IdentitySource]
    addresses: list[AddressChange]
    links: list[IdentityLinkRead]


class CandidateEvidence(ResponseModel):
    code: CandidateReason
    strength: Strength
    detail: str | None = None


class IdentityAssetRef(ResponseModel):
    asset_id: UUID
    display_name: str
    primary_ip: str
    mac_address: str | None
    managed: bool
    archived: bool
    last_seen_at: datetime | None


class IdentityCandidate(ResponseModel):
    asset: IdentityAssetRef
    strength: Strength
    evidence: list[CandidateEvidence]


class IdentityCandidateList(ResponseModel):
    items: list[IdentityCandidate]


class IdentityComparison(ResponseModel):
    left: IdentityAssetRef
    right: IdentityAssetRef
    classification: Classification
    recommended_action: RecommendedAction
    evidence: list[CandidateEvidence]
    conflicts: list[str]
    explanation: str
    # Bloqueos de una reconciliación 5C.2 (solo si la recomendación es reconciliar).
    reconcile_blockers: list[str]


class IdentityLinkRequest(RequestModel):
    kind: LinkKind
    target_asset_id: UUID
    alias_asset_id: UUID | None = None
    wlan_client_id: UUID | None = None
    # Opcional en la vista previa (no escribe nada); obligatorio al crear.
    reason: str | None = Field(default=None, min_length=3, max_length=500)


class IdentityLinkCreate(IdentityLinkRequest):
    reason: str = Field(min_length=3, max_length=500)
    # Se exige tras ver la vista previa: asociar archiva el alias o reasigna el cliente.
    confirm: Literal[True]


class IdentityLinkPreview(ResponseModel):
    kind: LinkKind
    target: IdentityAssetRef
    alias: IdentityAssetRef | None
    wlan_client_id: UUID | None
    mac: str | None
    allowed: bool
    blockers: list[LinkBlocker]
    evidence: list[CandidateEvidence]
    effects: list[str]


class IdentityLinkRevoke(RequestModel):
    reason: str = Field(min_length=3, max_length=500)


class IdentityLinkList(ResponseModel):
    items: list[IdentityLinkRead]

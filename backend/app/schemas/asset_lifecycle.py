"""Ciclo de vida de activos (Fase 5C.1): archivar, restaurar, borrar, duplicados, reconciliar.

Ninguna respuesta lleva la identidad de máquina: solo si coincide ("same_machine_id").
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from app.models.asset import MonitoringMethod
from app.schemas.agent_management import CredentialStatus
from app.schemas.asset import AssetRead
from app.schemas.common import RequestModel, ResponseModel

ARCHIVE_REASON_MAX = 500

DeleteBlockingReason = Literal[
    "managed_history",
    "agent_history",
    "detections",
    "incidents",
    "vulnerabilities",
    "threat_intel",
    "audit_dependency",
    "other",
]
DuplicateReason = Literal["same_machine_id", "same_hostname", "same_ip", "same_mac"]
DuplicateConfidence = Literal["high", "medium", "low"]
ReconcileBlocker = Literal[
    "same_asset",
    "source_without_agent",
    "source_archived",
    "target_never_managed",
    "target_agent_online",
    "platform_mismatch",
    "machine_id_mismatch",
    "insufficient_evidence",
]


class AssetArchiveRequest(RequestModel):
    reason: str = Field(min_length=3, max_length=ARCHIVE_REASON_MAX)
    # lifecycle_version que la UI tenía al abrir el diálogo (409 si ya no es la actual).
    version: int = Field(ge=0)


class AssetVersionRequest(RequestModel):
    version: int = Field(ge=0)


class AssetReconcileRequest(RequestModel):
    # Activo histórico al que pasa el agente de este activo.
    target_asset_id: UUID
    version: int = Field(ge=0)
    target_version: int = Field(ge=0)


class AssetDeleteCheck(ResponseModel):
    asset_id: UUID
    deletable: bool
    blocking_reasons: list[DeleteBlockingReason]
    # Recuento por dependencia que bloquea (p. ej. {"vulnerability_findings": 2}).
    dependencies: dict[str, int]
    # Lo que se borra junto al activo si se elimina: historial de red propio del activo
    # descubierto (puertos, cambios, detecciones de bajo impacto, alertas resueltas...).
    removes: dict[str, int]
    # Puede archivarse en su lugar (no archivado y sin agente con credencial activa).
    can_archive: bool
    version: int
    display_name: str
    hostname: str | None
    primary_ip: str
    mac_address: str | None
    monitoring_method: MonitoringMethod
    last_seen_at: datetime | None


class DuplicateAsset(ResponseModel):
    asset_id: UUID
    display_name: str
    hostname: str | None
    primary_ip: str
    mac_address: str | None
    os_name: str | None
    monitoring_method: MonitoringMethod
    agent_version: str | None
    credential_status: CredentialStatus | None
    archived: bool
    last_seen_at: datetime | None
    first_seen_at: datetime
    version: int


class DuplicateCandidate(ResponseModel):
    asset: DuplicateAsset
    reasons: list[DuplicateReason]
    confidence: DuplicateConfidence
    # Si este activo (el consultado) puede reconciliarse con el candidato como destino.
    reconcilable: bool
    reconcile_blockers: list[ReconcileBlocker]


class DuplicateCandidateList(ResponseModel):
    asset_id: UUID
    items: list[DuplicateCandidate]


class DuplicatePair(ResponseModel):
    # `asset` es el más reciente (normalmente el agente nuevo) y `candidate` el histórico.
    asset: DuplicateAsset
    candidate: DuplicateAsset
    reasons: list[DuplicateReason]
    confidence: DuplicateConfidence
    reconcilable: bool
    reconcile_blockers: list[ReconcileBlocker]


class DuplicatePairList(ResponseModel):
    items: list[DuplicatePair]


class AssetReconcileResult(ResponseModel):
    asset: AssetRead
    # Activo que quedó sin agente y archivado (el duplicado).
    archived_duplicate_id: UUID
    confidence: DuplicateConfidence
    reasons: list[DuplicateReason]

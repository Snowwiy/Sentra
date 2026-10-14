"""Ciclo de vida de activos (Fases 5C.1 y 5C.2): archivar, restaurar, borrar, limpieza,
duplicados y reconciliación.

Ninguna respuesta lleva la identidad de máquina: solo si coincide ("same_machine_id") o si
contradice ("machine_id_mismatch"). Tampoco tokens ni hashes de token.
"""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from app.models.asset import AssetStatus, MonitoringMethod
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
    # Fase 5C.2: motivos de la política de ciclo de vida (asset_lifecycle_policy.py).
    "not_stale",
    "purge_window_not_reached",
    "monitored_source",
]
LifecycleStateValue = Literal["active", "offline", "stale", "cleanup_candidate", "archived"]
LifecycleSourceValue = Literal["discovered", "monitored", "managed"]
CleanupActionValue = Literal[
    "keep", "mark_stale", "archive_candidate", "hard_delete_eligible", "blocked"
]
DuplicateReason = Literal[
    "same_machine_id",
    "same_agent_lineage",
    "same_hostname",
    "same_ip",
    "same_mac",
    "same_random_mac",
    "same_os",
]
DuplicateConfidence = Literal["high", "medium", "low"]
EvidenceStrength = Literal["strong", "medium", "weak"]
DuplicateConflict = Literal["machine_id_mismatch"]
# Bloqueos duros: impiden reconciliar en cualquier caso.
ReconcileBlocker = Literal[
    "same_asset",
    "source_without_agent",
    "source_archived",
    "target_never_managed",
    "target_agent_online",
    "platform_mismatch",
]
# Avisos: un admin puede reconciliar igualmente si los acepta de forma explícita
# (acknowledge_weak_evidence). Caso típico: reinstalación de Windows con MachineGuid nuevo.
ReconcileWarning = Literal["machine_id_mismatch", "insufficient_evidence"]
SourceDisposition = Literal["source_archived", "source_deleted"]


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
    # Fase 5C.2: confirmación explícita del admin cuando la evidencia es débil o
    # contradictoria (reconcile_warnings). Sin ella, 409 asset_reconcile_refused.
    acknowledge_weak_evidence: bool = False


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
    # Fase 5C.2: estado de ciclo de vida, scans perdidos y última actividad.
    lifecycle_state: LifecycleStateValue = "active"
    missed_discovery_scans: int = 0
    last_activity_at: datetime | None = None


class DuplicateEvidence(ResponseModel):
    code: DuplicateReason
    strength: EvidenceStrength


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
    # Fase 5C.2: cada señal con su fuerza, señales que contradicen y avisos aceptables.
    evidence: list[DuplicateEvidence] = Field(default_factory=list)
    conflicts: list[DuplicateConflict] = Field(default_factory=list)
    reconcile_warnings: list[ReconcileWarning] = Field(default_factory=list)
    # Reconciliable solo si un admin acepta los avisos de forma explícita.
    requires_acknowledgement: bool = False


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
    evidence: list[DuplicateEvidence] = Field(default_factory=list)
    conflicts: list[DuplicateConflict] = Field(default_factory=list)
    reconcile_warnings: list[ReconcileWarning] = Field(default_factory=list)
    requires_acknowledgement: bool = False


class DuplicatePairList(ResponseModel):
    items: list[DuplicatePair]


class AssetReconcileResult(ResponseModel):
    asset: AssetRead
    # Activo que quedó sin agente (el duplicado); archivado salvo source_deleted.
    archived_duplicate_id: UUID
    confidence: DuplicateConfidence
    reasons: list[DuplicateReason]
    # Fase 5C.2: qué pasó con cada parte, de forma explícita (nunca un borrado silencioso).
    source_asset_id: UUID
    target_asset_id: UUID
    agent_id: UUID
    # Agente que tenía el activo histórico: queda en su linaje, sin credencial.
    previous_target_agent_id: UUID | None
    source_disposition: SourceDisposition
    source_disposition_reasons: list[str]
    evidence: list[DuplicateEvidence]
    acknowledged_warnings: list[ReconcileWarning]


class ReconcilePreview(ResponseModel):
    """Impacto de reconciliar `source` (agente nuevo) con `target` (histórico). Solo lee."""

    source: DuplicateAsset
    target: DuplicateAsset
    confidence: DuplicateConfidence
    reasons: list[DuplicateReason]
    evidence: list[DuplicateEvidence]
    conflicts: list[DuplicateConflict]
    reconcilable: bool
    reconcile_blockers: list[ReconcileBlocker]
    reconcile_warnings: list[ReconcileWarning]
    requires_acknowledgement: bool
    # Recuentos (acotados) del historial que conserva cada parte. Nada se copia ni se borra:
    # el del source se queda en él, archivado; el del target sigue en el target.
    source_history: dict[str, int]
    target_history: dict[str, int]
    target_has_previous_agent: bool
    # Previsión con el mismo gate que se aplicará al ejecutar.
    source_disposition: SourceDisposition
    source_disposition_reasons: list[str]


# --- Limpieza (Fase 5C.2) ------------------------------------------------------------------


class CleanupPolicyRead(ResponseModel):
    discovered_stale_after_hours: int
    discovered_stale_missed_scans: int
    discovered_purge_after_days: int
    managed_stale_after_days: int
    auto_cleanup: bool
    batch_size: int


class CleanupCandidate(ResponseModel):
    asset_id: UUID
    display_name: str
    hostname: str | None
    primary_ip: str
    mac_address: str | None
    # SO del agente o, sin agente, el deducido desde la red.
    platform: str | None
    monitoring_method: MonitoringMethod
    lifecycle_source: LifecycleSourceValue
    lifecycle_state: LifecycleStateValue
    status: AssetStatus
    last_seen_at: datetime | None
    last_network_seen_at: datetime | None
    last_activity_at: datetime | None
    missed_successful_scans: int
    stale_for_hours: int | None
    action: CleanupActionValue
    hard_delete_eligible: bool
    blocking_reasons: list[str]
    dependencies: dict[str, int]
    version: int


class CleanupPreview(ResponseModel):
    generated_at: datetime
    policy: CleanupPolicyRead
    total: int
    limit: int
    offset: int
    # Reparto por acción de TODOS los candidatos (no solo de la página).
    counts: dict[str, int]
    items: list[CleanupCandidate]


class CleanupItem(RequestModel):
    asset_id: UUID
    version: int = Field(ge=0)


class CleanupRequest(RequestModel):
    action: Literal["hard_delete", "archive"]
    # El máximo real es ASSET_CLEANUP_BATCH_SIZE (lo comprueba la ruta); 500 es el techo.
    items: list[CleanupItem] = Field(min_length=1, max_length=500)
    reason: str | None = Field(default=None, min_length=3, max_length=ARCHIVE_REASON_MAX)


class CleanupItemResult(ResponseModel):
    asset_id: UUID
    outcome: Literal["deleted", "archived", "skipped"]
    reasons: list[str]
    display_name: str | None


class CleanupResult(ResponseModel):
    action: Literal["hard_delete", "archive"]
    requested: int
    succeeded: int
    skipped: int
    results: list[CleanupItemResult]

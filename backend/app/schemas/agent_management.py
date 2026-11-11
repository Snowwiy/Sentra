"""Agents as the dashboard manages them. Never carries a token, a hash or any secret."""

import enum
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from app.models.asset import AssetStatus, MonitoringMethod
from app.schemas.common import RequestModel, ResponseModel

AgentPlatform = Literal["windows", "linux", "macos", "other"]


class CredentialStatus(enum.StrEnum):
    """State of the agent's own credential (derived, never stored)."""

    # Holds a valid per-agent token.
    ACTIVE = "active"
    # Cut off by an operator: its calls get 401 and re-enrollment is refused (403).
    REVOKED = "revoked"
    # Not revoked, but without a valid token (reinstated, or token lost): it must enroll
    # again with a new one-time token.
    RE_ENROLLMENT_REQUIRED = "re_enrollment_required"


class AgentRead(ResponseModel):
    asset_id: UUID
    agent_id: UUID
    display_name: str
    hostname: str | None
    primary_ip: str
    os_name: str | None
    os_version: str | None
    architecture: str | None
    platform: AgentPlatform
    agent_version: str | None
    # Informado por el agente (p. ej. "windows_service"); null = no reportado.
    installation_method: str | None
    monitoring_method: MonitoringMethod
    # Liveness of the agent (unknown = enrolled, never reported yet).
    status: AssetStatus
    credential_status: CredentialStatus
    # First enrollment, and when the current credential was issued (last enrollment).
    enrolled_at: datetime
    credential_issued_at: datetime | None
    revoked_at: datetime | None
    last_seen_at: datetime | None
    # Fase 5C.1: estado del ACTIVO, separado del de la credencial (revocar no archiva).
    asset_state: Literal["active", "archived"] = "active"
    archived_at: datetime | None = None
    lifecycle_version: int = 0
    # Fase 5F: site del activo del agente.
    site_id: UUID
    site_name: str
    # Fase 7D.1 (H01): cómo se emitió la credencial vigente (enrollment_token, legacy_key,
    # recovery, rotation; null = anterior a 7D.1) y si hay una rotación a medio completar.
    credential_source: str | None = None
    rotation_pending: bool = False
    rotation_requested_at: datetime | None = None
    rotation_reason: str | None = None
    # Fase 7D.1 (H04): transporte del último heartbeat (https, http_loopback, http_remote) y
    # última vez que la credencial viajó en claro por la red (inventario de migración).
    transport: str | None = None
    transport_at: datetime | None = None
    insecure_transport_at: datetime | None = None
    # Fase 7D.2 (H06): último 429 por cuota de ingesta y rechazos acumulados (ventana de
    # un día como mucho: los cubos sin uso se purgan). Null/0 = no limitado.
    ingest_throttled_at: datetime | None = None
    ingest_rejections: int = 0


class AgentSummary(ResponseModel):
    total: int
    online: int
    offline: int
    # Enrolled but never reported (or waiting to re-enroll).
    pending: int
    revoked: int
    # Fase 5C.1: agentes cuyo activo está archivado. No cuentan en los demás totales.
    archived: int = 0
    # Fase 7D.1: agentes cuyo último heartbeat llegó por HTTP fuera de loopback, y con la
    # credencial emitida por la clave compartida legacy (candidatos a migrar).
    insecure_transport: int = 0
    legacy_key: int = 0
    # Fase 7D.2: agentes activos con un 429 de cuota en los últimos 15 minutos.
    throttled: int = 0


class AgentList(ResponseModel):
    summary: AgentSummary
    items: list[AgentRead]


class ConsoleInfo(ResponseModel):
    """What the dashboard needs to offer agent management (console available)."""

    # Lifetime of a new enrollment token when none is given.
    enrollment_token_ttl_minutes: int
    # AGENT_SERVER_URL if configured, else URLs built from this machine's addresses.
    suggested_server_urls: list[str]
    server_url_configured: bool


class AgentRecoveryCreate(RequestModel):
    """Fase 7D.1 (H01): autorización de recuperación de UN agente existente."""

    # Motivo obligatorio (queda en la auditoría): "reinstalación tras cambio de disco".
    reason: str = Field(min_length=10, max_length=500)
    # Confirmación explícita: la autorización sustituirá la credencial de este activo.
    confirm: Literal[True]
    ttl_minutes: int | None = Field(default=None, ge=1, le=60)
    # Restricción opcional: solo vale si el agente informa este hostname.
    expected_hostname: str | None = Field(default=None, min_length=1, max_length=255)


class AgentRecoveryRead(ResponseModel):
    recovery_id: UUID
    asset_id: UUID
    agent_id: UUID
    state: Literal["active", "consumed", "expired", "revoked"]
    reason: str
    created_by: str
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None
    revoked_at: datetime | None
    expected_hostname: str | None
    site_name: str | None


class AgentRecoveryCreated(AgentRecoveryRead):
    # Se devuelve una sola vez. El servidor solo guarda su SHA-256.
    token: str


class AgentRecoveryList(ResponseModel):
    items: list[AgentRecoveryRead]


class AgentRotationRequest(RequestModel):
    """Fase 7D.1: pedir al agente que rote su credencial en el próximo heartbeat."""

    # Opcional: rotar no cambia la identidad ni corta al agente, solo renueva su secreto.
    reason: str | None = Field(default=None, max_length=500)

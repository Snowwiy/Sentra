"""Contratos de la búsqueda global de la Analyst Console (Fase 7B.4)."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from app.schemas.common import ResponseModel

SearchKind = Literal["ip", "mac", "sha256", "rule", "case", "text"]


class SearchAsset(ResponseModel):
    asset_id: UUID
    display_name: str
    primary_ip: str
    mac_address: str | None
    archived: bool


class SearchDetection(ResponseModel):
    detection_id: UUID
    rule_id: str
    title: str
    status: str
    severity: str
    asset_id: UUID
    asset_name: str
    last_seen_at: datetime


class SearchIncident(ResponseModel):
    incident_id: UUID
    number: int
    title: str
    status: str
    severity: str


class SearchOperation(ResponseModel):
    operation_id: UUID
    title: str
    status: str
    asset_id: UUID
    asset_name: str
    artifact_path: str | None


class SearchUser(ResponseModel):
    # Solo lo necesario para asignar trabajo: nada de sesiones, inicios de sesión ni hashes.
    user_id: UUID
    username: str
    role: str
    active: bool
    open_cases: int


class SearchResult(ResponseModel):
    query: str
    # Cómo se interpretó el texto (la UI lo muestra para que no haya sorpresas).
    kind: SearchKind
    assets: list[SearchAsset]
    detections: list[SearchDetection]
    incidents: list[SearchIncident]
    operations: list[SearchOperation]
    # Usuarios de Sentra: solo con incidents:manage (quien puede asignar casos). Para el resto
    # la lista va vacía y `users_visible` es false, así la UI no sugiere que no hay coincidencias.
    users: list[SearchUser]
    users_visible: bool

"""Búsqueda global de la Analyst Console (Fase 7B.4, docs/analyst-console.md).

Un solo cuadro de búsqueda que entiende lo que el analista suele pegar: una IP, una MAC, un
SHA-256 (de un script o binario), un id de regla (SCR-001), el número de un caso o texto
libre. No es un lenguaje de consulta: el texto solo se compara (igualdad o LIKE escapado)
contra columnas conocidas, cada grupo tiene un tope y todo respeta el site pedido.
"""

import ipaddress
import re
from datetime import timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.passwords import normalize_username
from app.discovery.probes import normalize_mac
from app.models.asset import Asset
from app.models.attribution import MaintenanceArtifact, MaintenanceOperation
from app.models.detection import Detection
from app.models.incident import ACTIVE_STATUSES, Incident
from app.models.user import User
from app.schemas.console_search import (
    SearchAsset,
    SearchDetection,
    SearchIncident,
    SearchOperation,
    SearchResult,
    SearchUser,
)
from app.services.asset_lifecycle_policy import LifecyclePolicy
from app.services.asset_service import AssetFilter, AssetService

GROUP_LIMIT = 10
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_RULE = re.compile(r"^[A-Za-z]{2,6}-\d{3}$")
_CASE = re.compile(r"^(?:INC-|#)?(\d{1,9})$", re.IGNORECASE)


def _like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def classify_query(query: str) -> str:
    """ip / mac / sha256 / rule / case / text: decide qué columnas se consultan."""
    text = query.strip()
    try:
        ipaddress.ip_address(text)
        return "ip"
    except ValueError:
        pass
    if normalize_mac(text):
        return "mac"
    if _SHA256.match(text):
        return "sha256"
    if _RULE.match(text):
        return "rule"
    if _CASE.match(text):
        return "case"
    return "text"


class ConsoleSearch:
    def __init__(self, session: Session, heartbeat_timeout: timedelta) -> None:
        self._session = session
        self._timeout = heartbeat_timeout

    def _scoped(self, stmt: Any, site_id: int | None) -> Any:
        return stmt.where(Asset.site_id == site_id) if site_id is not None else stmt

    def search(
        self, query: str, site_id: int | None, *, include_users: bool = False
    ) -> SearchResult:
        text = " ".join(query.split())
        kind = classify_query(text)
        assets: list[SearchAsset] = []
        detections: list[SearchDetection] = []
        incidents: list[SearchIncident] = []
        operations: list[SearchOperation] = []
        if kind in ("ip", "mac", "text"):
            # Misma búsqueda que el inventario (etiqueta, nombre, DNS, IP, MAC).
            listed = AssetService(self._session, self._timeout, LifecyclePolicy()).list_assets(
                AssetFilter(
                    search=normalize_mac(text) or text, archived="include", site_id=site_id
                ),
                sort="name",
                limit=GROUP_LIMIT,
            )
            assets = [
                SearchAsset(
                    asset_id=a.asset_id,
                    display_name=a.display_name,
                    primary_ip=a.primary_ip,
                    mac_address=a.mac_address,
                    archived=a.archived_at is not None,
                )
                for a in listed.items
            ]
        if kind in ("sha256", "rule", "text"):
            detections = self._detections(text, kind, site_id)
        if kind == "sha256":
            operations = self._operations(text.lower(), site_id)
        if kind in ("case", "text"):
            incidents = self._incidents(text, kind)
        users: list[SearchUser] = []
        if include_users and kind == "text":
            users = self._users(text)
        return SearchResult(
            query=text,
            kind=kind,
            assets=assets,
            detections=detections,
            incidents=incidents,
            operations=operations,
            users=users,
            users_visible=include_users,
        )

    def _detections(self, text: str, kind: str, site_id: int | None) -> list[SearchDetection]:
        condition: Any
        if kind == "sha256":
            digest = text.lower()
            condition = or_(
                func.lower(Detection.details["script"]["script_sha256"].astext) == digest,
                Detection.details["scripts"].contains([{"script": {"script_sha256": digest}}]),
            )
        elif kind == "rule":
            condition = Detection.rule_id == text.upper()
        else:
            pattern = _like(text)
            condition = or_(
                Detection.title.ilike(pattern, escape="\\"),
                Detection.summary.ilike(pattern, escape="\\"),
            )
        stmt = (
            select(Detection, Asset)
            .join(Asset, Asset.id == Detection.asset_id)
            .where(condition)
            .order_by(Detection.last_seen_at.desc())
            .limit(GROUP_LIMIT)
        )
        return [
            SearchDetection(
                detection_id=d.public_id,
                rule_id=d.rule_id,
                title=d.title,
                status=d.status.value,
                severity=d.severity.value,
                asset_id=a.public_id,
                asset_name=a.display_name,
                last_seen_at=d.last_seen_at,
            )
            for d, a in self._session.execute(self._scoped(stmt, site_id)).all()
        ]

    def _incidents(self, text: str, kind: str) -> list[SearchIncident]:
        # Los casos no pertenecen a un site (pueden abarcar varios): se buscan siempre.
        if kind == "case":
            match = _CASE.match(text)
            condition: Any = Incident.number == int(match.group(1)) if match else None
        else:
            condition = Incident.title.ilike(_like(text), escape="\\")
        rows = self._session.scalars(
            select(Incident).where(condition).order_by(Incident.id.desc()).limit(GROUP_LIMIT)
        ).all()
        return [
            SearchIncident(
                incident_id=i.public_id,
                number=i.number,
                title=i.title,
                status=i.status.value if hasattr(i.status, "value") else str(i.status),
                severity=i.severity.value if hasattr(i.severity, "value") else str(i.severity),
            )
            for i in rows
        ]

    def _operations(self, digest: str, site_id: int | None) -> list[SearchOperation]:
        stmt = (
            select(MaintenanceOperation, MaintenanceArtifact, Asset)
            .join(MaintenanceArtifact, MaintenanceArtifact.operation_id == MaintenanceOperation.id)
            .join(Asset, Asset.id == MaintenanceOperation.asset_id)
            .where(MaintenanceArtifact.sha256 == digest)
            .order_by(MaintenanceOperation.created_at.desc())
            .limit(GROUP_LIMIT)
        )
        return [
            SearchOperation(
                operation_id=op.public_id,
                title=op.title,
                status=op.status,
                asset_id=asset.public_id,
                asset_name=asset.display_name,
                artifact_path=artifact.path,
            )
            for op, artifact, asset in self._session.execute(self._scoped(stmt, site_id)).all()
        ]

    def _users(self, text: str) -> list[SearchUser]:
        # Los nombres de usuario se guardan en forma canónica (minúsculas): se compara con la
        # misma forma. Los desactivados aparecen porque siguen siendo owners históricos.
        needle = normalize_username(text)
        open_cases = (
            select(func.count())
            .select_from(Incident)
            .where(Incident.owner_user_id == User.id, Incident.status.in_(ACTIVE_STATUSES))
            .correlate(User)
            .scalar_subquery()
        )
        rows = self._session.execute(
            select(User, open_cases)
            .where(User.username.ilike(_like(needle), escape="\\"))
            .order_by(User.is_active.desc(), User.username)
            .limit(GROUP_LIMIT)
        ).all()
        return [
            SearchUser(
                user_id=u.public_id,
                username=u.username,
                role=u.role,
                active=u.is_active,
                open_cases=int(count or 0),
            )
            for u, count in rows
        ]

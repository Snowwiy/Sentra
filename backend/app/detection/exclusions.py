"""Excepciones de reglas de detección (Fase 6E.5, docs/behavioral-detection.md).

Una excepción dice "esta regla no abre detección cuando el campo X de la señal vale Y" (en un
activo o en todos). Solo admin (rules:manage), siempre con motivo, auditada, caducable y
revocable: nunca se borra, para que se pueda explicar por qué no hubo detección.

Fase 7A.8: las reglas que más falsos positivos dieron con scripts y servicios propios
(SCR-001, CORR-002, NET-001) solo admiten excepciones exactas (RULE_POLICIES): con caducidad
obligatoria, por huella del script o por ejecutable en un puerto de un activo. Una excepción
por "powershell.exe" o por un intérprete ocultaría ataques reales y se rechaza en todas las
reglas.
"""

import uuid
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError, SentraError
from app.detection.behavior import SHELLS, basename
from app.detection.rules import RULE_IDS
from app.models.asset import Asset
from app.models.endpoint import DetectionExclusion
from app.schemas.detection_exclusion import (
    DetectionExclusionCreate,
    DetectionExclusionList,
    DetectionExclusionRead,
)
from app.services import audit_service
from app.services.audit_service import Actor

Exclusions = dict[str, list[DetectionExclusion]]
MAX_ACTIVE = 500


class ExclusionRuleError(SentraError):
    status_code = 422
    code = "exclusion_rule_unknown"


class ExclusionLimitError(ConflictError):
    code = "exclusion_limit"


class ExclusionTooBroadError(SentraError):
    """La excepción ocultaría más de lo que se ha revisado (422)."""

    status_code = 422
    code = "exclusion_too_broad"


@dataclass(frozen=True)
class RulePolicy:
    """Qué excepciones admite una regla con alto riesgo de ocultar ataques."""

    fields: frozenset[str]
    # Campos que solo valen junto con require_sha256 (la ruta sola se puede reutilizar).
    hash_required_for: frozenset[str] = frozenset()
    port_required: bool = False
    asset_required: bool = False
    # Caducidad obligatoria y como mucho este plazo: una excepción se revisa, no se olvida.
    max_days: int = 90


SCRIPT_FIELDS = frozenset({"script_path", "script_sha256"})
_SCRIPT_POLICY = RulePolicy(fields=SCRIPT_FIELDS, hash_required_for=frozenset({"script_path"}))
RULE_POLICIES: dict[str, RulePolicy] = {
    "SCR-001": _SCRIPT_POLICY,
    "CORR-002": _SCRIPT_POLICY,
    # Puerto expuesto: un ejecutable (o su hash) en un puerto de un activo, nunca "python".
    "NET-001": RulePolicy(
        fields=frozenset({"exe", "sha256"}), port_required=True, asset_required=True
    ),
}


_INTERPRETERS = SHELLS | {f"{shell}.exe" for shell in SHELLS}
# Ubicaciones del sistema: el intérprete de ahí es el que usa todo el equipo.
_SYSTEM_DIRS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\program files\\powershell\\",
    "/usr/bin/",
    "/usr/local/bin/",
    "/bin/",
)


def interpreter_wide(field: str, value: str) -> bool:
    """¿La excepción cubriría cualquier uso de un intérprete del sistema?

    Un nombre ("powershell.exe") o el ejecutable del sistema ocultan todo lo que se ejecute
    con él. Una copia en una ruta propia (C:\\Tools\\Deploy\\powershell.exe) sí se admite.
    """
    lowered = value.strip().lower()
    if field not in ("exe", "name") or basename(lowered) not in _INTERPRETERS:
        return False
    if field == "name" or ("\\" not in lowered and "/" not in lowered):
        return True
    return any(directory in lowered for directory in _SYSTEM_DIRS)


def check_policy(body: DetectionExclusionCreate, now: datetime) -> None:
    """Rechaza excepciones demasiado amplias (ExclusionTooBroadError) antes de crearlas."""
    if interpreter_wide(body.field, body.value):
        raise ExclusionTooBroadError(
            "A system interpreter (PowerShell, cmd, Python...) cannot be excluded as a whole"
        )
    policy = RULE_POLICIES.get(body.rule_id)
    if policy is None:
        if body.field in SCRIPT_FIELDS:
            raise ExclusionTooBroadError("Script fields only apply to PowerShell rules")
        if body.require_sha256 is not None or body.port is not None:
            raise ExclusionTooBroadError("This rule does not use require_sha256 or port")
        return
    if body.field not in policy.fields:
        allowed = ", ".join(sorted(policy.fields))
        raise ExclusionTooBroadError(f"{body.rule_id} exclusions must use: {allowed}")
    if body.field in policy.hash_required_for and body.require_sha256 is None:
        raise ExclusionTooBroadError(f"{body.field} exclusions require require_sha256")
    if body.field not in policy.hash_required_for and body.require_sha256 is not None:
        raise ExclusionTooBroadError("require_sha256 only applies to path exclusions")
    if policy.port_required and body.port is None:
        raise ExclusionTooBroadError(f"{body.rule_id} exclusions require a port")
    if not policy.port_required and body.port is not None:
        raise ExclusionTooBroadError(f"{body.rule_id} exclusions do not use a port")
    if policy.asset_required and body.asset_id is None:
        raise ExclusionTooBroadError(f"{body.rule_id} exclusions must name an asset")
    if body.expires_at is None or body.expires_at <= now:
        raise ExclusionTooBroadError(f"{body.rule_id} exclusions need a future expires_at")
    if body.expires_at > now + timedelta(days=policy.max_days):
        raise ExclusionTooBroadError(
            f"{body.rule_id} exclusions expire within {policy.max_days} days"
        )


def matches(exclusion: DetectionExclusion, asset_id: int, data: Mapping[str, Any]) -> bool:
    """¿La excepción cubre esta señal? Valor exacto y, si las tiene, huella y puerto."""
    if exclusion.asset_id is not None and exclusion.asset_id != asset_id:
        return False
    value = data.get(exclusion.field)
    if not isinstance(value, str) or value.strip().lower() != exclusion.value:
        return False
    if exclusion.require_sha256 is not None:
        key = "script_sha256" if exclusion.field in SCRIPT_FIELDS else "sha256"
        digest = data.get(key)
        if not isinstance(digest, str) or digest.strip().lower() != exclusion.require_sha256:
            return False
    return exclusion.port is None or data.get("port") == exclusion.port


def find_exclusion(
    exclusions: Exclusions, rule_id: str, asset_id: int, data: Mapping[str, Any]
) -> DetectionExclusion | None:
    for exclusion in exclusions.get(rule_id, ()):
        if matches(exclusion, asset_id, data):
            return exclusion
    return None


def load_exclusions(session: Session, now: datetime | None = None) -> Exclusions:
    """Excepciones vigentes agrupadas por regla (una consulta por lote del motor)."""
    now = now or datetime.now(UTC)
    rows = session.scalars(
        select(DetectionExclusion).where(
            DetectionExclusion.revoked_at.is_(None),
            or_(DetectionExclusion.expires_at.is_(None), DetectionExclusion.expires_at > now),
        )
    ).all()
    grouped: Exclusions = defaultdict(list)
    for row in rows:
        grouped[row.rule_id].append(row)
    return dict(grouped)


def _read(row: DetectionExclusion, asset: Asset | None) -> DetectionExclusionRead:
    now = datetime.now(UTC)
    active = row.revoked_at is None and (row.expires_at is None or row.expires_at > now)
    return DetectionExclusionRead(
        id=row.public_id,
        rule_id=row.rule_id,
        asset_id=asset.public_id if asset else None,
        asset_name=asset.display_name if asset else None,
        field=row.field,
        value=row.value,
        reason=row.reason,
        created_by=row.created_by,
        created_at=row.created_at,
        expires_at=row.expires_at,
        revoked_at=row.revoked_at,
        revoked_by=row.revoked_by,
        active=active,
        hits=row.hits,
        last_hit_at=row.last_hit_at,
        require_sha256=row.require_sha256,
        port=row.port,
    )


class ExclusionService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def list(self, include_inactive: bool) -> DetectionExclusionList:
        query = select(DetectionExclusion).order_by(DetectionExclusion.created_at.desc())
        if not include_inactive:
            query = query.where(DetectionExclusion.revoked_at.is_(None))
        rows = self._session.scalars(query.limit(MAX_ACTIVE)).all()
        assets = {
            a.id: a
            for a in self._session.scalars(
                select(Asset).where(Asset.id.in_({r.asset_id for r in rows if r.asset_id}))
            )
        }
        return DetectionExclusionList(
            items=[_read(r, assets.get(r.asset_id) if r.asset_id else None) for r in rows]
        )

    def create(self, body: DetectionExclusionCreate, actor: Actor) -> DetectionExclusionRead:
        session = self._session
        if body.rule_id not in RULE_IDS:
            # Solo reglas integradas: una regla personalizada se ajusta editando su condición.
            raise ExclusionRuleError("Unknown built-in rule")
        asset = None
        if body.asset_id is not None:
            asset = session.scalars(select(Asset).where(Asset.public_id == body.asset_id)).first()
            if asset is None:
                raise NotFoundError("Asset not found")
        now = datetime.now(UTC)
        check_policy(body, now)
        active = len(load_exclusions(session).get(body.rule_id, ()))
        if active >= MAX_ACTIVE:
            raise ExclusionLimitError("Too many active exclusions for this rule")
        row = DetectionExclusion(
            rule_id=body.rule_id,
            asset_id=asset.id if asset else None,
            field=body.field,
            value=body.value.strip().lower(),
            reason=body.reason,
            created_by=actor.name,
            created_at=now,
            expires_at=body.expires_at,
            require_sha256=body.require_sha256.lower() if body.require_sha256 else None,
            port=body.port,
        )
        session.add(row)
        session.flush()
        audit_service.record(
            session,
            actor,
            "detection_exclusion_created",
            target_type="detection_exclusion",
            target_id=row.public_id,
            details={
                "rule_id": body.rule_id,
                "field": body.field,
                "asset": str(body.asset_id) if body.asset_id else None,
                "expires_at": body.expires_at.isoformat() if body.expires_at else None,
                "require_sha256": row.require_sha256,
                "port": body.port,
            },
            commit=False,
        )
        read = _read(row, asset)
        session.commit()
        return read

    def revoke(self, public_id: uuid.UUID, actor: Actor) -> DetectionExclusionRead:
        session = self._session
        row = session.scalars(
            select(DetectionExclusion)
            .where(DetectionExclusion.public_id == public_id)
            .with_for_update()
        ).first()
        if row is None:
            raise NotFoundError("Exclusion not found")
        if row.revoked_at is None:
            row.revoked_at = datetime.now(UTC)
            row.revoked_by = actor.name
            audit_service.record(
                session,
                actor,
                "detection_exclusion_revoked",
                target_type="detection_exclusion",
                target_id=row.public_id,
                details={"rule_id": row.rule_id},
                commit=False,
            )
        asset = session.get(Asset, row.asset_id) if row.asset_id else None
        read = _read(row, asset)
        session.commit()
        return read

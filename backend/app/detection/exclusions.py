"""Excepciones de reglas de detección (Fase 6E.5, docs/behavioral-detection.md).

Una excepción dice "esta regla no abre detección cuando el campo X de la señal vale Y" (en un
activo o en todos). Solo admin (rules:manage), siempre con motivo, auditada, caducable y
revocable: nunca se borra, para que se pueda explicar por qué no hubo detección.
"""

import uuid
from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError, SentraError
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
        active = len(load_exclusions(session).get(body.rule_id, ()))
        if active >= MAX_ACTIVE:
            raise ExclusionLimitError("Too many active exclusions for this rule")
        now = datetime.now(UTC)
        row = DetectionExclusion(
            rule_id=body.rule_id,
            asset_id=asset.id if asset else None,
            field=body.field,
            value=body.value.strip().lower(),
            reason=body.reason,
            created_by=actor.name,
            created_at=now,
            expires_at=body.expires_at,
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

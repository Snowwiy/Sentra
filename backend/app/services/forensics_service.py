"""Investigación forense remota (Fase 6E.6, docs/forensic-investigation.md).

La recogida reutiliza el Response Engine de 5D: cada acción `forensic_*` es una ejecución de
Response ligada a una investigación (misma política, permisos, cola de comandos, reentrega y
auditoría). Este módulo añade lo que 5D no tenía:

- guardar la evidencia aparte del resultado acotado de la ejecución, como JSON canónico
  exacto, recalculando su SHA-256 y comparándolo con el que calculó el agente;
- casos (investigaciones), notas de interpretación separadas de la evidencia y paquetes ZIP
  con manifiesto y cadena de custodia sacada de la auditoría.

El servidor nunca "arregla" un artefacto: si el hash no coincide queda `mismatch`, se audita
como fallo y solo se puede empaquetar aceptando el aviso explícitamente.
"""

import hashlib
import io
import json
import logging
import re
import uuid
import zipfile
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import ConflictError, NotFoundError, SentraError
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.forensics import (
    EvidencePackage,
    ForensicArtifact,
    Investigation,
    InvestigationNote,
)
from app.models.incident import Incident
from app.models.response import AgentCommand, ResponseExecution
from app.response.results import clean_text
from app.schemas.forensics import (
    ArtifactDetail,
    ArtifactRead,
    CollectionRead,
    InvestigationCreate,
    InvestigationDetail,
    InvestigationList,
    InvestigationRead,
    NoteCreate,
    NoteRead,
    PackageRead,
)
from app.services import audit_service
from app.services.audit_service import Actor
from app.services.site_service import in_site

logger = logging.getLogger(__name__)

ARTIFACT_SCHEMA = "sentra-forensic/1"
PACKAGE_SCHEMA = "sentra-evidence-package/1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PLATFORMS = frozenset({"windows", "linux", "macos"})
MAX_LIMITATIONS = 50
CUSTODY_MAX = 2000


class InvestigationNotFoundError(NotFoundError):
    code = "investigation_not_found"


class InvestigationStateError(ConflictError):
    code = "investigation_closed"


class InvestigationVersionError(ConflictError):
    code = "investigation_version_conflict"


class EvidenceIntegrityError(ConflictError):
    code = "evidence_integrity_mismatch"


class EvidencePackageTooLargeError(SentraError):
    status_code = 413
    code = "evidence_package_too_large"


class EvidenceEmptyError(ConflictError):
    code = "evidence_empty"


def canonical(content: Any) -> bytes:
    """Mismo JSON canónico que el agente (docs/fase-6e-contracts.md)."""
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _limitations(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw[:MAX_LIMITATIONS]:
        if isinstance(item, dict):
            out.append(
                {
                    "code": clean_text(item.get("code") or "unknown", 64),
                    "detail": clean_text(item.get("detail") or "", 300),
                }
            )
    return out


class ArtifactRejectedError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def store_artifact(
    session: Session,
    settings: Settings,
    execution: ResponseExecution,
    command: AgentCommand,
    data: dict[str, Any],
    now: datetime,
) -> tuple[str, dict[str, Any]]:
    """Guarda la evidencia de una recogida forense y devuelve (resumen, referencia).

    La referencia sustituye a la evidencia en el resultado de la ejecución, que 5D sanea y
    recorta (un JSON recortado no sería evidencia). ArtifactRejectedError si el artefacto no
    cumple el contrato: la ejecución queda failed con ese código y no se guarda nada.
    """
    artifact = data.get("artifact")
    if not isinstance(artifact, dict):
        raise ArtifactRejectedError("artifact_missing", "The agent result has no artifact")
    if artifact.get("schema") != ARTIFACT_SCHEMA or artifact.get("kind") != command.command_type:
        raise ArtifactRejectedError("artifact_invalid", "Unexpected artifact schema or kind")
    content = artifact.get("content")
    if not isinstance(content, dict):
        raise ArtifactRejectedError("artifact_invalid", "Artifact content must be an object")
    agent_sha = artifact.get("sha256")
    if not isinstance(agent_sha, str) or not _SHA256.match(agent_sha):
        raise ArtifactRejectedError("artifact_invalid", "Artifact sha256 is missing or invalid")
    if execution.investigation_id is None:
        raise ArtifactRejectedError("investigation_missing", "The collection has no investigation")
    raw = canonical(content)
    if len(raw) > settings.forensics_artifact_max_kb * 1024:
        raise ArtifactRejectedError("artifact_too_large", "The artifact exceeds the size limit")
    digest = hashlib.sha256(raw).hexdigest()
    integrity = "verified" if digest == agent_sha else "mismatch"
    platform = artifact.get("platform")
    row = ForensicArtifact(
        investigation_id=execution.investigation_id,
        execution_id=execution.id,
        asset_id=execution.asset_id,
        agent_id=command.agent_id,
        operator=execution.actor,
        action=command.command_type,
        scope=dict(execution.parameters or {}),
        agent_sha256=agent_sha,
        sha256=digest,
        integrity=integrity,
        size_bytes=len(raw),
        content=raw.decode("utf-8"),
        truncated=artifact.get("truncated") is True,
        limitations=_limitations(data.get("limitations")),
        agent_version=clean_text(artifact.get("agent_version") or "", 32) or None,
        platform=platform if platform in _PLATFORMS else None,
        collected_at=_parse_time(artifact.get("collected_at")),
        received_at=now,
    )
    session.add(row)
    session.flush()
    investigation = session.get(Investigation, execution.investigation_id)
    if investigation is not None:
        investigation.updated_at = now
    audit_service.record(
        session,
        Actor(f"agent:{str(command.agent_id)[:8]}"),
        "forensic_artifact_received",
        audit_service.SUCCESS if integrity == "verified" else audit_service.FAILURE,
        target_type="forensic_artifact",
        target_id=row.public_id,
        details={
            "investigation": str(investigation.public_id) if investigation else None,
            "execution": str(execution.public_id),
            "action": command.command_type,
            "sha256": digest,
            "agent_sha256": agent_sha,
            "integrity": integrity,
            "size_bytes": len(raw),
        },
        commit=False,
    )
    if integrity == "mismatch":
        logger.warning(
            "forensic artifact hash mismatch",
            extra={"artifact": str(row.public_id), "action": command.command_type},
        )
    total = content.get("total")
    summary = f"Artefacto {command.command_type} guardado ({len(raw)} bytes"
    summary += f", {total} elementos)" if isinstance(total, int) else ")"
    if integrity == "mismatch":
        summary += "; el hash del agente NO coincide"
    reference = {
        "artifact_id": str(row.public_id),
        "sha256": digest,
        "integrity": integrity,
        "size_bytes": len(raw),
        "truncated": row.truncated,
        "limitations": row.limitations,
    }
    return summary, reference


def _artifact_read(row: ForensicArtifact, execution_public: uuid.UUID | None) -> ArtifactRead:
    return ArtifactRead(
        id=row.public_id,
        action=row.action,
        operator=row.operator,
        scope=row.scope or {},
        sha256=row.sha256,
        agent_sha256=row.agent_sha256,
        integrity=row.integrity,
        size_bytes=row.size_bytes,
        truncated=row.truncated,
        limitations=row.limitations or [],
        agent_version=row.agent_version,
        platform=row.platform,
        collected_at=row.collected_at,
        received_at=row.received_at,
        execution_id=execution_public,
    )


class ForensicsService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    # --- lectura -------------------------------------------------------------------------------

    def _get(self, public_id: uuid.UUID, lock: bool = False) -> Investigation:
        query = select(Investigation).where(Investigation.public_id == public_id)
        if lock:
            query = query.with_for_update()
        row = self._session.scalar(query)
        if row is None:
            raise InvestigationNotFoundError("Investigation not found")
        return row

    def _reads(self, rows: list[Investigation]) -> list[InvestigationRead]:
        ids = [r.id for r in rows]
        counts: dict[int, tuple[int, int]] = {}
        if ids:
            for inv_id, total, mismatched in self._session.execute(
                select(
                    ForensicArtifact.investigation_id,
                    func.count(),
                    func.sum(case((ForensicArtifact.integrity == "mismatch", 1), else_=0)),
                )
                .where(ForensicArtifact.investigation_id.in_(ids))
                .group_by(ForensicArtifact.investigation_id)
            ):
                counts[inv_id] = (int(total), int(mismatched or 0))
        incidents = {
            i.id: i.public_id
            for i in self._session.scalars(
                select(Incident).where(
                    Incident.id.in_({r.incident_id for r in rows if r.incident_id})
                )
            )
        }
        return [
            InvestigationRead(
                id=r.public_id,
                asset_id=r.asset_public_id,
                asset_label=r.asset_label,
                asset_exists=r.asset_id is not None,
                incident_id=incidents.get(r.incident_id) if r.incident_id else None,
                title=r.title,
                status=r.status,
                legal_hold=r.legal_hold,
                created_by=r.created_by,
                created_at=r.created_at,
                updated_at=r.updated_at,
                closed_at=r.closed_at,
                closed_by=r.closed_by,
                version=r.version,
                artifact_count=counts.get(r.id, (0, 0))[0],
                mismatch_count=counts.get(r.id, (0, 0))[1],
            )
            for r in rows
        ]

    def list_investigations(
        self,
        asset_public_id: uuid.UUID | None,
        status: str | None,
        site_id: int | None,
        limit: int,
        offset: int,
    ) -> InvestigationList:
        conditions: list[Any] = []
        if asset_public_id is not None:
            conditions.append(Investigation.asset_public_id == asset_public_id)
        if status is not None:
            conditions.append(Investigation.status == status)
        site = in_site(Investigation.asset_id, site_id)
        if site is not None:
            conditions.append(site)
        total = int(
            self._session.scalar(select(func.count()).select_from(Investigation).where(*conditions))
            or 0
        )
        rows = list(
            self._session.scalars(
                select(Investigation)
                .where(*conditions)
                .order_by(Investigation.created_at.desc(), Investigation.id.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        return InvestigationList(items=self._reads(rows), total=total)

    def detail(self, public_id: uuid.UUID) -> InvestigationDetail:
        row = self._get(public_id)
        session = self._session
        artifacts = list(
            session.scalars(
                select(ForensicArtifact)
                .where(ForensicArtifact.investigation_id == row.id)
                .order_by(ForensicArtifact.received_at.desc())
            )
        )
        executions = list(
            session.scalars(
                select(ResponseExecution)
                .where(ResponseExecution.investigation_id == row.id)
                .order_by(ResponseExecution.created_at.desc())
                .limit(200)
            )
        )
        by_id = {e.id: e.public_id for e in executions}
        missing = {
            a.execution_id for a in artifacts if a.execution_id and a.execution_id not in by_id
        }
        if missing:
            for execution_id, execution_public in session.execute(
                select(ResponseExecution.id, ResponseExecution.public_id).where(
                    ResponseExecution.id.in_(missing)
                )
            ):
                by_id[execution_id] = execution_public
        notes = session.scalars(
            select(InvestigationNote)
            .where(InvestigationNote.investigation_id == row.id)
            .order_by(InvestigationNote.created_at)
        )
        packages = session.scalars(
            select(EvidencePackage)
            .where(EvidencePackage.investigation_id == row.id)
            .order_by(EvidencePackage.created_at.desc())
        )
        return InvestigationDetail(
            investigation=self._reads([row])[0],
            artifacts=[
                _artifact_read(a, by_id.get(a.execution_id) if a.execution_id else None)
                for a in artifacts
            ],
            notes=[
                NoteRead(
                    id=n.public_id,
                    kind=n.kind,
                    body=n.body,
                    author=n.author,
                    created_at=n.created_at,
                )
                for n in notes
            ],
            collections=[
                CollectionRead(
                    execution_id=e.public_id,
                    action=e.action_id,
                    status=e.status,
                    actor=e.actor,
                    created_at=e.created_at,
                    finished_at=e.finished_at,
                    error_code=e.error_code,
                )
                for e in executions
            ],
            packages=[
                PackageRead(
                    id=p.public_id,
                    sha256=p.sha256,
                    size_bytes=p.size_bytes,
                    artifact_count=p.artifact_count,
                    includes_mismatch=p.includes_mismatch,
                    created_by=p.created_by,
                    created_at=p.created_at,
                )
                for p in packages
            ],
        )

    def artifact(self, public_id: uuid.UUID, artifact_id: uuid.UUID) -> ArtifactDetail:
        row = self._get(public_id)
        artifact = self._session.scalar(
            select(ForensicArtifact).where(
                ForensicArtifact.public_id == artifact_id,
                ForensicArtifact.investigation_id == row.id,
            )
        )
        if artifact is None:
            raise NotFoundError("Artifact not found")
        execution_public = (
            self._session.scalar(
                select(ResponseExecution.public_id).where(
                    ResponseExecution.id == artifact.execution_id
                )
            )
            if artifact.execution_id
            else None
        )
        base = _artifact_read(artifact, execution_public)
        return ArtifactDetail(
            **base.model_dump(),
            investigation_id=row.public_id,
            content=json.loads(artifact.content),
        )

    # --- cambios -------------------------------------------------------------------------------

    def _audit(
        self, actor: Actor, action: str, row: Investigation, details: dict[str, Any] | None = None
    ) -> None:
        audit_service.record(
            self._session,
            actor,
            action,
            target_type="investigation",
            target_id=row.public_id,
            details={"asset": str(row.asset_public_id), **(details or {})},
            commit=False,
        )

    def create(self, body: InvestigationCreate, actor: Actor) -> InvestigationRead:
        session = self._session
        asset = session.scalar(select(Asset).where(Asset.public_id == body.asset_id))
        if asset is None:
            raise NotFoundError("Asset not found")
        incident_id = None
        if body.incident_id is not None:
            incident = session.scalar(
                select(Incident).where(Incident.public_id == body.incident_id)
            )
            if incident is None:
                raise NotFoundError("Incident not found")
            incident_id = incident.id
        now = datetime.now(UTC)
        row = Investigation(
            asset_id=asset.id,
            asset_public_id=asset.public_id,
            asset_label=asset.display_name[:255],
            incident_id=incident_id,
            title=clean_text(body.title, 200),
            status="open",
            legal_hold=False,
            created_by=actor.name[:64],
            created_at=now,
            updated_at=now,
            version=1,
        )
        session.add(row)
        session.flush()
        self._audit(actor, "investigation_created", row)
        read = self._reads([row])[0]
        session.commit()
        return read

    def _check_version(self, row: Investigation, version: int) -> None:
        if row.version != version:
            raise InvestigationVersionError("The investigation changed; reload it")

    def set_status(
        self, public_id: uuid.UUID, status: str, version: int, actor: Actor
    ) -> InvestigationRead:
        row = self._get(public_id, lock=True)
        self._check_version(row, version)
        now = datetime.now(UTC)
        if row.status != status:
            row.status = status
            row.closed_at = now if status == "closed" else None
            row.closed_by = actor.name[:64] if status == "closed" else None
            row.updated_at = now
            row.version += 1
            self._audit(
                actor,
                "investigation_closed" if status == "closed" else "investigation_reopened",
                row,
            )
        read = self._reads([row])[0]
        self._session.commit()
        return read

    def set_legal_hold(
        self, public_id: uuid.UUID, legal_hold: bool, version: int, actor: Actor
    ) -> InvestigationRead:
        row = self._get(public_id, lock=True)
        self._check_version(row, version)
        if row.legal_hold != legal_hold:
            row.legal_hold = legal_hold
            row.updated_at = datetime.now(UTC)
            row.version += 1
            self._audit(actor, "investigation_legal_hold", row, {"legal_hold": legal_hold})
        read = self._reads([row])[0]
        self._session.commit()
        return read

    def add_note(self, public_id: uuid.UUID, body: NoteCreate, actor: Actor) -> NoteRead:
        row = self._get(public_id, lock=True)
        if row.status != "open":
            raise InvestigationStateError("The investigation is closed")
        now = datetime.now(UTC)
        note = InvestigationNote(
            investigation_id=row.id,
            kind=body.kind,
            body=clean_text(body.body, 8000),
            author=actor.name[:64],
            created_at=now,
        )
        self._session.add(note)
        row.updated_at = now
        self._session.flush()
        # Sin el texto: una nota puede llevar datos sensibles; la auditoría dice que existe.
        self._audit(actor, "investigation_note_added", row, {"kind": body.kind})
        out = NoteRead(
            id=note.public_id,
            kind=body.kind,
            body=note.body,
            author=note.author,
            created_at=note.created_at,
        )
        self._session.commit()
        return out

    # --- paquete de evidencia -----------------------------------------------------------------

    def _custody(
        self, row: Investigation, artifacts: list[ForensicArtifact]
    ) -> list[dict[str, Any]]:
        """Cadena de custodia: entradas de auditoría del caso, sus artefactos y recogidas."""
        artifact_ids = [str(a.public_id) for a in artifacts]
        execution_ids = [
            str(e)
            for e in self._session.scalars(
                select(ResponseExecution.public_id).where(
                    ResponseExecution.investigation_id == row.id
                )
            )
        ]
        conditions = [
            (AuditEvent.target_type == "investigation")
            & (AuditEvent.target_id == str(row.public_id))
        ]
        if artifact_ids:
            conditions.append(
                (AuditEvent.target_type == "forensic_artifact")
                & AuditEvent.target_id.in_(artifact_ids)
            )
        if execution_ids:
            conditions.append(AuditEvent.details["execution"].astext.in_(execution_ids))
        events = self._session.scalars(
            select(AuditEvent)
            .where(or_(*conditions))
            .order_by(AuditEvent.created_at, AuditEvent.id)
            .limit(CUSTODY_MAX)
        )
        return [
            {
                "at": e.created_at.isoformat(),
                "actor": e.actor,
                "action": e.action,
                "result": e.result,
                "target_type": e.target_type,
                "target_id": e.target_id,
                "details": e.details or {},
            }
            for e in events
        ]

    def package(
        self, public_id: uuid.UUID, acknowledge_mismatch: bool, actor: Actor
    ) -> tuple[bytes, str, str]:
        """ZIP de la investigación: (bytes, sha256, nombre de fichero). Registrado y auditado."""
        row = self._get(public_id)
        artifacts = list(
            self._session.scalars(
                select(ForensicArtifact)
                .where(ForensicArtifact.investigation_id == row.id)
                .order_by(ForensicArtifact.received_at, ForensicArtifact.id)
            )
        )
        if not artifacts:
            raise EvidenceEmptyError("The investigation has no artifacts yet")
        total = sum(a.size_bytes for a in artifacts)
        if total > self._settings.forensics_package_max_mb * 1024 * 1024:
            raise EvidencePackageTooLargeError("The evidence exceeds the package size limit")
        mismatched = [a for a in artifacts if a.integrity != "verified"]
        if mismatched and not acknowledge_mismatch:
            raise EvidenceIntegrityError(
                "Some artifacts failed integrity verification; acknowledge to package them",
                details=[{"artifact_id": str(a.public_id)} for a in mismatched],
            )
        now = datetime.now(UTC)
        notes = list(
            self._session.scalars(
                select(InvestigationNote)
                .where(InvestigationNote.investigation_id == row.id)
                .order_by(InvestigationNote.created_at)
            )
        )
        entries = []
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for artifact in artifacts:
                stamp = f"{artifact.received_at:%Y%m%dT%H%M%SZ}"
                name = f"evidence/{stamp}-{artifact.action}-{artifact.public_id}.json"
                data = artifact.content.encode("utf-8")
                # Se vuelve a comprobar al empaquetar: lo guardado es lo que se recibió.
                stored_ok = hashlib.sha256(data).hexdigest() == artifact.sha256
                archive.writestr(name, data)
                entries.append(
                    {
                        "id": str(artifact.public_id),
                        "file": name,
                        "action": artifact.action,
                        "scope": artifact.scope or {},
                        "operator": artifact.operator,
                        "sha256": artifact.sha256,
                        "agent_sha256": artifact.agent_sha256,
                        "integrity": artifact.integrity,
                        "stored_hash_verified": stored_ok,
                        "size_bytes": artifact.size_bytes,
                        "truncated": artifact.truncated,
                        "limitations": artifact.limitations or [],
                        "agent_version": artifact.agent_version,
                        "platform": artifact.platform,
                        "collected_at": artifact.collected_at.isoformat()
                        if artifact.collected_at
                        else None,
                        "received_at": artifact.received_at.isoformat(),
                    }
                )
            interpretations = [
                {
                    "kind": n.kind,
                    "author": n.author,
                    "created_at": n.created_at.isoformat(),
                    "body": n.body,
                }
                for n in notes
            ]
            archive.writestr(
                "interpretations/notes.json",
                json.dumps(
                    {
                        "notice": "Interpretaciones humanas o de IA. No son evidencia.",
                        "items": interpretations,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
            )
            manifest = {
                "schema": PACKAGE_SCHEMA,
                "generated_at": now.isoformat(),
                "generated_by": actor.name,
                "investigation": {
                    "id": str(row.public_id),
                    "title": row.title,
                    "status": row.status,
                    "legal_hold": row.legal_hold,
                    "asset_id": str(row.asset_public_id),
                    "asset_label": row.asset_label,
                    "created_by": row.created_by,
                    "created_at": row.created_at.isoformat(),
                },
                "hash_algorithm": "sha256 of canonical JSON (sort_keys, compact, UTF-8)",
                "includes_mismatch": bool(mismatched),
                "artifacts": entries,
                "chain_of_custody": self._custody(row, artifacts),
            }
            archive.writestr(
                "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2, default=str)
            )
        payload = buffer.getvalue()
        digest = hashlib.sha256(payload).hexdigest()
        package = EvidencePackage(
            investigation_id=row.id,
            sha256=digest,
            size_bytes=len(payload),
            artifact_count=len(artifacts),
            includes_mismatch=bool(mismatched),
            created_by=actor.name[:64],
            created_at=now,
        )
        self._session.add(package)
        self._session.flush()
        self._audit(
            actor,
            "evidence_package_downloaded",
            row,
            {
                "package": str(package.public_id),
                "sha256": digest,
                "artifacts": len(artifacts),
                "includes_mismatch": bool(mismatched),
            },
        )
        self._session.commit()
        filename = f"sentra-evidence-{row.public_id}-{now:%Y%m%dT%H%M%SZ}.zip"
        return payload, digest, filename

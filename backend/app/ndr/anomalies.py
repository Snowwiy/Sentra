"""Registro de anomalías NDR con deduplicación (Fase 7E.2).

Una anomalía activa (open o acknowledged) con la misma (site, regla, clave) absorbe las
nuevas ocurrencias: suma `occurrences`, extiende `last_seen`, sube veredicto y severidad si
la nueva evidencia es más fuerte (nunca los baja) y guarda la evidencia más reciente. Así
un envenenamiento ARP sostenido es UNA anomalía con su historia, no cientos.

Fase 7E.4: la anomalía se atribuye al activo inventariado del site (por la MAC del sujeto o,
sin MAC, por su IP) y, si tiene veredicto suspicious o superior, emite una señal NDR_ANOMALY
al motor de detección. "observed" nunca emite: es un hecho sin juicio (p. ej. telnet en uso o
un escaneo autorizado de Sentra) y no debe subir el riesgo ni abrir detecciones.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.signals import SignalKind, SourceType
from app.models.asset import Asset
from app.models.detection import DetectionSignal
from app.models.ndr import ACTIVE_ANOMALY_STATUSES, NdrAnomaly
from app.ndr.rules import SEVERITY_RANK, VERDICT_RANK, NdrRule, rules_by_id

MAX_EVIDENCE_ITEMS = 20
MAX_TEXT = 200
SIGNAL_MIN_RANK = VERDICT_RANK["suspicious"]
_RULES = rules_by_id()


@dataclass
class Finding:
    rule: NdrRule
    dedup_key: str
    verdict: str
    severity: str
    summary: str
    evidence: dict[str, Any]
    at: datetime
    subject_ip: str | None = None
    subject_mac: str | None = None


def _bounded(value: Any, depth: int = 0) -> Any:
    """Evidencia acotada: listas cortas, textos cortos, sin anidar sin límite."""
    if depth > 3:
        return None
    if isinstance(value, dict):
        return {str(k)[:64]: _bounded(v, depth + 1) for k, v in list(value.items())[:32]}
    if isinstance(value, list | tuple | set):
        return [_bounded(v, depth + 1) for v in list(value)[:MAX_EVIDENCE_ITEMS]]
    if isinstance(value, str):
        return value[:MAX_TEXT]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def record_finding(
    session: Session, site_id: int, sensor_id: int | None, finding: Finding
) -> NdrAnomaly:
    """Crea la anomalía o actualiza la activa. Devuelve la fila (para enriquecerla después)."""
    row = session.scalar(
        select(NdrAnomaly)
        .where(
            NdrAnomaly.site_id == site_id,
            NdrAnomaly.rule_id == finding.rule.id,
            NdrAnomaly.dedup_key == finding.dedup_key[:160],
            NdrAnomaly.status.in_(ACTIVE_ANOMALY_STATUSES),
        )
        .with_for_update()
    )
    evidence = _bounded(finding.evidence)
    if row is None:
        row = NdrAnomaly(
            site_id=site_id,
            sensor_id=sensor_id,
            rule_id=finding.rule.id,
            rule_version=finding.rule.version,
            category=finding.rule.category,
            verdict=finding.verdict,
            severity=finding.severity,
            status="open",
            dedup_key=finding.dedup_key[:160],
            subject_ip=finding.subject_ip,
            subject_mac=finding.subject_mac,
            title=finding.rule.title,
            summary=finding.summary[:1000],
            evidence=evidence,
            occurrences=1,
            first_seen=finding.at,
            last_seen=finding.at,
        )
        session.add(row)
        session.flush()
    else:
        row.occurrences += 1
        row.last_seen = max(row.last_seen, finding.at)
        row.sensor_id = sensor_id or row.sensor_id
        if VERDICT_RANK[finding.verdict] > VERDICT_RANK.get(row.verdict, 0):
            row.verdict = finding.verdict
            row.summary = finding.summary[:1000]
        if SEVERITY_RANK[finding.severity] > SEVERITY_RANK.get(row.severity, 0):
            row.severity = finding.severity
        row.evidence = evidence
    if row.asset_id is None:
        row.asset_id = resolve_asset(session, site_id, row.subject_ip, row.subject_mac)
    _signal(session, row, finding.at)
    return row


def resolve_asset(session: Session, site_id: int, ip: str | None, mac: str | None) -> int | None:
    """Activo no archivado del site con esa MAC o, si no hay MAC, con esa IP principal.

    La MAC manda cuando existe: en las reglas ARP el sujeto es quien anuncia (la MAC), y la IP
    puede ser ajena (la víctima). Nunca cruza sites: las IP privadas se repiten entre sites.
    Si varios activos comparten la IP (duplicados), gana el más reciente.
    """
    if mac:
        found = session.scalar(
            select(Asset.id)
            .where(
                Asset.site_id == site_id,
                Asset.mac_address == mac.lower(),
                Asset.archived_at.is_(None),
            )
            .order_by(Asset.id.desc())
            .limit(1)
        )
        return int(found) if found is not None else None
    if ip:
        found = session.scalar(
            select(Asset.id)
            .where(Asset.site_id == site_id, Asset.primary_ip == ip, Asset.archived_at.is_(None))
            .order_by(Asset.id.desc())
            .limit(1)
        )
        return int(found) if found is not None else None
    return None


def _mitre(rule_id: str) -> dict[str, str]:
    """Mapeo MITRE de la regla NDR (7E.5) para que la detección NET-NDR-001 lo herede."""
    rule = _RULES.get(rule_id)
    if rule is None or rule.mitre is None:
        return {}
    mapped = {"mitre_tactic": rule.mitre.tactic, "mitre_technique": rule.mitre.technique}
    if rule.mitre.subtechnique:
        mapped["mitre_subtechnique"] = rule.mitre.subtechnique
    return mapped


def _signal(session: Session, row: NdrAnomaly, at: datetime) -> None:
    """Señal al motor de detección la primera vez que la anomalía alcanza cada veredicto
    (suspicious, probable, confirmed). Mismo transacción que la ingesta: si el lote se
    revierte, la señal también."""
    rank = VERDICT_RANK.get(row.verdict, 0)
    if row.asset_id is None or rank < SIGNAL_MIN_RANK or rank <= row.signaled_rank:
        return
    session.add(
        DetectionSignal(
            asset_id=row.asset_id,
            kind=SignalKind.NDR_ANOMALY.value,
            subject=f"ndr:{row.public_id}",
            occurred_at=at,
            source_type=SourceType.NDR.value,
            source_id=str(row.public_id),
            data={
                "anomaly_id": str(row.public_id),
                "rule_id": row.rule_id,
                "rule_title": row.title,
                "category": row.category,
                "verdict": row.verdict,
                "severity": row.severity,
                "summary": row.summary[:500],
                "subject_ip": row.subject_ip,
                "subject_mac": row.subject_mac,
                **_mitre(row.rule_id),
            },
            created_at=datetime.now(UTC),
        )
    )
    row.signaled_rank = rank

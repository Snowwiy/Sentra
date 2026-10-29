"""Auditoría 7B.0 de solo lectura: riesgo, detecciones, eventos e identidad de un equipo.

La usa `python -m app.cli audit-7b`. Responde con datos, no con suposiciones, a las preguntas
de la auditoría (riesgo 99/100 de ravenslg, CORR-002, PER-001, puertos 8000/5432, eventos
4104/7045/4688, versión del agente, duplicado 192.168.50.66):

- la transacción se abre en READ ONLY: un error de programación no puede escribir nada;
- el veredicto de cada caso sale del mismo cálculo de atribución que usa el servidor
  (app/detection/attribution.py), sin guardarlo. Nunca concluye "legítimo" por un nombre:
  sin una operación aprobada cuya evidencia case, el caso queda suspicious_unverified o
  insufficient_evidence, con la evidencia que falta y cómo obtenerla;
- confirmed_malicious solo aparece si un analista lo declaró (el cálculo nunca lo concluye);
- no copia contenido de scripts ni mensajes completos: solo los campos estructurados que ya
  guarda el servidor (ruta, hash, PID, SID, servicio, ImagePath, cuenta).
"""

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from app.detection.attribution import ATTRIBUTABLE_RULES
from app.detection.signals import POWERSHELL, POWERSHELL_CORE, SECURITY, SYSTEM
from app.models.asset import Asset
from app.models.asset_lineage import AssetAgentLineage
from app.models.detection import Detection
from app.models.dhcp import AssetIdentityHistory
from app.models.endpoint import ProcessInstance
from app.models.event import SystemEvent
from app.models.exposure import AssetPort
from app.models.risk import AssetRisk, RiskSnapshot
from app.services.agent_management_service import credential_status
from app.services.attribution_service import compute
from app.services.device_identity import DeviceIdentityService

AUDIT_PORTS = (5432, 5433, 8000)
MAX_EVENTS = 400
MAX_DETECTIONS = 200
MAX_SNAPSHOTS = 30
_EVENT_FIELDS = (
    "Path",
    "ScriptSha256",
    "ScriptBlockId",
    "ProcessID",
    "UserID",
    "SuspiciousKeywords",
    "ServiceName",
    "ImagePath",
    "StartType",
    "AccountName",
    "NewProcessName",
    "ParentProcessName",
    "SubjectUserName",
)
_DETAIL_KEYS = ("script", "scripts", "service", "services", "port", "process", "account", "sentra")


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def find_assets(session: Session, refs: Sequence[str]) -> list[Asset]:
    """UUID público o hostname (sin distinguir mayúsculas). Un hostname puede dar varios."""
    found: list[Asset] = []
    for ref in refs:
        try:
            condition: Any = Asset.public_id == UUID(ref)
        except ValueError:
            condition = or_(
                func.lower(Asset.hostname) == ref.lower(),
                func.lower(Asset.device_name) == ref.lower(),
            )
        for asset in session.scalars(select(Asset).where(condition).order_by(Asset.id)):
            if asset not in found:
                found.append(asset)
    return found


def _case(verdict: str | None, analyst: bool) -> str:
    """Clasificación de la auditoría a partir del veredicto (nunca por el nombre)."""
    if verdict == "confirmed_malicious" and analyst:
        return "confirmed_malicious"
    if verdict in ("verified_benign", "suspicious_unverified", "insufficient_evidence"):
        return verdict
    return "insufficient_evidence"


def _detections(
    session: Session, asset: Asset, since: datetime, now: datetime
) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(Detection)
        .where(Detection.asset_id == asset.id, Detection.last_seen_at >= since)
        .order_by(Detection.first_seen_at, Detection.id)
        .limit(MAX_DETECTIONS)
    ).all()
    out: list[dict[str, Any]] = []
    for row in rows:
        details = row.details or {}
        item: dict[str, Any] = {
            "detection_id": str(row.public_id),
            "rule_id": row.rule_id,
            "rule_version": row.rule_version,
            "kind": row.kind.value if hasattr(row.kind, "value") else str(row.kind),
            "status": row.status.value if hasattr(row.status, "value") else str(row.status),
            "severity": row.severity.value if hasattr(row.severity, "value") else row.severity,
            "confidence": row.confidence.value
            if hasattr(row.confidence, "value")
            else row.confidence,
            "occurrences": row.occurrence_count,
            "dedup_key": row.dedup_key,
            "first_seen_at": _iso(row.first_seen_at),
            "last_seen_at": _iso(row.last_seen_at),
            "resolved_by": row.resolved_by,
            "alert": bool(row.alert_id),
            "summary": row.summary,
            "details": {k: details[k] for k in _DETAIL_KEYS if k in details},
            "stored_verdict": row.attribution_verdict,
        }
        if row.rule_id in ATTRIBUTABLE_RULES:
            result = compute(session, row, now)
            if result is not None:
                payload = result.to_json(now)
                item["computed_verdict"] = payload["verdict"]
                item["missing_evidence"] = payload["missing_evidence"]
                item["operation"] = payload["operation"]
                item["tamper_suspected"] = payload["tamper_suspected"]
        analyst = (row.attribution or {}).get("source") == "analyst"
        item["classification"] = _case(
            row.attribution_verdict or item.get("computed_verdict"), analyst
        )
        out.append(item)
    return out


def _events(session: Session, asset: Asset, since: datetime) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(SystemEvent)
        .where(
            SystemEvent.asset_id == asset.id,
            SystemEvent.occurred_at >= since,
            or_(
                (SystemEvent.channel.in_((POWERSHELL, POWERSHELL_CORE)))
                & (SystemEvent.event_code == 4104),
                (SystemEvent.channel == SYSTEM) & (SystemEvent.event_code == 7045),
                (SystemEvent.channel == SECURITY) & (SystemEvent.event_code == 4688),
            ),
        )
        .order_by(SystemEvent.occurred_at, SystemEvent.id)
        .limit(MAX_EVENTS)
    ).all()
    return [
        {
            "occurred_at": _iso(e.occurred_at),
            "channel": e.channel,
            "event_code": e.event_code,
            "level": e.level.value if hasattr(e.level, "value") else str(e.level),
            "record_id": e.record_id,
            # Sin ruta ni hash en un 4104: lo envió un agente anterior a 0.6.0.
            "agent_context": bool((e.data or {}).get("Path") or (e.data or {}).get("ScriptSha256"))
            if e.event_code == 4104
            else None,
            "data": {k: (e.data or {})[k] for k in _EVENT_FIELDS if k in (e.data or {})},
        }
        for e in rows
    ]


def _processes(
    session: Session, asset: Asset, pids: set[int], since: datetime
) -> list[dict[str, Any]]:
    if not pids:
        return []
    rows = session.scalars(
        select(ProcessInstance)
        .where(
            ProcessInstance.asset_id == asset.id,
            ProcessInstance.pid.in_(sorted(pids)),
            or_(ProcessInstance.ended_at.is_(None), ProcessInstance.ended_at >= since),
        )
        .order_by(ProcessInstance.started_at)
        .limit(100)
    ).all()
    parents = {
        p.instance_key: p
        for p in session.scalars(
            select(ProcessInstance).where(
                ProcessInstance.instance_key.in_(
                    [r.parent_instance_key for r in rows if r.parent_instance_key]
                )
            )
        )
    }
    out = []
    for row in rows:
        parent = parents.get(row.parent_instance_key or "")
        out.append(
            {
                "pid": row.pid,
                "name": row.name,
                "exe": row.exe,
                "cmdline": row.cmdline,
                "username": row.username,
                "signer": row.signer,
                "started_at": _iso(row.started_at),
                "parent": {"pid": parent.pid, "name": parent.name, "exe": parent.exe}
                if parent
                else None,
            }
        )
    return out


def _asset_report(
    session: Session, asset: Asset, since: datetime, now: datetime, timeout: timedelta
) -> dict[str, Any]:
    risk = session.get(AssetRisk, asset.id)
    snapshots = session.scalars(
        select(RiskSnapshot)
        .where(RiskSnapshot.asset_id == asset.id)
        .order_by(RiskSnapshot.calculated_at.desc())
        .limit(MAX_SNAPSHOTS)
    ).all()
    lineage = session.scalars(
        select(AssetAgentLineage).where(AssetAgentLineage.asset_id == asset.id)
    ).all()
    events = _events(session, asset, since)
    pids = {
        int(e["data"]["ProcessID"]) for e in events if str(e["data"].get("ProcessID", "")).isdigit()
    }
    detections = _detections(session, asset, since, now)
    ports = session.scalars(
        select(AssetPort).where(AssetPort.asset_id == asset.id, AssetPort.port.in_(AUDIT_PORTS))
    ).all()
    versions = session.scalars(
        select(AssetIdentityHistory)
        .where(AssetIdentityHistory.asset_id == asset.id)
        .order_by(AssetIdentityHistory.observed_at.desc())
        .limit(50)
    ).all()
    with_context = [e for e in events if e["event_code"] == 4104]
    timeline = sorted(
        [{"at": e["occurred_at"], "what": f"{e['channel']} {e['event_code']}"} for e in events]
        + [
            {"at": d["first_seen_at"], "what": f"{d['rule_id']} {d['status']} ({d['severity']})"}
            for d in detections
        ]
        + [{"at": _iso(s.calculated_at), "what": f"riesgo {s.score} {s.level}"} for s in snapshots],
        key=lambda x: x["at"] or "",
    )
    identity = DeviceIdentityService(session, timeout).profile(asset.public_id)
    return {
        "asset": {
            "asset_id": str(asset.public_id),
            "display_name": asset.display_name,
            "hostname": asset.hostname,
            "primary_ip": asset.primary_ip,
            "mac_address": asset.mac_address,
            "os": " ".join(x for x in (asset.os_name, asset.os_version) if x) or None,
            "agent_version_reported": asset.agent_version,
            "agent_installation_method": asset.agent_installation_method,
            "credential_status": credential_status(asset) if asset.agent_id else None,
            "machine_id_present": bool(asset.machine_id_hash),
            "ever_managed": asset.ever_managed,
            "archived": asset.archived_at is not None,
            "criticality": asset.criticality.value
            if hasattr(asset.criticality, "value")
            else str(asset.criticality),
            "lineage": [
                {
                    "agent_id": str(row.agent_id),
                    "ended_at": _iso(row.ended_at),
                    "end_reason": str(row.end_reason) if row.end_reason else None,
                }
                for row in lineage
            ],
        },
        "identity": identity.model_dump(mode="json"),
        "identity_history": [
            {
                "field": h.field,
                "old": h.old_value,
                "new": h.new_value,
                "source": h.source,
                "at": _iso(h.observed_at),
            }
            for h in versions
        ],
        "agent_context": {
            # El agente 0.6.0 adjunta ruta/hash a cada 4104; sin ellos el instalado es antiguo
            # aunque la .venv del repositorio tenga otra versión (el servicio usa su runtime).
            "events_4104": len(with_context),
            "events_4104_with_context": sum(1 for e in with_context if e["agent_context"]),
        },
        "risk": {
            "score": risk.score if risk else None,
            "level": str(risk.level.value) if risk and hasattr(risk.level, "value") else None,
            "confidence": str(risk.confidence.value)
            if risk and hasattr(risk.confidence, "value")
            else None,
            "formula_version": risk.formula_version if risk else None,
            "top_factor": risk.top_factor if risk else None,
            "contributions": (risk.contributions or [])[:20] if risk else [],
            "breakdown": risk.breakdown if risk else None,
            "history": [
                {"at": _iso(s.calculated_at), "score": s.score, "level": str(s.level)}
                for s in snapshots
            ],
        },
        "detections": detections,
        "events": events,
        "processes": _processes(session, asset, pids, since),
        "ports": [
            {
                "port": p.port,
                "protocol": p.protocol,
                "state": p.state.value if hasattr(p.state, "value") else str(p.state),
                "service_hint": p.service_hint,
                "opened_at": _iso(p.opened_at),
                "last_seen_at": _iso(p.last_seen_at),
                "closed_at": _iso(p.closed_at),
            }
            for p in ports
        ],
        "timeline": timeline,
    }


def _ip_report(session: Session, ip: str, timeout: timedelta) -> dict[str, Any]:
    """Registros con esa IP (actual o histórica) y la comparación de cada par."""
    historical = select(AssetIdentityHistory.asset_id).where(
        AssetIdentityHistory.field == "ip",
        or_(AssetIdentityHistory.old_value == ip, AssetIdentityHistory.new_value == ip),
    )
    assets = session.scalars(
        select(Asset)
        .where(or_(Asset.primary_ip == ip, Asset.id.in_(historical)))
        .order_by(Asset.id)
        .limit(20)
    ).all()
    service = DeviceIdentityService(session, timeout)
    pairs = []
    for i, left in enumerate(assets):
        for right in assets[i + 1 :]:
            pairs.append(service.compare(left.public_id, right.public_id).model_dump(mode="json"))
    return {
        "ip": ip,
        "records": [service.profile(a.public_id).model_dump(mode="json") for a in assets],
        "comparisons": pairs,
    }


def collect(
    session: Session,
    refs: Sequence[str],
    ip: str | None,
    days: int,
    timeout: timedelta,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Informe completo. Abre la transacción en READ ONLY antes de cualquier consulta."""
    session.execute(text("SET TRANSACTION READ ONLY"))
    now = now or datetime.now(UTC)
    since = now - timedelta(days=days)
    assets = find_assets(session, refs)
    report: dict[str, Any] = {
        "generated_at": now.isoformat(),
        "window_days": days,
        "read_only": True,
        "not_found": [
            r
            for r in refs
            if not any(r.lower() in {str(a.public_id), (a.hostname or "").lower()} for a in assets)
        ],
        "assets": [_asset_report(session, a, since, now, timeout) for a in assets],
    }
    if ip:
        report["ip_analysis"] = _ip_report(session, ip, timeout)
    session.rollback()
    return report


def summary_lines(report: dict[str, Any]) -> list[str]:
    """Resumen legible para la consola; el detalle va en el JSON."""
    lines = [f"Auditoría 7B.0 (solo lectura), ventana {report['window_days']} días"]
    for item in report["assets"]:
        asset, risk = item["asset"], item["risk"]
        lines.append(
            f"- {asset['display_name']} ({asset['primary_ip']}): riesgo {risk['score']}"
            f" v{risk['formula_version']}, agente {asset['agent_version_reported']},"
            f" 4104 con contexto {item['agent_context']['events_4104_with_context']}"
            f"/{item['agent_context']['events_4104']}"
        )
        for d in item["detections"]:
            lines.append(
                f"    {d['rule_id']} {d['status']} x{d['occurrences']} -> {d['classification']}"
            )
        for p in item["ports"]:
            lines.append(f"    puerto {p['port']}/{p['protocol']} {p['state']}")
    if "ip_analysis" in report:
        for pair in report["ip_analysis"]["comparisons"]:
            lines.append(
                f"- {report['ip_analysis']['ip']}: {pair['left']['display_name']} /"
                f" {pair['right']['display_name']} -> {pair['classification']}"
            )
    if report["not_found"]:
        lines.append(f"No encontrados: {', '.join(report['not_found'])}")
    return lines

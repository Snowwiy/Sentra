"""Plantillas versionadas de informes (Fase 5E): snapshot → Document.

Plantillas internas escritas en Python con bloques cerrados (app/reports/document.py): no
hay motor de plantillas, ni plantillas del usuario, ni eval/exec, ni acceso a nada fuera
del snapshot que reciben. Mismo snapshot → mismo documento → mismos bytes.

`TABLE_COLUMNS` define las columnas (y su orden) de cada tabla del snapshot. Lo usan las
tablas HTML/PDF, la exportación CSV y los CSV del paquete de evidencia.
"""

from collections.abc import Callable
from typing import Any

from app.reports.document import (
    Block,
    Bullets,
    Document,
    KeyValues,
    Notice,
    Paragraph,
    Section,
    bars,
    fmt,
    table,
)
from app.reports.summary import level_es

Columns = tuple[tuple[str, str], ...]

SEVERITY_LABELS = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
    "informational": "Info",
    "warning": "Aviso",
    "info": "Info",
}
LEVEL_LABELS = {
    k: level_es(k).capitalize() for k in ("critical", "high", "medium", "low", "informational")
}
STATUS_LABELS = {"online": "En línea", "offline": "Sin conexión", "unknown": "Desconocido"}
SOURCE_LABELS = {"managed": "Managed", "monitored": "Monitored", "discovered": "Discovered"}
CLASSIFICATION_LABELS = {
    "internal": "INTERNAL",
    "confidential": "CONFIDENTIAL",
    "restricted": "RESTRICTED",
}

TABLE_COLUMNS: dict[str, Columns] = {
    "assets": (
        ("name", "Activo"),
        ("id", "ID"),
        ("ip", "IP"),
        ("mac", "MAC"),
        ("platform", "Plataforma"),
        ("source", "Origen"),
        ("status", "Estado"),
        ("lifecycle_state", "Ciclo de vida"),
        ("criticality", "Criticidad"),
        ("risk_score", "Riesgo"),
        ("risk_level", "Nivel"),
        ("last_activity_at", "Última actividad"),
        ("archived", "Archivado"),
    ),
    "detections": (
        ("id", "ID"),
        ("rule_id", "Regla"),
        ("title", "Título"),
        ("severity", "Severidad"),
        ("confidence", "Confianza"),
        ("status", "Estado"),
        ("asset", "Activo"),
        ("first_seen_at", "Primera vez"),
        ("last_seen_at", "Última vez"),
        ("occurrences", "Ocurrencias"),
        ("incidents", "Incidentes"),
        ("risk_points", "Puntos riesgo"),
    ),
    "evidence": (
        ("detection_id", "Detección"),
        ("rule_id", "Regla"),
        ("occurred_at", "Momento"),
        ("kind", "Señal"),
        ("role", "Rol"),
        ("source_type", "Fuente"),
        ("source_id", "Ref. fuente"),
        ("summary", "Resumen"),
    ),
    "alerts": (
        ("id", "ID"),
        ("rule", "Regla"),
        ("severity", "Severidad"),
        ("status", "Estado"),
        ("asset", "Activo"),
        ("message", "Mensaje"),
        ("opened_at", "Abierta"),
        ("resolved_at", "Resuelta"),
    ),
    "vulnerabilities": (
        ("id", "ID"),
        ("vulnerability", "Vulnerabilidad"),
        ("cve", "CVE"),
        ("title", "Título"),
        ("severity", "Severidad"),
        ("match_state", "Evidencia"),
        ("status", "Estado"),
        ("component", "Componente"),
        ("installed_version", "Versión"),
        ("fixed_version", "Corregida en"),
        ("source", "Fuente"),
        ("asset", "Activo"),
        ("first_seen_at", "Primera vez"),
        ("inventory_observed_at", "Inventario"),
        ("resolved_at", "Resuelta"),
    ),
    "incidents": (
        ("number", "Número"),
        ("title", "Título"),
        ("severity", "Severidad"),
        ("priority", "Prioridad"),
        ("status", "Estado"),
        ("owner", "Asignado"),
        ("created_at", "Creado"),
        ("resolved_at", "Resuelto"),
    ),
    "changes": (
        ("asset", "Activo"),
        ("category", "Categoría"),
        ("kind", "Cambio"),
        ("item", "Elemento"),
        ("detected_at", "Detectado"),
    ),
    "executions": (
        ("id", "ID"),
        ("created_at", "Creada"),
        ("action", "Acción"),
        ("risk_level", "Riesgo"),
        ("status", "Estado"),
        ("target", "Objetivo"),
        ("actor", "Actor"),
        ("playbook", "Playbook"),
        ("incident", "Incidente"),
        ("confirmed", "Confirmada"),
        ("result_summary", "Resultado"),
        ("error_code", "Error"),
        ("error_message", "Motivo"),
        ("duration_seconds", "Duración (s)"),
    ),
    "playbook_runs": (
        ("id", "ID"),
        ("playbook", "Playbook"),
        ("version", "Versión"),
        ("status", "Estado"),
        ("target", "Objetivo"),
        ("actor", "Actor"),
        ("steps", "Pasos"),
        ("error_code", "Error"),
        ("created_at", "Creada"),
        ("finished_at", "Terminada"),
        ("duration_seconds", "Duración (s)"),
    ),
    "timeline": (
        ("at", "Momento"),
        ("action", "Acción"),
        ("actor", "Actor"),
        ("entity_type", "Entidad"),
        ("entity_id", "Ref."),
        ("summary", "Detalle"),
    ),
    "new_assets": (
        ("name", "Activo"),
        ("id", "ID"),
        ("ip", "IP"),
        ("mac", "MAC"),
        ("source", "Origen"),
        ("platform", "Plataforma"),
        ("discovery_network", "Red"),
        ("first_seen_at", "Primera vez"),
    ),
    "stale": (
        ("name", "Activo"),
        ("id", "ID"),
        ("source", "Origen"),
        ("state", "Estado"),
        ("last_activity_at", "Última actividad"),
        ("stale_for_hours", "Horas sin actividad"),
    ),
    "events": (
        ("at", "Momento"),
        ("action", "Acción"),
        ("actor", "Actor"),
        ("target_type", "Tipo"),
        ("target_id", "Objetivo"),
        ("details", "Detalles"),
    ),
    "duplicates": (
        ("asset", "Activo"),
        ("candidate", "Posible duplicado de"),
        ("confidence", "Confianza"),
        ("reasons", "Motivos"),
        ("reconcilable", "Reconciliable"),
    ),
    "reconciliations": (
        ("ended_at", "Momento"),
        ("asset", "Activo"),
        ("agent_id", "Agente"),
        ("agent_version", "Versión"),
        ("end_reason", "Motivo"),
        ("related_asset", "Relacionado"),
        ("actor", "Actor"),
        ("reconciliation_id", "Reconciliación"),
    ),
    "risk_changes": (
        ("at", "Momento"),
        ("asset", "Activo"),
        ("previous_level", "Nivel anterior"),
        ("level", "Nivel"),
        ("previous_score", "Score anterior"),
        ("score", "Score"),
        ("transition", "Cambio"),
        ("reason", "Motivo"),
        ("top_factor", "Factor principal"),
    ),
    "threat_matches": (
        ("observed_value", "Observado"),
        ("indicator_type", "Tipo"),
        ("classification", "Clasificación"),
        ("match_confidence", "Confianza"),
        ("source", "Fuente"),
        ("status", "Estado"),
        ("asset", "Activo"),
        ("first_observed_at", "Primera vez"),
        ("last_observed_at", "Última vez"),
    ),
}

_INCIDENT_ASSETS: Columns = (
    ("asset", "Activo"),
    ("asset_id", "ID"),
    ("source", "Origen"),
    ("added_at", "Añadido"),
)
_INCIDENT_DETECTIONS: Columns = (
    ("detection_id", "Detección"),
    ("rule_id", "Regla"),
    ("title", "Título"),
    ("severity", "Severidad"),
    ("source", "Origen"),
    ("attached_at", "Vinculada"),
)
_INCIDENT_ALERTS: Columns = (
    ("alert_id", "Alerta"),
    ("rule", "Regla"),
    ("severity", "Severidad"),
    ("message", "Mensaje"),
    ("attached_at", "Vinculada"),
)
_INCIDENT_VULNS: Columns = (
    ("vulnerability", "Vulnerabilidad"),
    ("title", "Título"),
    ("severity", "Severidad"),
    ("component", "Componente"),
    ("installed_version", "Versión"),
    ("asset", "Activo"),
    ("attached_at", "Vinculada"),
)
_INCIDENT_THREATS: Columns = (
    ("indicator", "Indicador"),
    ("indicator_type", "Tipo"),
    ("classification", "Clasificación"),
    ("confidence", "Confianza"),
    ("source", "Fuente"),
    ("observed", "Observado"),
    ("asset", "Activo"),
    ("attached_at", "Vinculada"),
)
_NOTES: Columns = (("created_at", "Momento"), ("author", "Autor"), ("body", "Nota"))
_TOP_RISK: Columns = (
    ("asset", "Activo"),
    ("score", "Score"),
    ("level", "Nivel"),
    ("confidence", "Confianza"),
    ("top_factor", "Factor principal"),
    ("calculated_at", "Calculado"),
)
_EXEC_TOP: Columns = (
    ("asset", "Activo"),
    ("score", "Score"),
    ("level", "Nivel"),
    ("top_factor", "Factor principal"),
)


def _t(name: str, data: dict[str, Any] | None, empty: str = "Sin datos.") -> Block:
    return table(TABLE_COLUMNS[name], data, empty)


def _meta(meta: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = [
        ("ID del informe", meta["report_id"]),
        ("Tipo", f"{meta['report_name']} ({meta['report_type']})"),
        ("Plantilla", f"v{meta['template_version']}"),
        ("Solicitado por", meta["requested_by"]),
        ("Solicitado", fmt(meta["requested_at"])),
        ("Generado", fmt(meta["generated_at"])),
        ("Datos a fecha de", fmt(meta["cutoff_at"])),
    ]
    if meta.get("time_from") or meta.get("time_to"):
        pairs.append(("Período", f"{fmt(meta.get('time_from'))} a {fmt(meta.get('time_to'))}"))
    pairs.append(("Zona horaria", meta["timezone"]))
    pairs.append(("Clasificación", CLASSIFICATION_LABELS.get(meta["classification"], "INTERNAL")))
    filters = meta.get("filters") or {}
    pairs.append(("Filtros", fmt(filters) if filters else "ninguno"))
    scope = meta.get("scope") or {}
    for key, label in (("assets", "Activos"), ("incidents", "Incidentes")):
        if scope.get(key):
            pairs.append((label, ", ".join(str(item.get("name")) for item in scope[key])))
    return tuple(pairs)


def _kv(pairs: list[tuple[str, Any]]) -> KeyValues:
    return KeyValues(tuple((label, fmt(value)) for label, value in pairs))


def _executive(snapshot: dict[str, Any]) -> list[Section]:
    d = snapshot["data"]
    a, r, i, det, v, resp, tr = (
        d["assets"], d["risk"], d["incidents"], d["detections"], d["vulnerabilities"],
        d["response"], d["trends"],
    )  # fmt: skip
    trend_unit = "día" if tr["unit"] == "day" else "semana"
    return [
        Section(
            "Estado general",
            (Bullets(tuple(snapshot["summary"])),),
        ),
        Section(
            "Activos monitorizados",
            (
                _kv(
                    [
                        ("Total", a["total"]),
                        (
                            "Managed / Monitored / Discovered",
                            " / ".join(
                                str(a["by_source"][k])
                                for k in ("managed", "monitored", "discovered")
                            ),
                        ),
                        (
                            "En línea / sin conexión / desconocido",
                            " / ".join(
                                str(a["by_status"][k]) for k in ("online", "offline", "unknown")
                            ),
                        ),
                        ("Stale", a["stale"]),
                    ]
                ),
                bars("Estado de los activos", a["by_status"], STATUS_LABELS),
            ),
        ),
        Section(
            "Riesgo",
            (
                bars("Activos por nivel de riesgo", r["by_level"], LEVEL_LABELS),
                Paragraph("Activos con mayor riesgo (Risk Engine):"),
                table(
                    _EXEC_TOP,
                    {"rows": r["top_assets"], "total": len(r["top_assets"])},
                    "Sin activos puntuados.",
                ),
            ),
        ),
        Section(
            "Incidentes",
            (
                _kv(
                    [
                        ("Abiertos a la hora de corte", i["open_now"]),
                        ("Abiertos en el período", i["opened"]),
                        ("Resueltos en el período", i["resolved"]),
                    ]
                ),
                bars("Incidentes activos por severidad", i["active_by_severity"], SEVERITY_LABELS),
            ),
        ),
        Section(
            "Detecciones",
            (bars("Detecciones del período por severidad", det["by_severity"], SEVERITY_LABELS),),
        ),
        Section(
            "Vulnerabilidades",
            (
                bars("Confirmadas por severidad", v["confirmed"], SEVERITY_LABELS),
                bars("Probables por severidad", v["probable"], SEVERITY_LABELS),
                _kv(
                    [
                        ("Potenciales (sin confirmar)", v["potential_total"]),
                        ("Resueltas en el período", v["resolved_in_period"]),
                        ("Activos afectados (confirmadas o probables)", v["assets_affected"]),
                    ]
                ),
            ),
        ),
        Section("Response", (bars("Ejecuciones por estado", resp["by_status"]),)),
        Section(
            "Tendencias",
            (
                bars(
                    f"Detecciones nuevas por {trend_unit}",
                    {fmt(p["bucket"])[:10]: p["count"] for p in tr["detections"]},
                ),
                bars(
                    f"Incidentes creados por {trend_unit}",
                    {fmt(p["bucket"])[:10]: p["count"] for p in tr["incidents"]},
                ),
            ),
        ),
        Section(
            "Hallazgos prioritarios",
            (Bullets(tuple(d["findings"])),)
            if d["findings"]
            else (Paragraph("Sin hallazgos prioritarios."),),
        ),
    ]


def _technical(snapshot: dict[str, Any]) -> list[Section]:
    d, t = snapshot["data"], snapshot["tables"]
    risk = d["risk"]
    vulns = d["vulnerabilities"]
    return [
        Section("Resumen", (Bullets(tuple(snapshot["summary"])),)),
        Section(
            "Inventario de activos",
            (
                bars("Estado", d["assets"]["by_status"], STATUS_LABELS),
                bars("Origen", d["assets"]["by_source"], SOURCE_LABELS),
                _t("assets", t["assets"]),
            ),
        ),
        Section(
            "Ciclo de vida",
            (
                _kv(
                    [
                        ("Stale", d["lifecycle"]["stale"]),
                        ("Candidatos a limpieza", d["lifecycle"]["cleanup_candidates"]),
                        ("Archivados en el alcance", d["lifecycle"]["archived"]),
                    ]
                ),
            ),
        ),
        Section(
            "Riesgo",
            (
                bars("Activos por nivel", risk["by_level"], LEVEL_LABELS),
                table(_TOP_RISK, {"rows": risk["top_assets"], "total": len(risk["top_assets"])}),
                table(
                    TABLE_COLUMNS["risk_changes"],
                    risk["changes"],
                    "Sin cambios de nivel en el período.",
                ),
            ),
        ),
        Section(
            "Detecciones",
            (
                bars("Por severidad", d["detections"]["by_severity"], SEVERITY_LABELS),
                _t("detections", t["detections"]),
            ),
        ),
        Section(
            "Alertas",
            (
                bars("Por severidad", d["alerts"]["by_severity"], SEVERITY_LABELS),
                _t("alerts", t["alerts"]),
            ),
        ),
        Section(
            "Vulnerabilidades",
            (
                Notice(
                    "Confirmadas, probables y potenciales se listan por separado:"
                    " una potencial no está confirmada."
                ),
                Paragraph("Confirmadas:"),
                _t("vulnerabilities", vulns["confirmed"]["table"]),
                Paragraph("Probables:"),
                _t("vulnerabilities", vulns["probable"]["table"]),
                Paragraph("Potenciales (sin confirmar):"),
                _t("vulnerabilities", vulns["potential"]["table"]),
            ),
        ),
        Section(
            "Threat intelligence",
            (
                table(
                    TABLE_COLUMNS["threat_matches"],
                    d["threats"]["table"],
                    "Sin coincidencias en el período.",
                ),
            ),
        ),
        Section("Incidentes", (_t("incidents", t["incidents"]),)),
        Section(
            "Actividad de Response",
            (_t("executions", d["response"]["executions"], "Sin ejecuciones en el período."),),
        ),
        Section(
            "Cambios de discovery", (_t("changes", t["changes"], "Sin cambios en el período."),)
        ),
    ]


def _incident(snapshot: dict[str, Any]) -> list[Section]:
    d = snapshot["data"]
    c = d["case"]
    return [
        Section(
            "Incidente",
            (
                _kv(
                    [
                        ("Número", c["number"]),
                        ("Título", c["title"]),
                        ("Estado", c["status"]),
                        ("Severidad", c["severity"]),
                        ("Prioridad", c["priority"]),
                        ("Confianza", c["confidence"]),
                        ("Asignado a", c["owner"]),
                        ("Creado por", c["created_by"]),
                        ("Creado", c["created_at"]),
                        ("Primera actividad", c["first_seen_at"]),
                        ("Última actividad", c["last_seen_at"]),
                        ("Triage", c["triaged_at"]),
                        ("Resuelto", c["resolved_at"]),
                        ("Resuelto por", c["resolved_by"]),
                        ("Cerrado", c["closed_at"]),
                        ("Categoría de resolución", c["resolution_category"]),
                        ("Resumen de resolución", c["resolution_summary"]),
                        ("Fusionado en", c["merged_into"]),
                        (
                            "Riesgo al crear",
                            f"{fmt(c['risk_score_snapshot'])} ({fmt(c['risk_level_snapshot'])})",
                        ),
                    ]
                ),
                Paragraph(c["description"] or "Sin descripción."),
                Bullets(tuple(snapshot["summary"])),
            ),
        ),
        Section("Activos", (table(_INCIDENT_ASSETS, d["assets"]),)),
        Section("Detecciones", (table(_INCIDENT_DETECTIONS, d["detections"]),)),
        Section("Alertas", (table(_INCIDENT_ALERTS, d["alerts"]),)),
        Section("Vulnerabilidades", (table(_INCIDENT_VULNS, d["vulnerabilities"]),)),
        Section("Threat intelligence", (table(_INCIDENT_THREATS, d["threat_matches"]),)),
        Section("Notas", (table(_NOTES, d["notes"], "Sin notas."),)),
        Section(
            "Línea de tiempo",
            (Paragraph("Orden cronológico (UTC)."), _t("timeline", d["timeline"])),
        ),
        Section(
            "Response y playbooks",
            (
                _t("executions", d["executions"], "Sin ejecuciones de Response."),
                _t("playbook_runs", d["playbook_runs"], "Sin playbooks ejecutados."),
            ),
        ),
        Section(
            "Referencias de evidencia",
            (
                table(
                    (("type", "Tipo"), ("id", "ID")),
                    {"rows": d["evidence_refs"], "total": len(d["evidence_refs"])},
                    "Sin referencias.",
                ),
            ),
        ),
    ]


def _asset(snapshot: dict[str, Any]) -> list[Section]:
    d, t = snapshot["data"], snapshot["tables"]
    ident, agent, inv, risk = d["identity"], d["agent"], d["inventory"], d["risk"]
    blocks_agent: list[Block] = [
        _kv(
            [
                ("Origen", SOURCE_LABELS.get(ident["source"], ident["source"])),
                ("Estado", STATUS_LABELS.get(ident["status"], ident["status"])),
                ("Ciclo de vida", ident["lifecycle_state"]),
                ("Última actividad", ident["last_activity_at"]),
                ("Archivado", ident["archived_at"]),
                ("Archivado por", ident["archived_by"]),
                ("Motivo de archivo", ident["archive_reason"]),
                ("Agente actual", agent["agent_id"]),
                ("Versión del agente", agent["agent_version"]),
                ("Instalación", agent["installation_method"]),
                ("Credencial del agente", agent["credential_state"]),
                ("Capacidades", agent["capabilities"]),
            ]
        ),
        table(
            (
                ("ended_at", "Fin"),
                ("agent_id", "Agente anterior"),
                ("agent_version", "Versión"),
                ("end_reason", "Motivo"),
                ("actor", "Actor"),
            ),
            {"rows": agent["lineage"], "total": len(agent["lineage"])},
            "Sin agentes anteriores (linaje vacío).",
        ),
    ]
    return [
        Section(
            "Identidad",
            (
                _kv(
                    [
                        ("Nombre", ident["name"]),
                        ("ID", ident["id"]),
                        ("Hostname", ident["hostname"]),
                        ("Nombre de dispositivo", ident["device_name"]),
                        ("DNS inverso", ident["reverse_dns"]),
                        ("IP", ident["ip"]),
                        ("MAC", ident["mac"]),
                        ("Fabricante", ident["vendor"]),
                        ("Modelo", ident["model"]),
                        ("Tipo", ident["device_type"]),
                        ("Plataforma", ident["platform"]),
                        ("Versión SO", ident["os_version"]),
                        ("Arquitectura", ident["architecture"]),
                        ("Criticidad", ident["criticality"]),
                        ("Primera vez", ident["first_seen_at"]),
                    ]
                ),
                Bullets(tuple(snapshot["summary"])),
            ),
        ),
        Section("Ciclo de vida y agente", tuple(blocks_agent)),
        Section(
            "Inventario",
            (
                _kv(
                    [
                        ("Recogido", inv["collected_at"]),
                        ("Software", inv["software"]),
                        ("Servicios", inv["services"]),
                        ("Cuentas locales", inv["accounts"]),
                        ("Interfaces", inv["interfaces"]),
                        ("Discos", inv["disks"]),
                        ("Origen del software", inv["software_source"]),
                    ]
                )
                if inv
                else Paragraph("Sin inventario del agente."),
            ),
        ),
        Section(
            "Riesgo",
            (
                _kv(
                    [
                        ("Score", risk["score"]),
                        ("Nivel", risk["level"]),
                        ("Confianza", risk["confidence"]),
                        ("Calculado", risk["calculated_at"]),
                        ("Factor principal", risk["top_factor"]),
                    ]
                ),
                table(
                    (
                        ("category", "Categoría"),
                        ("label", "Contribución"),
                        ("points", "Puntos"),
                        ("rule_id", "Regla"),
                    ),
                    {"rows": risk["contributions"], "total": len(risk["contributions"])},
                    "Sin contribuciones.",
                ),
                table(
                    (
                        ("at", "Momento"),
                        ("score", "Score"),
                        ("level", "Nivel"),
                        ("transition", "Cambio"),
                        ("reason", "Motivo"),
                    ),
                    {"rows": risk["history"], "total": len(risk["history"])},
                    "Sin snapshots de riesgo en el período.",
                ),
            ),
        ),
        Section(
            "Detecciones", (_t("detections", t["detections"], "Sin detecciones en el período."),)
        ),
        Section(
            "Vulnerabilidades",
            (
                Notice(
                    "La columna Evidencia distingue confirmed, probable y potential:"
                    " una potencial no está confirmada."
                ),
                _t("vulnerabilities", t["vulnerabilities"], "Sin findings activos."),
            ),
        ),
        Section("Incidentes", (_t("incidents", d["incidents"], "Sin incidentes."),)),
        Section(
            "Threat intelligence",
            (table(TABLE_COLUMNS["threat_matches"], d["threats"]["table"], "Sin coincidencias."),),
        ),
        Section("Response", (_t("executions", t["executions"], "Sin ejecuciones en el período."),)),
        Section(
            "Cambios importantes", (_t("changes", t["changes"], "Sin cambios en el período."),)
        ),
        Section(
            "Evidencia de discovery",
            (
                _kv(
                    [
                        ("Fuentes", d["discovery"]["sources"]),
                        ("Red", d["discovery"]["network"]),
                        ("Descubierto", d["discovery"]["discovered_at"]),
                        ("Visto en red", d["discovery"]["last_network_seen_at"]),
                        ("Estado de red", d["discovery"]["network_status"]),
                        ("Confianza de clasificación", d["discovery"]["classification_confidence"]),
                        ("Evidencia de clasificación", d["discovery"]["classification_evidence"]),
                    ]
                ),
            ),
        ),
    ]


def _vulnerability(snapshot: dict[str, Any]) -> list[Section]:
    d = snapshot["data"]
    return [
        Section(
            "Resumen",
            (
                Bullets(tuple(snapshot["summary"])),
                bars("Confirmadas por severidad", d["confirmed"]["by_severity"], SEVERITY_LABELS),
                bars("Probables por severidad", d["probable"]["by_severity"], SEVERITY_LABELS),
                bars("Potenciales por severidad", d["potential"]["by_severity"], SEVERITY_LABELS),
            ),
        ),
        Section(
            "Confirmados",
            (
                _t("vulnerabilities", d["confirmed"]["table"], "Sin findings confirmados."),
                Paragraph("Probables:"),
                _t("vulnerabilities", d["probable"]["table"], "Sin findings probables."),
            ),
        ),
        Section(
            "Potenciales",
            (
                Notice("Findings POTENCIALES: no confirmados por la evidencia del inventario."),
                _t("vulnerabilities", d["potential"]["table"], "Sin findings potenciales."),
            ),
        ),
        Section(
            "Resueltos en el período",
            (
                _t(
                    "vulnerabilities",
                    d["resolved"]["table"],
                    "Sin findings resueltos en el período.",
                ),
            ),
        ),
        Section(
            "Evidencia de inventario antigua",
            (
                Paragraph(
                    f"Findings activos cuyo inventario tiene más de {d['stale_inventory_hours']} h."
                ),
                _t("vulnerabilities", d["stale_evidence"]["table"], "Ninguno."),
            ),
        ),
    ]


def _risk(snapshot: dict[str, Any]) -> list[Section]:
    d = snapshot["data"]
    unit = "día" if d["trend_unit"] == "day" else "semana"
    contributions: list[Block] = []
    for asset in d["top_assets"]:
        contributions.append(
            Paragraph(f"{asset['asset']} — score {asset['score']} ({fmt(asset['level'])}):")
        )
        contributions.append(
            table(
                (
                    ("category", "Categoría"),
                    ("label", "Contribución"),
                    ("points", "Puntos"),
                    ("rule_id", "Regla"),
                ),
                {"rows": asset["contributions"], "total": len(asset["contributions"])},
                "Sin contribuciones.",
            )
        )
    return [
        Section(
            "Distribución actual",
            (
                Bullets(tuple(snapshot["summary"])),
                bars("Activos por nivel", d["by_level"], LEVEL_LABELS),
                _kv(
                    [
                        ("Activos en el alcance", d["assets_in_scope"]),
                        ("Sin puntuar", d["unscored"]),
                    ]
                ),
            ),
        ),
        Section(
            "Activos más riesgosos",
            (
                table(
                    _TOP_RISK,
                    {"rows": d["top_assets"], "total": len(d["top_assets"])},
                    "Sin activos puntuados.",
                ),
            ),
        ),
        Section("Contribuciones", tuple(contributions) or (Paragraph("Sin datos."),)),
        Section(
            "Cambios de nivel",
            (
                bars("Transiciones", d["transitions"]),
                table(
                    TABLE_COLUMNS["risk_changes"],
                    d["changes"],
                    "Sin cambios de nivel en el período.",
                ),
            ),
        ),
        Section(
            "Evolución",
            (
                bars(
                    f"Score máximo por {unit} (snapshots del Risk Engine)",
                    {fmt(p["bucket"])[:10]: p["max_score"] for p in d["evolution"]},
                ),
                table(
                    (
                        ("bucket", "Inicio"),
                        ("avg_score", "Score medio"),
                        ("max_score", "Score máximo"),
                        ("samples", "Snapshots"),
                    ),
                    {"rows": d["evolution"], "total": len(d["evolution"])},
                ),
            ),
        ),
    ]


def _detection(snapshot: dict[str, Any]) -> list[Section]:
    d, t = snapshot["data"], snapshot["tables"]
    rows = t["detections"]["rows"]
    incidents = sorted({number for row in rows for number in row.get("incidents") or []})
    return [
        Section(
            "Resumen",
            (
                Bullets(tuple(snapshot["summary"])),
                bars("Por severidad", d["by_severity"], SEVERITY_LABELS),
                bars("Por estado", d["by_status"]),
                table(
                    (("rule_id", "Regla"), ("title", "Título"), ("count", "Detecciones")),
                    {"rows": d["top_rules"], "total": len(d["top_rules"])},
                ),
            ),
        ),
        Section("Detecciones", (_t("detections", t["detections"], "Sin detecciones."),)),
        Section("Evidencia", (_t("evidence", t["evidence"], "Sin evidencia guardada."),)),
        Section(
            "Incidentes asociados",
            (
                Bullets(tuple(incidents))
                if incidents
                else Paragraph("Ninguna detección está en un incidente."),
            ),
        ),
    ]


def _response(snapshot: dict[str, Any]) -> list[Section]:
    d, t = snapshot["data"], snapshot["tables"]
    return [
        Section(
            "Resumen",
            (
                Bullets(tuple(snapshot["summary"])),
                bars("Por estado", d["by_status"]),
                bars("Por acción", d["by_action"]),
            ),
        ),
        Section(
            "Ejecuciones",
            (
                Notice(
                    "Sin parámetros, tokens ni credenciales:"
                    " solo acción, objetivo, estado y resultado acotado."
                ),
                _t("executions", t["executions"], "Sin ejecuciones."),
            ),
        ),
        Section(
            "Playbooks", (_t("playbook_runs", t["playbook_runs"], "Sin ejecuciones de playbook."),)
        ),
    ]


def _lifecycle(snapshot: dict[str, Any]) -> list[Section]:
    t = snapshot["tables"]
    d = snapshot["data"]
    return [
        Section(
            "Resumen",
            (
                Bullets(tuple(snapshot["summary"])),
                bars("Origen de los activos", d["assets"]["by_source"], SOURCE_LABELS),
            ),
        ),
        Section(
            "Activos nuevos",
            (_t("new_assets", t["new_assets"], "Sin activos nuevos en el período."),),
        ),
        Section(
            "Stale y candidatos a limpieza", (_t("stale", t["stale"], "Ningún activo stale."),)
        ),
        Section(
            "Archivados y restaurados",
            (
                bars("Eventos de ciclo de vida", d["events_by_action"]),
                _t("events", t["events"], "Sin eventos en el período."),
            ),
        ),
        Section(
            "Posibles duplicados",
            (
                Notice(
                    "Misma IP no implica mismo equipo: solo se listan pares con evidencia de 5C.2."
                ),
                _t("duplicates", t["duplicates"], "Sin posibles duplicados."),
            ),
        ),
        Section(
            "Reconciliaciones",
            (_t("reconciliations", t["reconciliations"], "Sin reconciliaciones en el período."),),
        ),
        Section(
            "Cambios de discovery", (_t("changes", t["changes"], "Sin cambios en el período."),)
        ),
    ]


TEMPLATES: dict[str, Callable[[dict[str, Any]], list[Section]]] = {
    "executive_summary": _executive,
    "technical": _technical,
    "incident": _incident,
    "asset": _asset,
    "vulnerability": _vulnerability,
    "risk": _risk,
    "detection": _detection,
    "response_activity": _response,
    "lifecycle_change": _lifecycle,
}


def render_document(snapshot: dict[str, Any]) -> Document:
    meta = snapshot["meta"]
    sections = TEMPLATES[meta["report_type"]](snapshot)
    return Document(
        title=meta["title"],
        report_name=meta["report_name"],
        report_id=meta["report_id"],
        generated_at=fmt(meta["generated_at"]),
        classification=CLASSIFICATION_LABELS.get(meta["classification"], "INTERNAL"),
        meta=_meta(meta),
        summary=tuple(snapshot["summary"]),
        sections=tuple(sections),
    )

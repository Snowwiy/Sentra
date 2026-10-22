"""Catálogo CERRADO de tipos de informe (Fase 5E), definido en código.

Cada tipo declara quién puede generarlo, qué permisos de lectura de dominio hacen falta para
verlo, qué formatos y filtros admite, su plantilla versionada y sus límites. La API y la UI
solo conocen estos ids: no hay tipos, plantillas ni consultas definidas por el usuario.

Subir `template_version` es obligatorio al cambiar lo que una plantilla muestra: los informes
ya generados conservan la versión con la que se hicieron (y su fichero no cambia).
"""

from dataclasses import dataclass, field
from typing import Literal

from app.core.permissions import Permission
from app.models.detection import DetectionSeverity
from app.models.incident import IncidentStatus
from app.models.response import EXECUTION_STATUSES
from app.models.risk import RiskLevel
from app.vulnerabilities.catalog import SEVERITIES as VULN_SEVERITIES
from app.vulnerabilities.workflow import STATUSES as VULN_STATUSES

Audience = Literal["executive", "technical"]
Format = Literal["html", "pdf", "csv", "evidence"]
FORMATS: tuple[str, ...] = ("html", "pdf", "csv", "evidence")
CLASSIFICATIONS: tuple[str, ...] = ("internal", "confidential", "restricted")
FILTER_NAMES: tuple[str, ...] = (
    "asset_ids",
    "incident_ids",
    "detection_ids",
    "execution_ids",
    "playbook_ids",
    "severities",
    "statuses",
    "risk_levels",
    "platforms",
    "include_archived",
)
PLATFORMS: tuple[str, ...] = ("windows", "linux", "other")
RISK_LEVELS: tuple[str, ...] = tuple(level.value for level in RiskLevel)
DETECTION_SEVERITIES: tuple[str, ...] = tuple(s.value for s in DetectionSeverity)
DETECTION_STATUSES: tuple[str, ...] = ("open", "acknowledged", "resolved")
INCIDENT_STATUSES: tuple[str, ...] = tuple(s.value for s in IncidentStatus)
INCIDENT_SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")

CONTENT_TYPES = {
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
    "csv": "text/csv; charset=utf-8",
    "evidence": "application/zip",
}
EXTENSIONS = {"html": "html", "pdf": "pdf", "csv": "csv", "evidence": "zip"}


@dataclass(frozen=True)
class ReportDefinition:
    id: str
    name: str
    description: str
    audience: Audience
    # Permiso para generarlo (además de reports:generate, que exige la ruta).
    generate_permission: Permission
    # Permisos de lectura de los datos que contiene: hacen falta para generarlo Y para verlo
    # o descargarlo después. Un informe nunca enseña lo que el rol no puede leer en la API.
    domain_permissions: frozenset[Permission]
    supported_formats: tuple[str, ...]
    filters: tuple[str, ...]
    template_version: int
    sections: tuple[str, ...]
    required_filters: tuple[str, ...] = ()
    severity_values: tuple[str, ...] = ()
    status_values: tuple[str, ...] = ()
    # False: el informe cubre el objeto entero hasta la hora de corte (incidente).
    uses_range: bool = True
    # Tope propio (días) si es menor que REPORT_MAX_RANGE_DAYS.
    max_range_days: int | None = None
    # Tabla del snapshot que exporta el formato CSV (la principal del tipo).
    csv_table: str | None = None
    # Tablas que van como CSV dentro del paquete de evidencia.
    evidence_tables: tuple[str, ...] = field(default_factory=tuple)


# Versión de plantilla de los informes NUEVOS (Fase 6D.5: v2 con portada, gráficas
# extendidas y PDF con transliteración). La versión se guarda en `reports.template_version` y
# en `snapshot.meta.template_version`; el render elige la plantilla por la del snapshot, así un
# informe v1 ya generado se vuelve a renderizar con v1 y conserva sus bytes.
TEMPLATE_VERSION = 2
SUPPORTED_TEMPLATE_VERSIONS: tuple[int, ...] = (1, 2)

_MONITORING = Permission.MONITORING_READ
_ALL_DOMAINS = frozenset(
    {
        Permission.MONITORING_READ,
        Permission.INCIDENTS_READ,
        Permission.VULNERABILITIES_READ,
        Permission.THREAT_INTEL_READ,
        Permission.RESPONSE_READ,
    }
)

DEFINITIONS: tuple[ReportDefinition, ...] = (
    ReportDefinition(
        id="executive_summary",
        name="Resumen ejecutivo de seguridad",
        description=(
            "KPIs agregados, tendencias y principales riesgos para dirección. Sin IDs, IPs ni"
            " evidencia técnica."
        ),
        audience="executive",
        generate_permission=Permission.REPORTS_ADMIN,
        domain_permissions=_ALL_DOMAINS,
        supported_formats=("html", "pdf"),
        filters=("include_archived",),
        template_version=TEMPLATE_VERSION,
        sections=(
            "Estado general",
            "Activos monitorizados",
            "Riesgo",
            "Incidentes",
            "Detecciones",
            "Vulnerabilidades",
            "Response",
            "Tendencias",
            "Hallazgos prioritarios",
        ),
    ),
    ReportDefinition(
        id="technical",
        name="Informe técnico de seguridad",
        description=(
            "Detalle técnico con identificadores, activos, reglas, evidencia y línea de tiempo."
            " Sin activos ni incidentes concretos es global y solo lo genera un admin."
        ),
        audience="technical",
        generate_permission=Permission.REPORTS_GENERATE,
        domain_permissions=_ALL_DOMAINS,
        supported_formats=("html", "pdf", "evidence"),
        filters=(
            "asset_ids",
            "incident_ids",
            "severities",
            "risk_levels",
            "platforms",
            "include_archived",
        ),
        severity_values=DETECTION_SEVERITIES,
        template_version=TEMPLATE_VERSION,
        sections=(
            "Resumen",
            "Inventario de activos",
            "Ciclo de vida",
            "Riesgo",
            "Detecciones",
            "Alertas",
            "Vulnerabilidades",
            "Threat intelligence",
            "Incidentes",
            "Actividad de Response",
            "Cambios de discovery",
        ),
        evidence_tables=("assets", "detections", "alerts", "vulnerabilities", "incidents"),
    ),
    ReportDefinition(
        id="incident",
        name="Informe de incidente",
        description=(
            "Un incidente completo: activos, detecciones, alertas, vulnerabilidades, threat"
            " intel, notas, línea de tiempo y Response, en orden cronológico."
        ),
        audience="technical",
        generate_permission=Permission.REPORTS_GENERATE,
        domain_permissions=frozenset(
            {Permission.MONITORING_READ, Permission.INCIDENTS_READ, Permission.RESPONSE_READ}
        ),
        supported_formats=("html", "pdf", "evidence"),
        filters=("incident_ids",),
        required_filters=("incident_ids",),
        uses_range=False,
        template_version=TEMPLATE_VERSION,
        sections=(
            "Incidente",
            "Activos",
            "Detecciones",
            "Alertas",
            "Vulnerabilidades",
            "Threat intelligence",
            "Notas",
            "Línea de tiempo",
            "Response y playbooks",
            "Referencias de evidencia",
        ),
        evidence_tables=("timeline", "detections", "alerts", "executions"),
    ),
    ReportDefinition(
        id="asset",
        name="Informe de seguridad del activo",
        description=(
            "Identidad, ciclo de vida, agente y linaje, inventario, detecciones,"
            " vulnerabilidades, riesgo, incidentes, threat intel, Response y cambios."
        ),
        audience="technical",
        generate_permission=Permission.REPORTS_GENERATE,
        domain_permissions=_ALL_DOMAINS,
        supported_formats=("html", "pdf", "evidence"),
        filters=("asset_ids", "include_archived"),
        required_filters=("asset_ids",),
        template_version=TEMPLATE_VERSION,
        sections=(
            "Identidad",
            "Ciclo de vida y agente",
            "Inventario",
            "Riesgo",
            "Detecciones",
            "Vulnerabilidades",
            "Incidentes",
            "Threat intelligence",
            "Response",
            "Cambios importantes",
            "Evidencia de discovery",
        ),
        evidence_tables=("detections", "vulnerabilities", "changes", "executions"),
    ),
    ReportDefinition(
        id="vulnerability",
        name="Informe de vulnerabilidades",
        description=(
            "Findings confirmados, potenciales y resueltos por separado, con CVE, componente,"
            " catálogo, estado y evidencia de inventario antigua."
        ),
        audience="technical",
        generate_permission=Permission.REPORTS_GENERATE,
        domain_permissions=frozenset({Permission.MONITORING_READ, Permission.VULNERABILITIES_READ}),
        supported_formats=("html", "pdf", "csv"),
        filters=("asset_ids", "severities", "statuses", "platforms", "include_archived"),
        severity_values=VULN_SEVERITIES,
        status_values=VULN_STATUSES,
        template_version=TEMPLATE_VERSION,
        sections=(
            "Resumen",
            "Confirmados",
            "Potenciales",
            "Resueltos en el período",
            "Evidencia de inventario antigua",
        ),
        csv_table="vulnerabilities",
    ),
    ReportDefinition(
        id="risk",
        name="Informe de riesgo",
        description=(
            "Riesgo actual del Risk Engine (score, nivel, contribuciones), activos más"
            " riesgosos, cambios y evolución durante el período. No recalcula nada."
        ),
        audience="technical",
        generate_permission=Permission.REPORTS_GENERATE,
        domain_permissions=frozenset({Permission.MONITORING_READ}),
        supported_formats=("html", "pdf"),
        filters=("asset_ids", "risk_levels", "platforms", "include_archived"),
        template_version=TEMPLATE_VERSION,
        sections=(
            "Distribución actual",
            "Activos más riesgosos",
            "Contribuciones",
            "Cambios de nivel",
            "Evolución",
        ),
    ),
    ReportDefinition(
        id="detection",
        name="Informe de detecciones",
        description=(
            "Detecciones del motor con regla, severidad, confianza, estado, activo, evidencia,"
            " primera y última vez, incidentes asociados y contribución al riesgo."
        ),
        audience="technical",
        generate_permission=Permission.REPORTS_GENERATE,
        domain_permissions=frozenset({Permission.MONITORING_READ, Permission.INCIDENTS_READ}),
        supported_formats=("html", "pdf", "csv", "evidence"),
        filters=(
            "detection_ids",
            "asset_ids",
            "severities",
            "statuses",
            "platforms",
            "include_archived",
        ),
        severity_values=DETECTION_SEVERITIES,
        status_values=DETECTION_STATUSES,
        template_version=TEMPLATE_VERSION,
        sections=("Resumen", "Detecciones", "Evidencia", "Incidentes asociados"),
        csv_table="detections",
        evidence_tables=("detections", "evidence"),
    ),
    ReportDefinition(
        id="response_activity",
        name="Informe de actividad de Response",
        description=(
            "Ejecuciones de acciones y playbooks: actor, objetivo, estado, resultado, motivo de"
            " fallo, duración, riesgo y confirmación. Sin parámetros sensibles."
        ),
        audience="technical",
        generate_permission=Permission.REPORTS_GENERATE,
        domain_permissions=frozenset({Permission.MONITORING_READ, Permission.RESPONSE_READ}),
        supported_formats=("html", "pdf", "csv", "evidence"),
        filters=("asset_ids", "execution_ids", "playbook_ids", "statuses", "include_archived"),
        status_values=EXECUTION_STATUSES,
        template_version=TEMPLATE_VERSION,
        sections=("Resumen", "Ejecuciones", "Playbooks"),
        csv_table="executions",
        evidence_tables=("executions", "playbook_runs"),
    ),
    ReportDefinition(
        id="lifecycle_change",
        name="Informe de ciclo de vida y cambios",
        description=(
            "Activos nuevos, stale, archivados, restaurados, posibles duplicados,"
            " reconciliaciones y cambios de discovery (semántica 5C.2: misma IP no es mismo"
            " equipo)."
        ),
        audience="technical",
        generate_permission=Permission.REPORTS_GENERATE,
        domain_permissions=frozenset({_MONITORING, Permission.ASSET_DUPLICATES_READ}),
        supported_formats=("html", "pdf", "csv"),
        filters=("asset_ids", "platforms", "include_archived"),
        template_version=TEMPLATE_VERSION,
        sections=(
            "Resumen",
            "Activos nuevos",
            "Stale y candidatos a limpieza",
            "Archivados y restaurados",
            "Posibles duplicados",
            "Reconciliaciones",
            "Cambios de discovery",
        ),
        csv_table="new_assets",
    ),
)

_BY_ID = {definition.id: definition for definition in DEFINITIONS}
REPORT_TYPES: tuple[str, ...] = tuple(_BY_ID)


def get_definition(report_type: str) -> ReportDefinition | None:
    return _BY_ID.get(report_type)

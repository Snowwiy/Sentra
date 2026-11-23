"""Fase 7D.1: identidad de agentes, acceso a evidencias de endpoint y transporte

Revision ID: 0051
Revises: 0050
Create Date: 2026-11-07

Cambios (docs/fase-7d1.md):
- H01: credencial pendiente de rotación, origen de la credencial, petición de rotación y
  transporte observado en `assets`; tabla `agent_recovery_tokens` (autorizaciones de
  recuperación de una identidad existente: un solo uso, vida corta, solo el SHA-256).
- H02/H03: permisos de contenido guardados con cada copia derivada de evidencias:
  `tool_executions.read_permissions`, `reports.content_permissions`,
  `ai_insights.content_permissions`. Cada lectura los compara con los permisos ACTUALES.

Índices: cada FK nueva de agent_recovery_tokens tiene el suyo (asset_id, site_id,
created_by_user_id); token_hash es único.

Datos (conservador: ante la duda, el contenido histórico queda protegido):
- tool_executions.read_permissions = permisos de dominio de su herramienta (tabla fija de
  abajo, copia del catálogo en 0051) más telemetry:read en las herramientas cuya salida pudo
  copiar detalle de endpoint (detecciones, atribución, relacionadas).
- reports técnicos, de activo y de detección ya generados: ["telemetry:read"] (su snapshot
  pudo incluir evidencias de endpoint completas). El resto, [].
- ai_insights salvo vulnerability_analysis: ["telemetry:read"] (el contexto incluía
  detecciones y evidencias sin filtrar).
- alerts.details.summary de detecciones de endpoint: se sustituye por el resumen seguro
  (título de la regla). incidents.description igual a ese resumen copiado: también.
  La evidencia original (detections, detection_evidence) NO se toca.

DOWNGRADE: restaura alerts.details.summary e incidents.description desde detections.summary,
y elimina columnas y tabla (las autorizaciones de recuperación pendientes se pierden; las
credenciales pendientes de rotación se descartan y el agente sigue con la vigente).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0051"
down_revision: str | None = "0050"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())
_EMPTY = sa.text("'[]'::jsonb")

WITHHELD_NOTE = "El detalle de la actividad del endpoint requiere el permiso telemetry:read."

# Copia fija de los permisos de dominio del catálogo de herramientas en 0051: una migración no
# importa código de la aplicación, que puede cambiar después.
_M = "monitoring:read"
_T = "telemetry:read"
TOOL_READ_PERMISSIONS: dict[str, list[str]] = {
    "asset.lookup": [_M],
    "asset.profile": [_M],
    "asset.history": [_M],
    "telemetry.recent": [_M],
    "process.tree": [_M, _T],
    "process.instance": [_M, _T],
    "events.search": [_M],
    "detections.search": [_M, _T],
    "detections.get": [_M, _T],
    "vulnerabilities.assess": [_M, "vulnerabilities:read"],
    "exposure.ports": [_M],
    "risk.explain": [_M],
    "timeline.build": [_M],
    "topology.changes": [_M],
    "identity.evidence": [_M],
    "operations.history": [_M],
    "discovery.scan_host": ["discovery:run", _M, "response:execute"],
    "forensics.collect": ["forensics:acquire", _M, "response:execute"],
    "response.prepare": [_M, "response:execute"],
    "response.execute": [_M, "response:execute"],
    "case.open": ["incidents:manage", "incidents:read"],
    "case.link_evidence": ["incidents:manage", "incidents:read"],
    "attribution.explain": [_M, _T],
    "detections.related": [_M, _T],
    "identity.candidates": [_M],
}
# Herramienta desconocida (retirada antes de 0051): falla cerrado, solo quien gestiona.
_UNKNOWN_TOOL = [_M, _T, "tools:manage"]

# Detecciones de endpoint: misma regla que app/core/evidence_policy.py.
_ENDPOINT_DETECTION = """
    (d.rule_category = 'behavior' OR EXISTS (
        SELECT 1 FROM detection_evidence e
        WHERE e.detection_id = d.id AND e.source_type = 'endpoint_activity'
    ))
"""
_SAFE = f"left(d.title || '. ' || '{WITHHELD_NOTE}', 300)"
_SAFE_FULL = f"d.title || '. ' || '{WITHHELD_NOTE}'"


def upgrade() -> None:
    # --- H01: identidad y transporte de agentes ------------------------------------------
    for column in (
        sa.Column("agent_token_pending_hash", sa.String(64)),
        sa.Column("agent_token_pending_issued_at", sa.DateTime(timezone=True)),
        sa.Column("agent_credential_source", sa.String(16)),
        sa.Column("agent_rotation_requested_at", sa.DateTime(timezone=True)),
        sa.Column("agent_rotation_reason", sa.String(32)),
        sa.Column("agent_transport", sa.String(16)),
        sa.Column("agent_transport_at", sa.DateTime(timezone=True)),
        sa.Column("agent_insecure_transport_at", sa.DateTime(timezone=True)),
    ):
        op.add_column("assets", column)

    op.create_table(
        "agent_recovery_tokens",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("public_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "asset_id",
            sa.BigInteger(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("site_id", sa.BigInteger(), sa.ForeignKey("sites.id", ondelete="SET NULL")),
        sa.Column("expected_hostname", sa.String(255)),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column(
            "created_by_user_id", sa.BigInteger(), sa.ForeignKey("users.id", ondelete="SET NULL")
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_agent_recovery_tokens_asset_id", "agent_recovery_tokens", ["asset_id"])
    op.create_index("ix_agent_recovery_tokens_site_id", "agent_recovery_tokens", ["site_id"])
    op.create_index(
        "ix_agent_recovery_tokens_created_by_user_id",
        "agent_recovery_tokens",
        ["created_by_user_id"],
    )
    op.create_index("ix_agent_recovery_tokens_created", "agent_recovery_tokens", ["created_at"])

    # --- H02/H03: permisos de contenido de las copias -------------------------------------
    op.add_column(
        "tool_executions",
        sa.Column("read_permissions", _JSONB, nullable=False, server_default=_EMPTY),
    )
    op.add_column(
        "reports",
        sa.Column("content_permissions", _JSONB, nullable=False, server_default=_EMPTY),
    )
    op.add_column(
        "ai_insights",
        sa.Column("content_permissions", _JSONB, nullable=False, server_default=_EMPTY),
    )

    bind = op.get_bind()
    executions = sa.table(
        "tool_executions", sa.column("tool_id", sa.String), sa.column("read_permissions", _JSONB)
    )
    for tool_id, permissions in TOOL_READ_PERMISSIONS.items():
        bind.execute(
            executions.update()
            .where(executions.c.tool_id == tool_id)
            .values(read_permissions=sorted(permissions))
        )
    bind.execute(
        executions.update()
        .where(executions.c.tool_id.not_in(sorted(TOOL_READ_PERMISSIONS)))
        .values(read_permissions=sorted(_UNKNOWN_TOOL))
    )
    op.execute(
        "UPDATE reports SET content_permissions = '[\"telemetry:read\"]'::jsonb"
        " WHERE report_type IN ('technical', 'asset', 'detection')"
    )
    op.execute(
        "UPDATE ai_insights SET content_permissions = '[\"telemetry:read\"]'::jsonb"
        " WHERE kind <> 'vulnerability_analysis'"
    )

    # Copias del resumen de detecciones de endpoint visibles con monitoring:read.
    op.execute(
        f"""
        UPDATE alerts a
        SET details = jsonb_set(a.details, '{{summary}}', to_jsonb({_SAFE}))
        FROM detections d
        WHERE a.details ? 'detection_id' AND a.details ? 'summary'
          AND a.details->>'detection_id' = d.public_id::text
          AND {_ENDPOINT_DETECTION}
        """  # noqa: S608  (fragmentos constantes de este módulo, sin datos externos)
    )
    op.execute(
        f"""
        UPDATE incidents i
        SET description = {_SAFE_FULL}
        FROM incident_detections x JOIN detections d ON d.id = x.detection_id
        WHERE x.incident_id = i.id AND i.description = d.summary
          AND {_ENDPOINT_DETECTION}
        """  # noqa: S608  (fragmentos constantes de este módulo, sin datos externos)
    )


def downgrade() -> None:
    op.execute(
        f"""
        UPDATE incidents i
        SET description = d.summary
        FROM incident_detections x JOIN detections d ON d.id = x.detection_id
        WHERE x.incident_id = i.id AND i.description = {_SAFE_FULL}
          AND {_ENDPOINT_DETECTION}
        """  # noqa: S608  (fragmentos constantes de este módulo, sin datos externos)
    )
    op.execute(
        f"""
        UPDATE alerts a
        SET details = jsonb_set(a.details, '{{summary}}', to_jsonb(left(d.summary, 300)))
        FROM detections d
        WHERE a.details ? 'detection_id' AND a.details ? 'summary'
          AND a.details->>'detection_id' = d.public_id::text
          AND a.details->>'summary' = {_SAFE}
        """  # noqa: S608  (fragmentos constantes de este módulo, sin datos externos)
    )
    op.drop_column("ai_insights", "content_permissions")
    op.drop_column("reports", "content_permissions")
    op.drop_column("tool_executions", "read_permissions")

    op.drop_index("ix_agent_recovery_tokens_created", table_name="agent_recovery_tokens")
    op.drop_index("ix_agent_recovery_tokens_created_by_user_id", table_name="agent_recovery_tokens")
    op.drop_index("ix_agent_recovery_tokens_site_id", table_name="agent_recovery_tokens")
    op.drop_index("ix_agent_recovery_tokens_asset_id", table_name="agent_recovery_tokens")
    op.drop_table("agent_recovery_tokens")
    for name in (
        "agent_insecure_transport_at",
        "agent_transport_at",
        "agent_transport",
        "agent_rotation_reason",
        "agent_rotation_requested_at",
        "agent_credential_source",
        "agent_token_pending_issued_at",
        "agent_token_pending_hash",
    ):
        op.drop_column("assets", name)

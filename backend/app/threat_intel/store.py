"""Persistencia de la inteligencia por staging: descargar -> validar -> staging -> aplicar.

Todo ocurre dentro de la transacción del llamador (sync.py). Los registros se copian con
COPY a una tabla temporal (ON COMMIT DROP) y desde ahí se aplican con pocas sentencias SQL
por conjuntos: nuevos, cambiados, sin cambios y desaparecidos. Si el parser falla a mitad
(fichero truncado, gzip corrupto), la excepción deshace la transacción entera: nunca queda
inteligencia a medias. Lo mismo sirve para la previsualización: staging + contar + rollback.

Qué se considera cambio (y deja historial en threat_intel_changes):
- KEV: alta (kev_added), baja del feed (kev_removed: el registro queda inactive, nunca se
  borra), vuelta (kev_readded) y cambios de contenido (kev_updated: fecha límite, acción...);
- EPSS: solo cambios MATERIALES (epss.is_material). La variación diaria normal actualiza el
  valor actual sin historial (ver epss.py);
- indicadores: revocación, restauración y reclasificación de uno existente. Las altas no
  generan una fila por IOC (500 000 filas no aportan nada): las cuenta la sincronización.

Seguridad del SQL: las sentencias se componen solo con fragmentos constantes de este módulo
(nombres de tabla, bandas EPSS); todos los valores van como parámetros (por eso los
`noqa: S608`).

Los CVEs con cambios que afectan a la prioridad o al riesgo (alta/baja en KEV, EPSS material
o nuevo) quedan en la tabla temporal ti_changed_cves para que sync.py encole solo los
activos afectados.
"""

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.threat_intel import epss
from app.threat_intel.indicators import TELEMETRY_SUPPORT
from app.threat_intel.records import IndicatorRecord, VulnIntelRecord

# Tipos de indicador que pueden casar con datos locales (el resto nunca entra en la cola de
# matching retroactivo: no hay telemetría con la que compararlos).
MATCHABLE_TYPES = tuple(t for t, support in TELEMETRY_SUPPORT.items() if support != "unsupported")

_BAND_SQL = (
    "CASE WHEN {v} IS NULL THEN -1 WHEN {v} >= {high} THEN 2 WHEN {v} >= {elevated} THEN 1 "
    "ELSE 0 END"
)


def _band(column: str) -> str:
    return _BAND_SQL.format(v=column, high=epss.HIGH, elevated=epss.ELEVATED)


@dataclass
class StoreResult:
    seen: int = 0
    new: int = 0
    updated: int = 0
    unchanged: int = 0
    removed: int = 0
    reappeared: int = 0
    # CVEs con cambios que afectan a prioridad/riesgo (para encolar activos).
    changed_cves: int = 0
    # Indicadores que entran en la cola de matching retroactivo.
    pending_match: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "seen": self.seen,
            "new": self.new,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "removed": self.removed,
            "reappeared": self.reappeared,
        }


def _copy(
    session: Session, table: str, columns: tuple[str, ...], rows: Iterable[tuple[Any, ...]]
) -> int:
    """COPY por streaming a una tabla temporal. Devuelve las filas copiadas."""
    raw = session.connection().connection.driver_connection
    count = 0
    statement = f"COPY {table} ({', '.join(columns)}) FROM STDIN"
    with raw.cursor() as cursor, cursor.copy(statement) as copy:  # type: ignore[union-attr]
        for row in rows:
            copy.write_row(row)
            count += 1
    return count


def _scalar(session: Session, sql: str, **params: Any) -> int:
    return int(session.execute(text(sql), params).scalar() or 0)


# --- Inteligencia de vulnerabilidades (KEV, EPSS) ----------------------------------------------

_VULN_COLUMNS = (
    "cve_id",
    "epss_score",
    "epss_percentile",
    "data",
    "external_id",
    "published_at",
    "modified_at",
    "content_hash",
)


def stage_vulnerabilities(session: Session, records: Iterable[VulnIntelRecord]) -> int:
    session.execute(text("DROP TABLE IF EXISTS ti_stage_vuln"))
    session.execute(
        text(
            "CREATE TEMP TABLE ti_stage_vuln (cve_id text, epss_score float8, "
            "epss_percentile float8, data text, external_id text, published_at timestamptz, "
            "modified_at timestamptz, content_hash text) ON COMMIT DROP"
        )
    )
    count = _copy(
        session,
        "ti_stage_vuln",
        _VULN_COLUMNS,
        (
            (
                r.cve_id,
                r.epss_score,
                r.epss_percentile,
                json.dumps(r.data, default=str),
                r.external_id,
                r.published_at,
                r.modified_at,
                r.fingerprint(),
            )
            for r in records
        ),
    )
    # Un CVE repetido en el feed: se queda una fila (la última copiada).
    session.execute(
        text(
            "DELETE FROM ti_stage_vuln a USING ti_stage_vuln b "
            "WHERE a.cve_id = b.cve_id AND a.ctid < b.ctid"
        )
    )
    session.execute(text("CREATE UNIQUE INDEX ON ti_stage_vuln (cve_id)"))
    session.execute(text("ANALYZE ti_stage_vuln"))
    return count


def apply_vulnerabilities(
    session: Session,
    source_id: int,
    kind: str,
    now: datetime,
    sync_id: int | None,
    *,
    complete: bool,
    source_url: str | None,
) -> StoreResult:
    """Aplica ti_stage_vuln a vulnerability_intel. Deja ti_changed_cves para sync.py."""
    params: dict[str, Any] = {
        "source": source_id,
        "kind": kind,
        "now": now,
        "sync": sync_id,
        "url": source_url,
    }
    result = StoreResult()
    result.seen = _scalar(session, "SELECT count(*) FROM ti_stage_vuln")
    session.execute(text("DROP TABLE IF EXISTS ti_changed_cves"))
    session.execute(
        text(
            "CREATE TEMP TABLE ti_changed_cves (cve_id text PRIMARY KEY, change text) "
            "ON COMMIT DROP"
        )
    )
    existing = (
        "FROM ti_stage_vuln s JOIN vulnerability_intel v ON v.source_id = :source "
        "AND v.kind = CAST(:kind AS text) AND v.cve_id = s.cve_id"
    )
    result.new = _scalar(
        session,
        "SELECT count(*) FROM ti_stage_vuln s WHERE NOT EXISTS ("
        "SELECT 1 FROM vulnerability_intel v WHERE v.source_id = :source "
        "AND v.kind = CAST(:kind AS text) AND v.cve_id = s.cve_id)",
        **params,
    )
    result.reappeared = _scalar(session, f"SELECT count(*) {existing} WHERE NOT v.active", **params)
    result.updated = _scalar(
        session,
        f"SELECT count(*) {existing} WHERE v.active AND v.content_hash <> s.content_hash",
        **params,
    )
    result.unchanged = result.seen - result.new - result.reappeared - result.updated

    material = (
        f"({_band('v.epss_score')} <> {_band('s.epss_score')} OR "
        f"abs(coalesce(s.epss_score, 0) - coalesce(v.epss_score, 0)) >= {epss.MATERIAL_DELTA})"
    )
    if kind == "kev":
        session.execute(
            text(
                "INSERT INTO ti_changed_cves (cve_id, change) "
                "SELECT s.cve_id, 'kev_added' FROM ti_stage_vuln s WHERE NOT EXISTS ("
                "SELECT 1 FROM vulnerability_intel v WHERE v.source_id = :source "
                "AND v.kind = CAST(:kind AS text) AND v.cve_id = s.cve_id) ON CONFLICT DO NOTHING"
            ),
            params,
        )
        session.execute(
            text(
                "INSERT INTO ti_changed_cves (cve_id, change) "
                f"SELECT s.cve_id, 'kev_readded' {existing} WHERE NOT v.active "
                "ON CONFLICT DO NOTHING"
            ),
            params,
        )
        detail = (
            "jsonb_build_object('date_added', s.data::jsonb->>'date_added', "
            "'due_date', s.data::jsonb->>'due_date', "
            "'known_ransomware_use', s.data::jsonb->>'known_ransomware_use')"
        )
        # Historial de altas, vueltas y cambios de contenido de KEV (acotado: ~1 500 CVEs).
        session.execute(
            text(
                "INSERT INTO threat_intel_changes (source_id, sync_id, occurred_at, record_kind, "  # noqa: S608
                "cve_id, change, details) "
                f"SELECT :source, :sync, :now, 'vulnerability', c.cve_id, c.change, {detail} "
                "FROM ti_changed_cves c JOIN ti_stage_vuln s ON s.cve_id = c.cve_id"
            ),
            params,
        )
        session.execute(
            text(
                "INSERT INTO threat_intel_changes (source_id, sync_id, occurred_at, record_kind, "
                "cve_id, change, details) "
                "SELECT :source, :sync, :now, 'vulnerability', s.cve_id, 'kev_updated', "
                "jsonb_build_object('from_due_date', v.data->>'due_date', 'to_due_date', "
                "s.data::jsonb->>'due_date') "
                f"{existing} WHERE v.active AND v.content_hash <> s.content_hash"
            ),
            params,
        )
    else:
        # EPSS: nuevo CVE puntuado o cambio material (cambia la prioridad); historial solo
        # de los materiales sobre un valor previo (las altas diarias no dejan fila).
        session.execute(
            text(
                "INSERT INTO ti_changed_cves (cve_id, change) "
                "SELECT s.cve_id, 'epss_added' FROM ti_stage_vuln s WHERE NOT EXISTS ("
                "SELECT 1 FROM vulnerability_intel v WHERE v.source_id = :source "
                "AND v.kind = CAST(:kind AS text) AND v.cve_id = s.cve_id AND v.active) "
                "ON CONFLICT DO NOTHING"
            ),
            params,
        )
        session.execute(
            text(
                "INSERT INTO ti_changed_cves (cve_id, change) "
                f"SELECT s.cve_id, 'epss_material_change' {existing} WHERE v.active AND {material} "
                "ON CONFLICT DO NOTHING"
            ),
            params,
        )
        session.execute(
            text(
                "INSERT INTO threat_intel_changes (source_id, sync_id, occurred_at, record_kind, "
                "cve_id, change, details) "
                "SELECT :source, :sync, :now, 'vulnerability', s.cve_id, 'epss_material_change', "
                "jsonb_build_object('from_score', v.epss_score, 'to_score', s.epss_score, "
                "'from_percentile', v.epss_percentile, 'to_percentile', s.epss_percentile) "
                f"{existing} WHERE v.active AND {material}"
            ),
            params,
        )

    # Cambios: contenido distinto o registro inactivo que vuelve. EPSS conserva en
    # data.previous el valor anterior al último cambio material.
    previous = (
        f"CASE WHEN {material} THEN jsonb_build_object('score', v.epss_score, 'percentile', "
        "v.epss_percentile, 'date', v.data->>'score_date') ELSE v.data->'previous' END"
        if kind == "epss"
        else "NULL"
    )
    session.execute(
        text(
            "UPDATE vulnerability_intel v SET "  # noqa: S608
            "epss_score = s.epss_score, epss_percentile = s.epss_percentile, "
            f"data = CASE WHEN {previous} IS NULL THEN s.data::jsonb "
            f"ELSE s.data::jsonb || jsonb_build_object('previous', {previous}) END, "
            "external_id = s.external_id, source_url = :url, published_at = s.published_at, "
            "modified_at = s.modified_at, retrieved_at = :now, last_changed_at = :now, "
            "active = true, removed_at = NULL, content_hash = s.content_hash, "
            "record_version = v.record_version + 1 "
            "FROM ti_stage_vuln s WHERE v.source_id = :source AND v.kind = CAST(:kind AS text) "
            "AND v.cve_id = s.cve_id AND (v.content_hash <> s.content_hash OR NOT v.active)"
        ),
        params,
    )
    session.execute(
        text(
            "INSERT INTO vulnerability_intel (source_id, kind, cve_id, active, epss_score, "
            "epss_percentile, data, external_id, source_url, published_at, modified_at, "
            "retrieved_at, first_seen_at, last_changed_at, content_hash, record_version) "
            "SELECT :source, CAST(:kind AS text), s.cve_id, true, s.epss_score, s.epss_percentile, "
            "s.data::jsonb, s.external_id, :url, s.published_at, s.modified_at, :now, :now, "
            # ON CONFLICT y no NOT EXISTS: los existentes ya se actualizaron arriba, y un
            # anti-join contra una tabla con estadísticas "vacías" (tras borrados masivos)
            # acababa en Nested Loop + Seq Scan por fila (medido: 80 s para 100 000 filas).
            ":now, s.content_hash, 1 FROM ti_stage_vuln s "
            "ON CONFLICT ON CONSTRAINT uq_vulnerability_intel_record DO NOTHING"
        ),
        params,
    )
    if complete:
        # Feed completo: lo que ya no viene se marca inactivo (nunca se borra) y queda en el
        # historial ("CISA retiró este CVE del catálogo" es información, no un olvido).
        removed_change = "kev_removed" if kind == "kev" else "epss_removed"
        session.execute(
            text(
                "INSERT INTO ti_changed_cves (cve_id, change) "  # noqa: S608
                f"SELECT v.cve_id, '{removed_change}' FROM vulnerability_intel v "
                "WHERE v.source_id = :source AND v.kind = CAST(:kind AS text) AND v.active "
                "AND NOT EXISTS ("
                "SELECT 1 FROM ti_stage_vuln s WHERE s.cve_id = v.cve_id) ON CONFLICT DO NOTHING"
            ),
            params,
        )
        session.execute(
            text(
                "INSERT INTO threat_intel_changes (source_id, sync_id, occurred_at, record_kind, "  # noqa: S608
                "cve_id, change, details) "
                f"SELECT :source, :sync, :now, 'vulnerability', c.cve_id, c.change, NULL "
                f"FROM ti_changed_cves c WHERE c.change = '{removed_change}'"
            ),
            params,
        )
        removed = session.execute(
            text(
                "UPDATE vulnerability_intel v SET active = false, removed_at = :now, "  # noqa: S608
                "last_changed_at = :now FROM ti_changed_cves c "
                f"WHERE c.change = '{removed_change}' AND v.source_id = :source "
                "AND v.kind = CAST(:kind AS text) AND v.cve_id = c.cve_id"
            ),
            params,
        )
        result.removed = int(getattr(removed, "rowcount", 0) or 0)
    result.changed_cves = _scalar(session, "SELECT count(*) FROM ti_changed_cves")
    return result


# --- Indicadores (IOCs) ------------------------------------------------------------------------

_IND_COLUMNS = (
    "indicator_type",
    "value_normalized",
    "value_original",
    "network",
    "classification",
    "confidence",
    "confidence_score",
    "valid_from",
    "valid_until",
    "revoked",
    "first_seen",
    "last_seen",
    "tags",
    "description",
    "refs",
    "related",
    "external_id",
    "pattern",
    "content_hash",
)


def stage_indicators(session: Session, records: Iterable[IndicatorRecord]) -> int:
    session.execute(text("DROP TABLE IF EXISTS ti_stage_ind"))
    session.execute(
        text(
            "CREATE TEMP TABLE ti_stage_ind (indicator_type text, value_normalized text, "
            "value_original text, network text, classification text, confidence text, "
            "confidence_score int, valid_from timestamptz, valid_until timestamptz, "
            "revoked bool, first_seen timestamptz, last_seen timestamptz, tags text, "
            "description text, refs text, related text, external_id text, pattern text, "
            "content_hash text) ON COMMIT DROP"
        )
    )
    count = _copy(
        session,
        "ti_stage_ind",
        _IND_COLUMNS,
        (
            (
                r.indicator_type,
                r.value,
                r.original,
                r.network,
                r.classification,
                r.confidence,
                r.confidence_score,
                r.valid_from,
                r.valid_until,
                r.revoked,
                r.first_seen,
                r.last_seen,
                json.dumps(list(r.tags)),
                r.description,
                json.dumps(list(r.references)),
                json.dumps([{"type": t, "name": n} for t, n in r.related]),
                r.external_id,
                r.pattern,
                r.fingerprint(),
            )
            for r in records
        ),
    )
    session.execute(
        text(
            "DELETE FROM ti_stage_ind a USING ti_stage_ind b WHERE a.indicator_type = "
            "b.indicator_type AND a.value_normalized = b.value_normalized AND a.ctid < b.ctid"
        )
    )
    session.execute(text("CREATE UNIQUE INDEX ON ti_stage_ind (indicator_type, value_normalized)"))
    session.execute(text("ANALYZE ti_stage_ind"))
    return count


_IND_EXISTING = (
    "FROM ti_stage_ind s JOIN threat_indicators i ON i.source_id = :source "
    "AND i.indicator_type = s.indicator_type AND i.value_normalized = s.value_normalized"
)
_IND_MISSING = (
    "FROM ti_stage_ind s WHERE NOT EXISTS (SELECT 1 FROM threat_indicators i WHERE "
    "i.source_id = :source AND i.indicator_type = s.indicator_type "
    "AND i.value_normalized = s.value_normalized)"
)


def count_indicators(session: Session, source_id: int) -> StoreResult:
    """Previsualización: cuántos serían nuevos, cambiados o iguales (no escribe nada)."""
    params = {"source": source_id}
    result = StoreResult()
    result.seen = _scalar(session, "SELECT count(*) FROM ti_stage_ind")
    result.new = _scalar(session, f"SELECT count(*) {_IND_MISSING}", **params)
    result.updated = _scalar(
        session, f"SELECT count(*) {_IND_EXISTING} WHERE i.content_hash <> s.content_hash", **params
    )
    result.unchanged = result.seen - result.new - result.updated
    return result


def apply_indicators(
    session: Session, source_id: int, now: datetime, sync_id: int | None
) -> StoreResult:
    params: dict[str, Any] = {
        "source": source_id,
        "now": now,
        "sync": sync_id,
        "matchable": list(MATCHABLE_TYPES),
    }
    result = count_indicators(session, source_id)
    # Historial de cambios relevantes de indicadores existentes (no de cada alta).
    session.execute(
        text(
            "INSERT INTO threat_intel_changes (source_id, sync_id, occurred_at, record_kind, "
            "indicator_id, change, details) "
            "SELECT :source, :sync, :now, 'indicator', i.id, "
            "CASE WHEN s.revoked AND NOT i.revoked THEN 'indicator_revoked' "
            "WHEN NOT s.revoked AND i.revoked THEN 'indicator_restored' "
            "ELSE 'indicator_reclassified' END, "
            "jsonb_build_object('from', i.classification, 'to', s.classification, "
            "'from_confidence', i.confidence, 'to_confidence', s.confidence) "
            f"{_IND_EXISTING} WHERE s.revoked <> i.revoked OR s.classification <> i.classification "
            "OR s.confidence <> i.confidence"
        ),
        params,
    )
    session.execute(
        text(
            "UPDATE threat_indicators i SET value_original = s.value_original, "
            "network = s.network::cidr, classification = s.classification, "
            "confidence = s.confidence, confidence_score = s.confidence_score, "
            "valid_from = s.valid_from, valid_until = s.valid_until, revoked = s.revoked, "
            "revoked_at = CASE WHEN s.revoked AND NOT i.revoked THEN :now "
            "WHEN NOT s.revoked THEN NULL ELSE i.revoked_at END, "
            "first_seen_external = s.first_seen, last_seen_external = s.last_seen, "
            'tags = s.tags::jsonb, description = s.description, "references" = s.refs::jsonb, '
            "related = s.related::jsonb, external_id = s.external_id, pattern = s.pattern, "
            "content_hash = s.content_hash, retrieved_at = :now, updated_at = :now, "
            # Un indicador que cambia (vuelve a ser válido, se reclasifica) se busca otra vez
            # en los datos locales ya existentes.
            "pending_match = (s.indicator_type = ANY(:matchable) AND NOT s.revoked) "
            "FROM ti_stage_ind s WHERE i.source_id = :source AND i.indicator_type = "
            "s.indicator_type AND i.value_normalized = s.value_normalized "
            "AND i.content_hash <> s.content_hash"
        ),
        params,
    )
    session.execute(
        text(
            "INSERT INTO threat_indicators (public_id, source_id, indicator_type, "
            "value_normalized, value_original, network, classification, confidence, "
            "confidence_score, valid_from, valid_until, revoked, revoked_at, "
            'first_seen_external, last_seen_external, tags, description, "references", '
            "related, external_id, pattern, content_hash, pending_match, match_count, "
            "retrieved_at, created_at, updated_at) "
            "SELECT gen_random_uuid(), :source, s.indicator_type, s.value_normalized, "
            "s.value_original, s.network::cidr, s.classification, s.confidence, "
            "s.confidence_score, s.valid_from, s.valid_until, s.revoked, "
            "CASE WHEN s.revoked THEN :now END, s.first_seen, s.last_seen, s.tags::jsonb, "
            "s.description, s.refs::jsonb, s.related::jsonb, s.external_id, s.pattern, "
            "s.content_hash, (s.indicator_type = ANY(:matchable) AND NOT s.revoked), 0, "
            # Igual que en vulnerability_intel: ON CONFLICT en vez de NOT EXISTS.
            ":now, :now, :now FROM ti_stage_ind s "
            "ON CONFLICT ON CONSTRAINT uq_threat_indicator DO NOTHING"
        ),
        params,
    )
    result.pending_match = _scalar(
        session,
        "SELECT count(*) FROM threat_indicators WHERE source_id = :source AND pending_match",
        **params,
    )
    return result

import { useCallback, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import type { CveDetail, CveSourceRecord } from "../api/types";
import { vulnSourcesApi } from "../api/vulnSources";
import { config } from "../config";
import { ErrorState, LoadingState } from "../components/StateViews";
import { EpssBadge, KevBadge } from "../components/threatintel/IntelBadges";
import { VulnSeverityBadge } from "../components/vulnerabilities/VulnBadges";
import { errorMessage, formatDateTime } from "../lib/format";
import { usePolling } from "../lib/usePolling";
import { formatCvss, safeReference } from "../lib/vulnerabilities";
import { ADAPTER_LABELS, ATTRIBUTE_LABELS, isCveId, provenanceText, RETIRED_LABELS } from "../lib/vulnSources";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

/** Procedencia de cada atributo: lo que guardó el adapter y lo que documenta la fuente. */
function ProvenanceTable({ record, documented }: { record: CveSourceRecord; documented: Record<string, string> }) {
  const provenance = asRecord(record.provenance);
  const stored = asRecord(provenance.attributes);
  const attributes = Array.from(new Set([...Object.keys(stored), ...Object.keys(documented)]));
  if (attributes.length === 0) return <p className="muted small">El registro no guarda procedencia por atributo.</p>;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Atributo</th>
            <th>Origen en este registro</th>
            <th className="col-secondary">Origen documentado</th>
          </tr>
        </thead>
        <tbody>
          {attributes.map((attr) => (
            <tr key={attr}>
              <td>{ATTRIBUTE_LABELS[attr] ?? attr}</td>
              <td className="mono small">{provenanceText(stored[attr])}</td>
              <td className="col-secondary small">{documented[attr] ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RecordPanel({ record, detail }: { record: CveSourceRecord; detail: CveDetail }) {
  const provenance = asRecord(record.provenance);
  const references = record.references.map(safeReference).filter((u): u is string => u !== null);
  const documented = detail.attribute_sources[record.adapter] ?? {};
  return (
    <section className="panel panel--padded stack" aria-label={`Registro de ${record.source_name}`}>
      <h2>
        {record.source_name} <span className="muted small mono">({record.source})</span>
      </h2>
      <div className="detection-badges">
        <span className="badge">{ADAPTER_LABELS[record.adapter] ?? record.adapter}</span>
        <VulnSeverityBadge severity={record.severity} />
        {record.retired && <span className="badge badge--warn">{RETIRED_LABELS[record.retired] ?? record.retired}</span>}
      </div>
      {/* Texto de NVD/OSV: dato no confiable, siempre como texto (React escapa). */}
      <p>
        <strong>{record.title}</strong>
      </p>
      {record.description && <p className="note-body">{record.description}</p>}
      <dl className="fields">
        <Field label="Identificador en la fuente">
          <span className="mono">{record.vulnerability_id}</span>
        </Field>
        <Field label="CVSS">{formatCvss(record.cvss_score, record.cvss_version)}</Field>
        {record.cvss_vector && (
          <Field label="Vector CVSS">
            <span className="mono small">{record.cvss_vector}</span>
          </Field>
        )}
        {record.source_severity && <Field label="Severidad de la fuente">{record.source_severity}</Field>}
        <Field label="Publicado">{formatDateTime(record.published_at)}</Field>
        <Field label="Modificado">{formatDateTime(record.modified_at)}</Field>
        <Field label="Importado">{formatDateTime(record.imported_at)}</Field>
        <Field label="Actualizado en Sentra">
          {formatDateTime(record.updated_at)} · versión {record.record_version}
        </Field>
        {typeof provenance.retrieved_at === "string" && (
          <Field label="Recuperado de la fuente">{formatDateTime(provenance.retrieved_at)}</Field>
        )}
        {typeof provenance.content_sha256 === "string" && (
          <Field label="Huella del fichero o página">
            <span className="mono small">{provenance.content_sha256}</span>
          </Field>
        )}
        {record.aliases.length > 0 && <Field label="Alias">{record.aliases.join(", ")}</Field>}
        {record.cwe.length > 0 && <Field label="CWE">{record.cwe.join(", ")}</Field>}
        <Field label="Entradas de productos afectados">{record.affected.length}</Field>
      </dl>
      {record.remediation && (
        <>
          <h3>Remediación</h3>
          <p className="note-body">{record.remediation}</p>
        </>
      )}
      <h3>Procedencia de cada atributo</h3>
      <ProvenanceTable record={record} documented={documented} />
      {references.length > 0 && (
        <details>
          <summary className="small">Referencias ({references.length})</summary>
          <ul className="vuln-refs">
            {references.map((url) => (
              <li key={url}>
                <a href={url} target="_blank" rel="noopener noreferrer nofollow">
                  {url}
                </a>
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}

function Exploitation({ data }: { data: Record<string, unknown> | null }) {
  if (!data) {
    return (
      <section className="panel panel--padded">
        <h2>Explotación (Threat Intelligence)</h2>
        <p className="muted small">Sin datos de KEV ni EPSS para este CVE.</p>
      </section>
    );
  }
  const kev = asRecord(data.kev);
  const epss = asRecord(data.epss);
  const score = typeof epss.score === "number" ? epss.score : null;
  return (
    <section className="panel panel--padded">
      <h2>Explotación (Threat Intelligence)</h2>
      <div className="detection-badges">
        {data.known_exploited === true && <KevBadge stale={kev.stale === true} />}
        <EpssBadge score={score} />
        {data.known_exploited !== true && score == null && <span className="muted small">Sin datos</span>}
      </div>
      <dl className="fields">
        {data.known_exploited === true && (
          <>
            <Field label="Fuente KEV">{provenanceText(kev.source)}</Field>
            <Field label="Añadido a KEV">{provenanceText(kev.date_added)}</Field>
            <Field label="Fecha límite (KEV)">{provenanceText(kev.due_date)}</Field>
            <Field label="Uso en ransomware">{provenanceText(kev.known_ransomware_use)}</Field>
          </>
        )}
        {score != null && (
          <>
            <Field label="Fuente EPSS">{provenanceText(epss.source)}</Field>
            <Field label="Percentil EPSS">{provenanceText(epss.percentile)}</Field>
            <Field label="Fecha EPSS">{provenanceText(epss.score_date)}</Field>
          </>
        )}
      </dl>
      <p className="muted small">KEV y EPSS se leen de Threat Intelligence en cada consulta; no se copian al catálogo.</p>
    </section>
  );
}

/** Un CVE en el catálogo: un registro por fuente con la procedencia de cada atributo. */
export function CveDetailPage() {
  const { cveId = "" } = useParams();
  const valid = isCveId(cveId);
  const fetchCve = useCallback((signal: AbortSignal) => vulnSourcesApi.cve(cveId, signal), [cveId]);
  const { data, error, loading, refresh } = usePolling(fetchCve, config.refreshIntervalMs * 4, valid);

  const back = (
    <Link to="/vulnerabilities/catalog?tab=records" className="muted">
      ← Catálogo
    </Link>
  );
  if (!valid) {
    return (
      <div className="page">
        {back}
        <ErrorState message="Identificador de CVE no válido." />
      </div>
    );
  }
  if (loading) return <LoadingState label="Cargando CVE…" />;
  if (!data) {
    return (
      <div className="page">
        {back}
        <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />
      </div>
    );
  }
  return (
    <div className="page">
      {back}
      <div className="page__header">
        <div>
          <h1 className="vuln-id">{data.cve_id}</h1>
          <p className="muted small">
            {data.records.length === 1 ? "1 registro" : `${data.records.length} registros`} en el catálogo ·{" "}
            {data.findings.active} findings activos de {data.findings.total} en {data.findings.assets} activos
          </p>
        </div>
        {data.findings.total > 0 && (
          <div className="actions">
            <Link className="button" to={`/vulnerabilities?q=${encodeURIComponent(data.cve_id)}`}>
              Ver findings
            </Link>
          </div>
        )}
      </div>
      {error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}
      {data.records.length === 0 && (
        <div className="banner" role="note">
          Este CVE no está en el catálogo: solo hay datos de Threat Intelligence. Sentra no puede evaluarlo sin un
          registro con productos afectados.
        </div>
      )}
      {data.records.length > 1 && (
        <p className="muted small">
          Varias fuentes describen este CVE: el riesgo cuenta cada CVE una sola vez por componente.
        </p>
      )}
      <Exploitation data={data.exploitation} />
      {data.records.map((record) => (
        <RecordPanel key={`${record.source}-${record.vulnerability_id}`} record={record} detail={data} />
      ))}
    </div>
  );
}

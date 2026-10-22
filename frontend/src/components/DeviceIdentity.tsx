import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import type { Asset, ClassificationConfidence } from "../api/types";
import { formatDateTime } from "../lib/format";
import {
  NAME_SOURCE_LABELS,
  assetTitle,
  automaticTitle,
  confidenceLabel,
  evidenceLabel,
  nameStatusHelp,
  observedNameNote,
  osLabel,
  typeWithConfidence,
} from "../lib/identity";

const CONFIDENCE_CLASS: Record<ClassificationConfidence, string> = {
  low: "badge--warn",
  medium: "badge--info",
  high: "badge--ok",
};

export function ConfidenceBadge({ confidence }: { confidence: ClassificationConfidence | null }) {
  const label = confidenceLabel(confidence);
  if (!confidence || !label) return null;
  return (
    <span className={`badge ${CONFIDENCE_CLASS[confidence]}`} title="Confianza de la clasificación">
      {label}
    </span>
  );
}

/**
 * Nombre como dato principal y la IP debajo, como dato secundario. Las tablas con columna
 * de IP propia (ordenable) pasan showIp={false} para no repetirla.
 */
export function AssetName({
  asset,
  link = true,
  showIp = true,
  onEditLabel,
}: {
  asset: Asset;
  link?: boolean;
  showIp?: boolean;
  /** Corrección 6C: acceso rápido a la etiqueta (solo se pasa con assets:manage). */
  onEditLabel?: (asset: Asset) => void;
}) {
  const title = assetTitle(asset);
  const named = Boolean(asset.custom_label || asset.device_name || asset.hostname);
  // Con etiqueta, el nombre automático queda a la vista (en el tooltip y debajo).
  const automatic = asset.custom_label ? automaticTitle(asset) : null;
  // Fase 6D.3: sin nombre útil, el tooltip explica por qué (no es un fallo de Sentra).
  const why = asset.custom_label ? null : nameStatusHelp(asset.name_status);
  return (
    <div className="asset-name">
      {link ? (
        <Link
          to={`/assets/${asset.asset_id}`}
          className={named ? "strong" : "strong muted"}
          title={automatic ? `Etiqueta personalizada. Nombre automático: ${automatic}` : (why ?? undefined)}
        >
          {title}
        </Link>
      ) : (
        <span className="strong">{title}</span>
      )}
      {onEditLabel && (
        <button
          type="button"
          className="button button--small asset-name__edit"
          aria-label={`Editar etiqueta de ${title}`}
          onClick={(event) => {
            // La fila de la tabla navega al detalle: editar no debe hacerlo.
            event.stopPropagation();
            onEditLabel(asset);
          }}
        >
          {asset.custom_label ? "Editar" : "Etiquetar"}
        </button>
      )}
      {automatic && <div className="small muted">auto: {automatic}</div>}
      {showIp && <div className="mono small muted">{asset.primary_ip}</div>}
    </div>
  );
}

/** Tipo ("Consola probable") y fabricante del dispositivo, para tablas. */
export function DeviceTypeCell({ asset }: { asset: Asset }) {
  return (
    <div title={asset.device_type_reason ?? "No se puede determinar con la información disponible"}>
      {asset.device_type ? typeWithConfidence(asset) : <span className="muted">Desconocido</span>}
      {asset.device_vendor && <div className="small muted">{asset.device_vendor}</div>}
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

/**
 * Sección "Identificación" del detalle del activo. Solo muestra los campos que tienen
 * valor: un campo vacío no aporta y haría pensar que falta un dato que sí se buscó.
 */
export function IdentificationPanel({ asset }: { asset: Asset }) {
  const os = osLabel(asset);
  const evidence = asset.classification_evidence;
  return (
    <section className="panel" aria-label="Identificación">
      <div className="panel__toolbar">
        <h2>Identificación</h2>
        <span className="muted small">
          {asset.monitoring_method === "agent"
            ? "datos del agente como fuente principal"
            : "deducida de lo observable en la red"}
        </span>
      </div>
      <dl className="fields">
        {asset.custom_label && (
          <Row label="Etiqueta">
            {asset.custom_label}
            <span className="muted small">
              {" "}
              (personalizada
              {asset.custom_label_updated_by && ` por ${asset.custom_label_updated_by}`}
              {asset.custom_label_updated_at && `, ${formatDateTime(asset.custom_label_updated_at)}`})
            </span>
          </Row>
        )}
        <Row label={asset.custom_label ? "Nombre automático" : "Nombre"}>
          {automaticTitle(asset)}
          {asset.device_name && asset.name_source && (
            <span className="muted small"> ({NAME_SOURCE_LABELS[asset.name_source] ?? asset.name_source})</span>
          )}
          {!asset.custom_label && nameStatusHelp(asset.name_status) && (
            <div className="muted small" data-testid="name-status-help">
              {nameStatusHelp(asset.name_status)}
            </div>
          )}
        </Row>
        {asset.observed_names.length > 0 && (
          <Row label="Nombres observados">
            <ul className="plain-list small" aria-label="Nombres observados">
              {asset.observed_names.map((name) => (
                <li key={`${name.source}:${name.value}`}>
                  <span className={name.kind === "generic" || name.confirmed === false ? "muted" : undefined}>
                    {name.value}
                  </span>
                  {name.selected && (
                    <>
                      {" "}
                      <span className="badge badge--info">elegido</span>
                    </>
                  )}{" "}
                  <span className="muted">{observedNameNote(name)}</span>
                </li>
              ))}
            </ul>
          </Row>
        )}
        <Row label="IP">
          <span className="mono">{asset.primary_ip}</span>
        </Row>
        <Row label="Tipo">{typeWithConfidence(asset)}</Row>
        {asset.device_vendor && <Row label="Fabricante dispositivo">{asset.device_vendor}</Row>}
        {asset.device_model && <Row label="Modelo">{asset.device_model}</Row>}
        {asset.network_adapter_vendor && (
          <Row label="Fabricante NIC">
            <span title={asset.vendor ?? undefined}>{asset.network_adapter_vendor}</span>
          </Row>
        )}
        {os && <Row label={asset.os_name ? "SO" : "SO probable"}>{os}</Row>}
        {asset.classification_confidence && (
          <Row label="Confianza">
            <ConfidenceBadge confidence={asset.classification_confidence} />
          </Row>
        )}
        {evidence.length > 0 && (
          <Row label="Evidencias">
            <ul className="plain-list small" aria-label="Evidencias">
              {evidence.map((item) => (
                <li key={`${item.source}:${item.value}`}>{evidenceLabel(item)}</li>
              ))}
            </ul>
          </Row>
        )}
      </dl>
    </section>
  );
}

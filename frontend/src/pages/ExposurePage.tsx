import { useCallback, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { vulnerabilitiesApi } from "../api/sentra";
import { config } from "../config";
import { Pager, Toolbar } from "../components/ListControls";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { MatchBadge, VulnSeverityBadge } from "../components/vulnerabilities/VulnBadges";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { usePolling } from "../lib/usePolling";
import { EXPOSURE_LABEL_TEXT } from "../lib/vulnerabilities";

const PAGE_SIZE = 50;

/**
 * Exposición consolidada (Fase 5B): puertos observados por Discovery, contexto declarado del
 * activo y vulnerabilidades del servicio. Un puerto abierto no es una vulnerabilidad: aquí
 * solo se muestra lo observado, con etiquetas que dicen desde dónde.
 */
export function ExposurePage() {
  const [params] = useSearchParams();
  const assetId = params.get("asset") ?? undefined;
  const [sensitive, setSensitive] = useState(false);
  const [onlyNew, setOnlyNew] = useState(false);
  const [withVulns, setWithVulns] = useState(false);
  const [port, setPort] = useState("");
  const [page, setPage] = useState(1);

  const portNumber = Number.parseInt(port, 10);
  const validPort = Number.isInteger(portNumber) && portNumber >= 1 && portNumber <= 65535 ? portNumber : undefined;
  const fetchExposure = useCallback(
    (signal: AbortSignal) =>
      vulnerabilitiesApi.exposure(
        {
          sensitive,
          new: onlyNew,
          withVulnerabilities: withVulns,
          assetId,
          port: validPort,
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        },
        signal,
      ),
    [sensitive, onlyNew, withVulns, assetId, validPort, page],
  );
  const { data, error, loading, refresh } = usePolling(fetchExposure, config.refreshIntervalMs);
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE));
  const toggle = (setter: (value: boolean) => void) => (value: boolean) => {
    setter(value);
    setPage(1);
  };

  return (
    <div className="page">
      <Link to="/vulnerabilities" className="muted">
        ← Vulnerabilidades
      </Link>
      <div className="page__header">
        <div>
          <h1>Exposición</h1>
          <p className="muted small">
            Servicios observados desde el sensor de Sentra (LAN). Sentra no escanea desde Internet: "expuesto a Internet"
            solo aparece si el contexto del activo lo declara.
          </p>
        </div>
      </div>
      {assetId && (
        <div className="banner" role="note">
          Filtrado por un activo. <Link to="/vulnerabilities/exposure">Ver todos</Link>
        </div>
      )}
      <section className="panel">
        <Toolbar>
          <label className="form-field form-field--inline">
            <input type="checkbox" checked={sensitive} onChange={(e) => toggle(setSensitive)(e.target.checked)} />
            <span className="small">Solo puertos sensibles</span>
          </label>
          <label className="form-field form-field--inline">
            <input type="checkbox" checked={onlyNew} onChange={(e) => toggle(setOnlyNew)(e.target.checked)} />
            <span className="small">Solo nuevos</span>
          </label>
          <label className="form-field form-field--inline">
            <input type="checkbox" checked={withVulns} onChange={(e) => toggle(setWithVulns)(e.target.checked)} />
            <span className="small">Con vulnerabilidades</span>
          </label>
          <input
            className="input"
            inputMode="numeric"
            placeholder="Puerto"
            aria-label="Puerto"
            value={port}
            onChange={(e) => {
              setPort(e.target.value.replace(/\D/g, "").slice(0, 5));
              setPage(1);
            }}
          />
        </Toolbar>
        {error && data && (
          <div className="banner banner--warn" role="alert">
            Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
          </div>
        )}
        {loading ? (
          <LoadingState label="Cargando exposición…" />
        ) : !data && error ? (
          <ErrorState message={errorMessage(error)} onRetry={refresh} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState title="Sin servicios observados para este filtro" />
        ) : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Activo</th>
                    <th>Puerto</th>
                    <th>Servicio</th>
                    <th>Observación</th>
                    <th>Vulnerabilidades</th>
                    <th>Abierto desde</th>
                    <th>Última vez</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <tr key={`${item.asset.asset_id}-${item.protocol}-${item.port}`}>
                      <td>
                        <Link to={`/assets/${item.asset.asset_id}?tab=exposure`}>{item.asset.name}</Link>
                        <div className="muted small mono">{item.asset.primary_ip}</div>
                      </td>
                      <td className="mono">
                        {item.port}/{item.protocol}
                        {item.sensitive && <span className="badge badge--warn"> sensible</span>}
                        {item.new && <span className="badge badge--info"> nuevo</span>}
                      </td>
                      <td>
                        {item.service_hint ?? "—"}
                        {item.process && <div className="muted small">{item.process}</div>}
                      </td>
                      <td className="small">
                        {item.labels.map((label) => (
                          <div key={label}>{EXPOSURE_LABEL_TEXT[label] ?? label}</div>
                        ))}
                      </td>
                      <td>
                        {item.vulnerabilities.length === 0 ? (
                          <span className="muted">—</span>
                        ) : (
                          item.vulnerabilities.map((v) => (
                            <div key={v.finding_id}>
                              <Link className="vuln-id" to={`/vulnerabilities/${v.finding_id}`}>
                                {v.vulnerability_id}
                              </Link>{" "}
                              <VulnSeverityBadge severity={v.severity} /> <MatchBadge state={v.match_state} />
                            </div>
                          ))
                        )}
                        {item.vulnerabilities_total > item.vulnerabilities.length && (
                          <div className="muted small">
                            +{item.vulnerabilities_total - item.vulnerabilities.length} más
                          </div>
                        )}
                      </td>
                      <td title={formatDateTime(item.opened_at)}>{formatRelative(item.opened_at)}</td>
                      <td title={formatDateTime(item.last_seen_at)}>{formatRelative(item.last_seen_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={Math.min(page, pages)} pages={pages} total={data.total} onPage={setPage} noun="servicios" />
          </>
        )}
      </section>
    </div>
  );
}

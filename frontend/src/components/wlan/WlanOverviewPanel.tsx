import { Link } from "react-router-dom";
import type { WlanFindingCode, WlanOverview, WlanSourceStatus } from "../../api/types";
import { formatDateTime, formatRelative } from "../../lib/format";
import { AVAILABILITY_CLASS, availabilityLabel, describeSource, FINDING_LABELS } from "../../lib/wlan";
import { EmptyState } from "../StateViews";

export type WlanTab = "access-points" | "ssids" | "bss" | "clients";

/** True si el ámbito no tiene ni APs, ni BSS, ni clientes. */
export function overviewIsEmpty(overview: WlanOverview): boolean {
  return overview.access_points === 0 && overview.bss === 0 && overview.clients === 0 && overview.ssids === 0;
}

function SourceCard({ status }: { status: WlanSourceStatus }) {
  const text = describeSource(status);
  return (
    <article className="wlan-source" aria-label={`Fuente: ${text.title}`}>
      <div className="wlan-source__head">
        <span className="strong">{text.title}</span>
        <span className={AVAILABILITY_CLASS[status.availability] ?? "badge badge--muted"} title={status.detail}>
          {availabilityLabel(status.availability)}
        </span>
      </div>
      <p className="small">{text.explanation}</p>
      <p className="muted small">
        {text.reporters}
        {" · "}
        Última observación:{" "}
        {status.last_seen_at ? (
          <time dateTime={status.last_seen_at} title={formatDateTime(status.last_seen_at)}>
            {formatRelative(status.last_seen_at)}
          </time>
        ) : (
          "nunca"
        )}
      </p>
      {text.breakdown && <p className="muted small">{text.breakdown}</p>}
      {text.partialNote && (
        <p className="small" role="note">
          <span className="badge badge--warn">Consulta parcial</span> {text.partialNote}
        </p>
      )}
    </article>
  );
}

/** Explica cómo obtener datos Wi-Fi cuando el ámbito no tiene ninguno. */
export function WlanEmptyHelp() {
  return (
    <EmptyState title="Todavía no hay datos Wi-Fi en este ámbito">
      Sentra solo observa de forma pasiva. Hay dos fuentes: un sensor del site con la capacidad{" "}
      <span className="mono">snmp.wlan</span> (sensor 0.4.0 o posterior) que consulta por SNMP una controladora o un AP
      registrado en <Link to="/infrastructure">Infraestructura</Link> con un perfil SNMP; o agentes que envían el
      apartado Wi-Fi (<span className="mono">wireless</span>) de su inventario. Revisa los{" "}
      <Link to="/sensors">sensores</Link> y los <Link to="/agents">agentes</Link> del site.
    </EmptyState>
  );
}

const CARD_CLASS = "stat";

/**
 * Resumen del ámbito: recuentos, avisos de configuración insegura e indicadores de
 * disponibilidad de cada fuente. Las tarjetas abren la pestaña correspondiente.
 */
export function WlanOverviewPanel({
  overview,
  onOpenTab,
}: {
  overview: WlanOverview;
  onOpenTab: (tab: WlanTab, preset?: { insecure?: boolean }) => void;
}) {
  const empty = overviewIsEmpty(overview);
  const findings = Object.entries(overview.findings_by_code).filter(([, n]) => n > 0);
  const unknownAps = overview.access_points_by_authorization.unknown ?? 0;
  return (
    <>
      {!empty && (
        <section className="stats" aria-label="Resumen Wi-Fi">
          <button type="button" className={CARD_CLASS} onClick={() => onOpenTab("access-points")}>
            <span className="stat__label">Puntos de acceso</span>
            <span className="stat__value">{overview.access_points}</span>
            <span className="muted small">
              {overview.access_points_recent} con evidencia reciente · {unknownAps} sin clasificar
            </span>
          </button>
          <button type="button" className={CARD_CLASS} onClick={() => onOpenTab("ssids")}>
            <span className="stat__label">Redes (SSID)</span>
            <span className="stat__value">{overview.ssids}</span>
          </button>
          <button type="button" className={CARD_CLASS} onClick={() => onOpenTab("bss")}>
            <span className="stat__label">BSS</span>
            <span className="stat__value">{overview.bss}</span>
            <span className="muted small">
              {overview.bss_recent} recientes · {overview.bss_observed_only} solo observados por agentes
            </span>
          </button>
          <button type="button" className={CARD_CLASS} onClick={() => onOpenTab("clients")}>
            <span className="stat__label">Clientes</span>
            <span className="stat__value">{overview.clients}</span>
            <span className="muted small">{overview.clients_recent} con evidencia reciente</span>
          </button>
          <button
            type="button"
            className={`${CARD_CLASS}${overview.insecure_bss > 0 ? " stat--warn" : ""}`}
            onClick={() => onOpenTab("bss", { insecure: true })}
          >
            <span className="stat__label">Configuraciones inseguras</span>
            <span className="stat__value">{overview.insecure_bss}</span>
            <span className="muted small">BSS abiertos, WEP, WPA1 o TKIP</span>
          </button>
        </section>
      )}
      {findings.length > 0 && (
        <div className="banner banner--warn" role="note">
          <span className="strong">Configuraciones inseguras observadas (informativo):</span>{" "}
          {findings
            .map(([code, n]) => `${FINDING_LABELS[code as WlanFindingCode] ?? code}: ${n}`)
            .join(" · ")}
          . No modifican el riesgo de ningún activo ni disparan acciones; revisa la configuración de la red con su
          responsable.
        </div>
      )}
      <section className="panel" aria-label="Disponibilidad de datos Wi-Fi">
        <div className="panel__toolbar">
          <h2>Disponibilidad de datos</h2>
          <span className="muted small">Qué fuentes informan en este ámbito y cuándo lo hicieron por última vez.</span>
        </div>
        <div className="wlan-sources">
          {overview.sources.map((status) => (
            <SourceCard key={status.source} status={status} />
          ))}
        </div>
        {empty && <WlanEmptyHelp />}
      </section>
    </>
  );
}

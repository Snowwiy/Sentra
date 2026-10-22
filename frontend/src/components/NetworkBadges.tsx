import type { MonitoringMethod } from "../api/types";
import { hostForAddress, portService, serviceDestination, serviceUrl, type PortService } from "../lib/services";
import { CopyButton } from "./CopyButton";

/** DISCOVERED → MONITORED → MANAGED, as in the hybrid monitoring model. */
export const METHOD_LABELS: Record<MonitoringMethod, string> = {
  discovered: "Descubierto",
  agentless: "Monitorizado",
  agent: "Gestionado",
};

const METHOD_TITLES: Record<MonitoringMethod, string> = {
  discovered: "Encontrado en la red; solo se conoce lo observable desde la red",
  agentless: "Monitorizado en remoto sin agente",
  agent: "Con Sentra Agent instalado",
};

export function MethodBadge({ method }: { method: MonitoringMethod }) {
  return (
    <span className={`badge badge--method-${method}`} title={METHOD_TITLES[method]}>
      {METHOD_LABELS[method]}
    </span>
  );
}

// Los tipos de dispositivo y sus etiquetas viven en lib/identity (Fase 4E).
export { DEVICE_TYPE_LABELS, deviceTypeLabel } from "../lib/identity";

/**
 * Puertos abiertos con su servicio (Corrección 6C).
 *
 * - HTTP/HTTPS: enlace «Abrir» a http(s)://IP:PUERTO en una pestaña nueva, solo al pulsar.
 *   Los puertos alternativos (8080, 8443...) se marcan como «probable»: es lo habitual en
 *   ese puerto, no algo comprobado. Con un nombre DNS confirmado se ofrece además abrirlo
 *   por nombre (útil con certificados emitidos para el nombre), sin decir que el puerto
 *   "pertenece" a ese dominio.
 * - Resto: se nombra el protocolo si se conoce y se puede copiar el destino IP:PUERTO.
 *
 * Sin `address` (o si no es una IP válida) se muestran solo los números, como antes.
 */
export function PortList({
  ports,
  limit = 8,
  address,
  hostname = null,
  detailed = false,
}: {
  ports: number[];
  limit?: number;
  /** IP del activo; sin ella no hay enlaces ni destinos. */
  address?: string;
  /** Nombre DNS confirmado (lib/services confirmedHostname); null si no hay. */
  hostname?: string | null;
  /** Vista de detalle: una fila por puerto con el botón de copiar visible. */
  detailed?: boolean;
}) {
  if (ports.length === 0) return <span className="muted">—</span>;
  const shown = ports.slice(0, limit);
  const host = address ? hostForAddress(address) : null;
  const more = ports.length > limit && (
    <span className="muted small" title={ports.join(", ")}>
      {" "}
      +{ports.length - limit}
    </span>
  );
  if (host === null || !address) {
    return (
      <span className="mono small" title={ports.join(", ")}>
        {shown.join(", ")}
        {more}
      </span>
    );
  }
  return (
    <span className={detailed ? "port-services port-services--detailed" : "port-services"}>
      <ul className="port-services__list" aria-label="Puertos abiertos">
        {shown.map((port) => (
          <PortItem key={port} service={portService(port)} address={address} host={host} hostname={hostname} detailed={detailed} />
        ))}
      </ul>
      {more}
    </span>
  );
}

function PortItem({
  service,
  address,
  host,
  hostname,
  detailed,
}: {
  service: PortService;
  address: string;
  host: string;
  hostname: string | null;
  detailed: boolean;
}) {
  const { port, protocol, web, inferred } = service;
  const label = protocol ? `${port}/${protocol}${inferred ? "?" : ""}` : String(port);
  const title = inferred
    ? `${protocol} probable: es lo habitual en el puerto ${port}, no está comprobado`
    : protocol
      ? `${protocol} (puerto estándar)`
      : "Servicio desconocido";
  // Los clics no deben llegar a la fila de la tabla, que navega al detalle del activo.
  const stop = (event: { stopPropagation: () => void }) => event.stopPropagation();
  const url = web ? serviceUrl(web, host, port) : null;
  const byName = web && hostname ? serviceUrl(web, hostname, port) : null;
  const destination = serviceDestination(address, port);
  return (
    <li className="port-services__item">
      <span className="mono small" title={title}>
        {label}
      </span>
      {url ? (
        <>
          <a
            className="port-services__open"
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            onClick={stop}
            title={`Abrir ${url} en una pestaña nueva`}
            aria-label={`Abrir servicio ${protocol}${inferred ? " probable" : ""} en ${destination ?? address} (pestaña nueva)`}
          >
            Abrir servicio
          </a>
          {detailed && byName && (
            <a
              className="port-services__open small"
              href={byName}
              target="_blank"
              rel="noopener noreferrer"
              onClick={stop}
              title={`${hostname} resuelve a esta IP; el servicio puede responder distinto según el nombre`}
              aria-label={`Abrir servicio ${protocol} por el nombre ${hostname} (pestaña nueva)`}
            >
              por nombre
            </a>
          )}
        </>
      ) : (
        destination &&
        (detailed || protocol) && (
          <CopyButton
            text={destination}
            label={detailed ? "Copiar destino" : "Copiar"}
            ariaLabel={`Copiar destino ${protocol ?? "del puerto"} ${destination}`}
          />
        )
      )}
    </li>
  );
}

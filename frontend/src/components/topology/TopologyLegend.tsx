import type { TopologyCoverage } from "../../api/types";
import { deviceTypeLabel } from "../../lib/identity";
import {
  CONFIDENCE_LABELS,
  CONFIDENCE_OPACITY,
  LINK_KIND_HELP,
  LINK_KIND_LABELS,
  LINK_KINDS,
  LINK_STYLES,
  nodeFill,
  SHAPE_LABELS,
  shapePath,
  type NodeShape,
} from "../../lib/topology";

const SHAPES: NodeShape[] = ["square", "circle", "triangle", "diamond"];

/**
 * Leyenda: cada clase de enlace con su muestra de trazo y el nombre del patrón en texto, para
 * que se entienda sin distinguir colores; formas de nodo; confianza y estado.
 */
export function TopologyLegend() {
  return (
    <section className="panel panel--padded topo-legend" aria-label="Leyenda de la topología">
      <h2 className="panel__title">Leyenda</h2>
      <ul className="topo-legend__list" aria-label="Clases de enlace">
        {LINK_KINDS.map((kind) => {
          const style = LINK_STYLES[kind];
          return (
            <li key={kind} title={LINK_KIND_HELP[kind]}>
              <svg width="56" height="12" aria-hidden="true" focusable="false">
                <line
                  x1="2"
                  y1="6"
                  x2="54"
                  y2="6"
                  stroke={style.color}
                  strokeWidth={style.width}
                  strokeDasharray={style.dash || undefined}
                  strokeLinecap="round"
                />
              </svg>
              <span>
                {LINK_KIND_LABELS[kind]} <span className="muted small">· trazo {style.pattern}</span>
              </span>
            </li>
          );
        })}
      </ul>
      <ul className="topo-legend__list" aria-label="Formas de nodo">
        {SHAPES.map((shape) => (
          <li key={shape}>
            <svg width="24" height="24" aria-hidden="true" focusable="false">
              <path d={shapePath(shape, 12, 12, 8)} fill={nodeFill(null)} stroke="#e3e9f2" />
            </svg>
            <span className="small">{SHAPE_LABELS[shape]}</span>
          </li>
        ))}
      </ul>
      <p className="muted small">
        Confianza: alta ({Math.round(CONFIDENCE_OPACITY.high * 100)} % opaco, trazo más grueso), {CONFIDENCE_LABELS.medium}{" "}
        ({Math.round(CONFIDENCE_OPACITY.medium * 100)} %) y {CONFIDENCE_LABELS.low} ({Math.round(CONFIDENCE_OPACITY.low * 100)} %,
        trazo fino). Enlaces ausentes: casi transparentes. Rechazados: en rojo. Color del nodo: verde en línea, rojo
        fuera de línea, ámbar sin datos recientes, gris desconocido. Compartir red no es un enlace: las cajas solo
        agrupan.
      </p>
      <p className="muted small">
        Wi-Fi: asociación verificada (el agente informa del BSSID o un controlador lista el cliente). Va al punto de
        acceso si está inventariado; si no (p. ej. un router doméstico sin SNMP), a un nodo externo «Wi-Fi &lt;SSID&gt;».
        Un cliente con MAC privada sin correlacionar no se enlaza.
      </p>
    </section>
  );
}

const LIMITATION_TEXT: Record<string, string> = {
  nodes_without_link_evidence:
    "Hay nodos sin ninguna evidencia de conexión. Sentra no los une al gateway por estar en la misma subred: solo dibuja enlaces con LLDP/CDP, la tabla FDB de un switch gestionable, una asociación Wi-Fi verificada o el gateway que informa un agente.",
  no_physical_link_evidence:
    "No hay enlaces físicos confirmados: ningún switch gestionable aporta LLDP/CDP ni tabla FDB (un router doméstico como el Archer GX90 no los ofrece sin SNMP).",
  access_point_not_inventoried:
    "Algunas asociaciones Wi-Fi apuntan a un BSS cuyo punto de acceso no está inventariado: el enlace es verificado, el AP no.",
};

/** Fase 7B-Fix1: cobertura del grafo y sus límites, explícitos y sin enlaces inventados. */
export function TopologyCoverageNotice({ coverage }: { coverage: TopologyCoverage }) {
  if (coverage.limitations.length === 0) return null;
  const byType = Object.entries(coverage.unlinked_by_type ?? {})
    .map(([type, count]) => `${count} ${type === "unknown" ? "sin tipo" : deviceTypeLabel(type)}`)
    .join(", ");
  return (
    <div className="banner" role="note" aria-label="Cobertura de la topología">
      <strong>
        {coverage.nodes_without_links} de {coverage.nodes} nodos sin enlace
      </strong>
      {byType && <span className="small"> ({byType})</span>}
      <ul className="plain-list small">
        {coverage.limitations.map((code) => (
          <li key={code}>{LIMITATION_TEXT[code] ?? code}</li>
        ))}
      </ul>
    </div>
  );
}

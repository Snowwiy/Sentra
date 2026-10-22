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
    </section>
  );
}

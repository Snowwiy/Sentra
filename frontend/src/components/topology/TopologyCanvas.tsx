import {
  memo,
  useCallback,
  useEffect,
  useImperativeHandle,
  useRef,
  type KeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type PointerEvent as ReactPointerEvent,
  type Ref,
} from "react";
import type { TopologyLink, TopologyNode } from "../../api/types";
import {
  CONFIDENCE_OPACITY,
  CONFIDENCE_WIDTH,
  LINK_STYLES,
  NODE_KIND_LABELS,
  NODE_RADIUS,
  nodeFill,
  nodeShape,
  nodeTitle,
  shapePath,
  truncate,
  type Layout,
} from "../../lib/topology";

/** Por debajo de este zoom se ocultan las etiquetas: con cientos de nodos solo serían ruido. */
export const LABEL_MIN_ZOOM = 0.55;
const MIN_ZOOM = 0.08;
const MAX_ZOOM = 4;

export interface CanvasHandle {
  zoomBy: (factor: number) => void;
  fit: () => void;
}

interface View {
  x: number;
  y: number;
  k: number;
}

/**
 * Capa de enlaces. Memoizada y con un único manejador delegado (data-link-id): con 5000
 * enlaces no se crean 5000 funciones, y el arrastre o el zoom no la vuelven a renderizar
 * porque la transformación se aplica directamente al <g> contenedor.
 */
const LinkLayer = memo(function LinkLayer({ links, layout }: { links: TopologyLink[]; layout: Layout }) {
  return (
    <g className="topo-links">
      {links.map((link) => {
        const a = layout.positions.get(link.source);
        const b = layout.positions.get(link.target);
        if (!a || !b) return null;
        const style = LINK_STYLES[link.kind];
        const width = style.width + CONFIDENCE_WIDTH[link.confidence];
        return (
          <g key={link.id} data-link-id={link.id} className="topo-link">
            {/* Trazo ancho transparente: zona de clic cómoda sobre una línea fina. */}
            <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} className="topo-link__hit" />
            <line
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke={link.review_state === "rejected" ? "#ef4444" : style.color}
              strokeWidth={width}
              strokeOpacity={link.present ? CONFIDENCE_OPACITY[link.confidence] : 0.3}
              strokeDasharray={style.dash || undefined}
              strokeLinecap="round"
              data-kind={link.kind}
              data-confidence={link.confidence}
            />
          </g>
        );
      })}
    </g>
  );
});

function nodeAria(node: TopologyNode): string {
  const parts = [nodeTitle(node), NODE_KIND_LABELS[node.kind]];
  if (node.ip) parts.push(`IP ${node.ip}`);
  if (node.status) parts.push(`estado ${node.status}`);
  parts.push(`${node.link_count} enlaces`);
  return parts.join(", ");
}

/** Capa de nodos: memoizada; cada nodo es tabulable (Enter o espacio lo seleccionan). */
const NodeLayer = memo(function NodeLayer({
  nodes,
  layout,
  matches,
}: {
  nodes: TopologyNode[];
  layout: Layout;
  matches: Set<string>;
}) {
  return (
    <g className="topo-nodes">
      {nodes.map((node) => {
        const p = layout.positions.get(node.id);
        if (!p) return null;
        const match = matches.has(node.id);
        return (
          <g
            key={node.id}
            data-node-id={node.id}
            className={`topo-node${match ? " topo-node--match" : ""}`}
            role="button"
            tabIndex={0}
            aria-label={nodeAria(node)}
          >
            {match && <circle cx={p.x} cy={p.y} r={NODE_RADIUS + 7} className="topo-node__match" />}
            <path
              d={shapePath(nodeShape(node), p.x, p.y, NODE_RADIUS)}
              fill={nodeFill(node.status)}
              className="topo-node__shape"
            />
            <text x={p.x} y={p.y + NODE_RADIUS + 15} className="topo-label" textAnchor="middle">
              {truncate(nodeTitle(node), 22)}
            </text>
          </g>
        );
      })}
    </g>
  );
});

/** Resalta la selección encima de las capas memoizadas (seleccionar no re-renderiza el grafo). */
function SelectionLayer({
  layout,
  selectedNode,
  selectedLink,
}: {
  layout: Layout;
  selectedNode: string | undefined;
  selectedLink: TopologyLink | undefined;
}) {
  const p = selectedNode ? layout.positions.get(selectedNode) : undefined;
  const a = selectedLink ? layout.positions.get(selectedLink.source) : undefined;
  const b = selectedLink ? layout.positions.get(selectedLink.target) : undefined;
  return (
    <g className="topo-selection" aria-hidden="true">
      {a && b && <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} className="topo-selection__link" />}
      {p && <circle cx={p.x} cy={p.y} r={NODE_RADIUS + 9} className="topo-selection__node" />}
    </g>
  );
}

/**
 * Lienzo SVG de la topología con zoom (rueda y botones) y arrastre. La vista (x, y, zoom) vive
 * en una ref y se aplica al <g> con setAttribute dentro de requestAnimationFrame: durante el
 * arrastre React no renderiza nada, ni siquiera este componente.
 */
export function TopologyCanvas({
  nodes,
  links,
  layout,
  matches,
  selectedNode,
  selectedLink,
  onSelectNode,
  onSelectLink,
  handleRef,
}: {
  nodes: TopologyNode[];
  links: TopologyLink[];
  layout: Layout;
  matches: Set<string>;
  selectedNode: string | undefined;
  selectedLink: TopologyLink | undefined;
  onSelectNode: (id: string) => void;
  onSelectLink: (id: string) => void;
  handleRef?: Ref<CanvasHandle>;
}) {
  const svgRef = useRef<SVGSVGElement>(null);
  const viewportRef = useRef<SVGGElement>(null);
  const view = useRef<View>({ x: 0, y: 0, k: 1 });
  const frame = useRef<number | null>(null);
  const drag = useRef<{ x: number; y: number; vx: number; vy: number; moved: boolean; id: number } | null>(null);
  const suppressClick = useRef(false);

  const apply = useCallback(() => {
    if (frame.current !== null) return;
    const run = () => {
      frame.current = null;
      const { x, y, k } = view.current;
      viewportRef.current?.setAttribute("transform", `translate(${x} ${y}) scale(${k})`);
      svgRef.current?.classList.toggle("topo--far", k < LABEL_MIN_ZOOM);
    };
    if (typeof window.requestAnimationFrame === "function") frame.current = window.requestAnimationFrame(run);
    else run();
  }, []);

  const size = useCallback(() => {
    const rect = svgRef.current?.getBoundingClientRect();
    return { w: rect && rect.width > 0 ? rect.width : 800, h: rect && rect.height > 0 ? rect.height : 560 };
  }, []);

  const fit = useCallback(() => {
    const { w, h } = size();
    const k = Math.max(MIN_ZOOM, Math.min(1.5, Math.min((w - 40) / layout.width, (h - 40) / layout.height)));
    view.current = { k, x: (w - layout.width * k) / 2, y: Math.max(20, (h - layout.height * k) / 2) };
    apply();
  }, [apply, layout.height, layout.width, size]);

  const zoomAt = useCallback(
    (factor: number, cx?: number, cy?: number) => {
      const { w, h } = size();
      const px = cx ?? w / 2;
      const py = cy ?? h / 2;
      const current = view.current;
      const k = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, current.k * factor));
      const ratio = k / current.k;
      view.current = { k, x: px - (px - current.x) * ratio, y: py - (py - current.y) * ratio };
      apply();
    },
    [apply, size],
  );

  useImperativeHandle(handleRef, () => ({ zoomBy: (f: number) => zoomAt(f), fit }), [fit, zoomAt]);

  // Encaje inicial y al cambiar la distribución (otro site, otra agrupación, otros filtros).
  useEffect(() => {
    fit();
  }, [fit]);

  useEffect(
    () => () => {
      if (frame.current !== null && typeof window.cancelAnimationFrame === "function") {
        window.cancelAnimationFrame(frame.current);
      }
      // Sin esto, tras un desmontaje y montaje (StrictMode en desarrollo) `apply` creería que
      // hay un frame pendiente y no volvería a aplicar la vista nunca.
      frame.current = null;
    },
    [],
  );

  // La rueda necesita un listener no pasivo para evitar que la página haga scroll a la vez.
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      const rect = svg.getBoundingClientRect();
      zoomAt(event.deltaY < 0 ? 1.15 : 1 / 1.15, event.clientX - rect.left, event.clientY - rect.top);
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, [zoomAt]);

  const onPointerDown = (event: ReactPointerEvent<SVGSVGElement>) => {
    if (event.button !== 0) return;
    drag.current = { x: event.clientX, y: event.clientY, vx: view.current.x, vy: view.current.y, moved: false, id: event.pointerId };
  };
  const onPointerMove = (event: ReactPointerEvent<SVGSVGElement>) => {
    const d = drag.current;
    if (!d || d.id !== event.pointerId) return;
    const dx = event.clientX - d.x;
    const dy = event.clientY - d.y;
    if (!d.moved && Math.hypot(dx, dy) < 4) return;
    if (!d.moved) {
      d.moved = true;
      svgRef.current?.setPointerCapture?.(event.pointerId);
      svgRef.current?.classList.add("topo--dragging");
    }
    view.current = { ...view.current, x: d.vx + dx, y: d.vy + dy };
    apply();
  };
  const endDrag = (event: ReactPointerEvent<SVGSVGElement>) => {
    const d = drag.current;
    if (!d || d.id !== event.pointerId) return;
    // Un arrastre no debe acabar seleccionando el nodo sobre el que se soltó.
    suppressClick.current = d.moved;
    drag.current = null;
    svgRef.current?.classList.remove("topo--dragging");
  };

  const targetOf = (element: EventTarget | null): { node?: string; link?: string } => {
    const el = element instanceof Element ? element.closest("[data-node-id],[data-link-id]") : null;
    if (!el) return {};
    return { node: el.getAttribute("data-node-id") ?? undefined, link: el.getAttribute("data-link-id") ?? undefined };
  };

  const onClick = (event: ReactMouseEvent<SVGSVGElement>) => {
    if (suppressClick.current) {
      suppressClick.current = false;
      return;
    }
    const { node, link } = targetOf(event.target);
    if (node) onSelectNode(node);
    else if (link) onSelectLink(link);
  };

  const onKeyDown = (event: KeyboardEvent<SVGSVGElement>) => {
    const { node } = targetOf(event.target);
    if (node && (event.key === "Enter" || event.key === " ")) {
      event.preventDefault();
      onSelectNode(node);
      return;
    }
    // Atajos del lienzo: + / - zoom, 0 encajar, flechas desplazar.
    const step = 60;
    const moves: Record<string, [number, number]> = {
      ArrowLeft: [step, 0],
      ArrowRight: [-step, 0],
      ArrowUp: [0, step],
      ArrowDown: [0, -step],
    };
    if (event.key === "+" || event.key === "=") zoomAt(1.2);
    else if (event.key === "-") zoomAt(1 / 1.2);
    else if (event.key === "0") fit();
    else if (moves[event.key] && event.target === svgRef.current) {
      const [dx, dy] = moves[event.key] ?? [0, 0];
      view.current = { ...view.current, x: view.current.x + dx, y: view.current.y + dy };
      apply();
    } else return;
    event.preventDefault();
  };

  return (
    <svg
      ref={svgRef}
      className="topo-canvas"
      role="group"
      aria-label="Mapa de topología. Tabulador recorre los nodos; Enter selecciona. Teclas + y - para zoom, 0 para encajar y flechas para desplazar."
      tabIndex={0}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      onClick={onClick}
      onKeyDown={onKeyDown}
      data-testid="topology-canvas"
    >
      <g ref={viewportRef}>
        <g className="topo-boxes" aria-hidden="true">
          {layout.boxes.map((box) => (
            <g key={box.id}>
              <rect x={box.x} y={box.y} width={box.width} height={box.height} rx={10} className="topo-box" />
              <text x={box.x + 12} y={box.y + 20} className="topo-box__label">
                {box.label} ({box.count})
              </text>
            </g>
          ))}
        </g>
        <LinkLayer links={links} layout={layout} />
        <NodeLayer nodes={nodes} layout={layout} matches={matches} />
        <SelectionLayer layout={layout} selectedNode={selectedNode} selectedLink={selectedLink} />
      </g>
    </svg>
  );
}

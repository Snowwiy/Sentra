import {
  type CausalLink,
  correlationInfo,
  type ServiceClassInfo,
  serviceDetectionInfo,
  temporalContext,
  MISSING_CONTEXT_LABELS,
  portExposureInfo,
  scriptInfo,
  SENTRA_COMPONENT_LABELS,
  SEQUENCE_LABELS,
  type Fields,
  type ScriptInfo,
} from "../../lib/detectionDetails";

function FieldList({ items, label }: { items: Fields; label: string }) {
  if (items.length === 0) return null;
  return (
    <dl className="fields" aria-label={label}>
      {items.map(([name, value]) => (
        <div className="field" key={name}>
          <dt>{name}</dt>
          <dd className="mono break-all">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function Explanation({ items }: { items: string[] }) {
  if (items.length === 0) return null;
  return (
    <>
      <h3>Explicación</h3>
      <ul className="recommendations" aria-label="Explicación">
        {items.map((text) => (
          <li key={text}>{text}</li>
        ))}
      </ul>
    </>
  );
}

/** Aviso de relación con Sentra: un nombre o una línea de comandos no prueban el origen. */
function SentraHint({ nameMatch, component }: { nameMatch: boolean; component: string | null }) {
  if (!nameMatch && !component) return null;
  return (
    <div className="banner banner--warn" role="note" aria-label="Relación con Sentra">
      {nameMatch && "El nombre coincide con un script de Sentra. "}
      {component && `La línea de comandos corresponde a ${SENTRA_COMPONENT_LABELS[component] ?? component}. `}
      Un nombre no prueba nada: compare la ruta y el SHA-256 con los de su instalación antes de descartarlo.
    </div>
  );
}

function MissingContext({ items }: { items: string[] }) {
  if (items.length === 0) return null;
  return (
    <>
      <h3>Contexto que falta</h3>
      <ul className="plain-list small" aria-label="Contexto que falta">
        {items.map((code) => (
          <li key={code}>{MISSING_CONTEXT_LABELS[code] ?? code}</li>
        ))}
      </ul>
    </>
  );
}

function ServiceClass({ info }: { info: ServiceClassInfo | null }) {
  if (!info) return null;
  return (
    <div className="stack" aria-label="Clasificación del servicio">
      <h3>Clasificación del servicio</h3>
      <FieldList
        items={[
          ["Tipo", info.kind],
          ["Verificación", info.verification],
        ]}
        label="Clasificación"
      />
      {info.checks.length > 0 && <FieldList items={info.checks} label="Comprobaciones" />}
      {info.explanation && <p className="small">{info.explanation}</p>}
    </div>
  );
}

function CausalLinks({ links }: { links: CausalLink[] }) {
  if (links.length === 0) return null;
  return (
    <>
      <h3>Relación causal</h3>
      <ul className="plain-list small" aria-label="Relación causal">
        {links.map((link) => (
          <li key={link.code}>
            <strong>{link.label}</strong>
            {link.strength === "strong" ? " (evidencia fuerte)" : " (evidencia media)"}
            {link.detail && `: ${link.detail}`}
          </li>
        ))}
      </ul>
    </>
  );
}

function ScriptBlock({ info, title }: { info: ScriptInfo; title?: string }) {
  const process = [...info.process];
  if (info.pid) process.push(["PID", info.pid]);
  if (info.userSid) process.push(["SID del usuario", info.userSid]);
  return (
    <div className="stack">
      {title && <h3>{title}</h3>}
      <h4>Script</h4>
      {info.script.length > 0 ? (
        <FieldList items={info.script} label="Script" />
      ) : (
        <p className="muted small">Sin datos del script.</p>
      )}
      <h4>Proceso</h4>
      {process.length > 0 ? (
        <FieldList items={process} label="Proceso" />
      ) : (
        <p className="muted small">No se conoce el proceso que lo ejecutó.</p>
      )}
      <h4>Por qué lo marcó PowerShell</h4>
      <p className="small">
        Evento 4104 de nivel Warning: el propio motor de PowerShell marcó el bloque como sospechoso. Sentra no recoge el
        contenido.
        {info.keywords.length > 0 && (
          <>
            {" "}
            Palabras: <span className="mono">{info.keywords.join(", ")}</span>.
          </>
        )}
      </p>
      <SentraHint nameMatch={info.sentraNameMatch} component={info.sentraComponent} />
      <MissingContext items={info.missing} />
    </div>
  );
}

/** Servicios cerca del script sin relación causal: contexto, no causa (Fase 7B-Fix1). */
function TemporalContext({ raw }: { raw: unknown }) {
  const items = temporalContext(raw);
  if (items.length === 0) return null;
  return (
    <>
      <h3>Contexto temporal (sin relación causal)</h3>
      <ul className="plain-list small" aria-label="Contexto temporal">
        {items.map((item, index) => (
          <li key={`${item.service}-${index}`}>
            <span className="mono">{item.service}</span>: {item.source}, {item.minutes} min {item.position}
            {item.verification && ` · ${item.verification}`}
          </li>
        ))}
      </ul>
    </>
  );
}

/**
 * Detalle estructurado de SCR-001, CORR-002 y NET-001 (Fase 7A.8): qué script o puerto, qué
 * proceso, por qué saltó y qué contexto faltó. Solo lectura y como texto plano.
 */
export function RuleDetailsPanel({ ruleId, details }: { ruleId: string; details: Record<string, unknown> | null }) {
  if (!details) return null;
  if (ruleId === "SCR-001") {
    const info = scriptInfo(details);
    return (
      <section className="panel panel--padded stack" aria-label="Detalle del script">
        <h2>Detalle del script</h2>
        <ScriptBlock info={info} />
        <TemporalContext raw={details.temporal_context} />
        <Explanation items={info.explanation} />
      </section>
    );
  }
  if (ruleId === "PER-001") {
    const info = serviceDetectionInfo(details);
    return (
      <section className="panel panel--padded stack" aria-label="Detalle del servicio">
        <h2>Servicio</h2>
        <FieldList items={info.service} label="Servicio" />
        <ServiceClass info={info.classification} />
        <Explanation items={info.explanation} />
      </section>
    );
  }
  if (ruleId === "CORR-002") {
    const info = correlationInfo(details);
    return (
      <section className="panel panel--padded stack" aria-label="Detalle de la secuencia">
        <h2>PowerShell y servicio nuevo</h2>
        {info.sequence && (
          <p>
            <strong>Secuencia:</strong> {SEQUENCE_LABELS[info.sequence] ?? info.sequence}
          </p>
        )}
        {info.review && (
          <div className="banner" role="note" aria-label="Revisión de la correlación">
            <strong>Revisada:</strong> {info.review.verdict}
            {info.review.actor && ` · ${info.review.actor}`}. {info.review.explanation.join(" ")}
          </div>
        )}
        <FieldList items={info.counts} label="Recuentos" />
        <CausalLinks links={info.links} />
        <h3>Persistencia</h3>
        <FieldList items={info.persistence} label="Persistencia" />
        <ServiceClass info={info.classification} />
        {info.sentraServiceName && (
          <div className="banner banner--warn" role="note">
            El servicio se llama como uno de Sentra. El nombre no prueba el origen: compare la ruta del ejecutable con la de
            su instalación.
          </div>
        )}
        {info.scripts.map((script, index) => (
          <ScriptBlock key={index} info={script} title={`Script ${index + 1} de ${info.scripts.length}`} />
        ))}
        <Explanation items={info.explanation} />
      </section>
    );
  }
  if (ruleId === "NET-001") {
    const info = portExposureInfo(details);
    return (
      <section className="panel panel--padded stack" aria-label="Detalle del puerto">
        <h2>
          Puerto {info.port}/tcp{info.serviceHint && ` (${info.serviceHint})`}
          {info.sensitive && <span className="badge badge--crit">sensible</span>}
        </h2>
        <h3>Proceso que escucha</h3>
        {info.owner.length > 0 ? (
          <FieldList items={info.owner} label="Proceso que escucha" />
        ) : (
          <p className="muted small">Sin agente o sin inventario de conexiones: no se sabe qué proceso escucha.</p>
        )}
        <SentraHint nameMatch={false} component={info.sentraComponent} />
        <Explanation items={info.explanation} />
      </section>
    );
  }
  return null;
}

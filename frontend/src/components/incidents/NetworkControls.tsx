// Solicitudes de control de red de un caso (Fase 7A.6). Proponen una restricción (puerto,
// servicio, dirección, dominio, sitio o subidas) y piden la decisión de un admin. Sentra NO
// aplica nada en la red: aprobar registra la decisión y explica qué punto de control haría
// falta; si alguien lo aplica fuera de Sentra, un admin lo deja registrado.
import { useCallback, useState, type FormEvent } from "react";
import { networkControlsApi } from "../../api/caseOperations";
import type {
  ControlCapabilities,
  ControlDirection,
  IncidentDetail,
  NetworkControlRead,
  NetworkControlType,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { config } from "../../config";
import {
  buildTarget,
  CONTROL_STATUS_BADGES,
  CONTROL_STATUS_LABELS,
  CONTROL_TYPE_LABELS,
  describeTarget,
  DIRECTION_LABELS,
  DIRECTIONAL_CONTROLS,
  EMPTY_TARGET,
  ENFORCEMENT_LABELS,
  isVersionConflict,
  type ControlTargetForm,
} from "../../lib/caseOperations";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { useSite } from "../../site/SiteContext";
import { Modal } from "../Modal";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";

const MAX_EXPIRY_DAYS = 365;
const toMessage = (err: unknown) => (err instanceof Error ? errorMessage(err) : String(err));
type Run = (action: () => Promise<unknown>) => Promise<boolean>;

/** Aviso fijo: lo que Sentra hace y no hace con estas solicitudes. */
export function NoEnforcementNotice({ capabilities }: { capabilities: ControlCapabilities | undefined }) {
  return (
    <div className="banner" role="note" aria-label="Sentra no aplica controles de red">
      <strong>Sentra no aplica nada en la red.</strong> Aprobar una solicitud registra la decisión y la deja en el caso
      y en la auditoría; no cambia ningún firewall, proxy ni DNS.{" "}
      {capabilities === undefined
        ? "Consultando los puntos de control instalados…"
        : capabilities.any_available
          ? "Hay puntos de control instalados para algunos tipos (ver abajo)."
          : "Puntos de control instalados: ninguno."}
      {capabilities && capabilities.items.length > 0 && (
        <details className="small">
          <summary>Qué haría falta para aplicar cada tipo</summary>
          <ul className="plain-list" aria-label="Puntos de control por tipo">
            {capabilities.items.map((item) => (
              <li key={item.control_type}>
                <strong>{CONTROL_TYPE_LABELS[item.control_type]}:</strong>{" "}
                {item.available ? `disponible (${item.points.join(", ")})` : "sin punto de control"}. {item.needs}{" "}
                <span className="muted">{item.note}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

function TargetFields({
  type,
  form,
  onChange,
}: {
  type: NetworkControlType;
  form: ControlTargetForm;
  onChange: (changes: Partial<ControlTargetForm>) => void;
}) {
  const input = (key: keyof ControlTargetForm, label: string, placeholder: string, mono = true) => (
    <label key={key}>
      <span className="muted small">{label}</span>
      <input
        className={`input${mono ? " mono" : ""}`}
        value={form[key]}
        placeholder={placeholder}
        onChange={(e) => onChange({ [key]: e.target.value })}
        aria-label={label}
      />
    </label>
  );
  switch (type) {
    case "block_port":
      return (
        <div className="actions">
          {input("port", "Puerto", "445")}
          <label>
            <span className="muted small">Protocolo</span>
            <select
              className="input input--select"
              value={form.protocol}
              onChange={(e) => onChange({ protocol: e.target.value as "tcp" | "udp" })}
              aria-label="Protocolo"
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </label>
        </div>
      );
    case "block_service":
      return (
        <div className="actions">
          {input("service", "Servicio", "smb")}
          {input("port", "Puerto (opcional)", "445")}
        </div>
      );
    case "block_address":
      return input("cidr", "Dirección o red (CIDR)", "203.0.113.0/24");
    case "block_domain":
    case "restrict_site_access":
      return input("domain", "Dominio", "*.ejemplo.com");
    case "prevent_upload":
      return input("destination", "Destino", "subidas.ejemplo.com");
  }
}

type Scope = "asset" | "site" | "global";

function RequestControlDialog({
  incident,
  capabilities,
  run,
  onClose,
}: {
  incident: IncidentDetail;
  capabilities: ControlCapabilities | undefined;
  run: Run;
  onClose: () => void;
}) {
  const site = useSite();
  const [type, setType] = useState<NetworkControlType>("block_port");
  const [form, setForm] = useState<ControlTargetForm>(EMPTY_TARGET);
  const [direction, setDirection] = useState<ControlDirection | "">("");
  const [scope, setScope] = useState<Scope>("asset");
  const assets = incident.asset_refs.filter((asset) => asset.exists);
  const [assetId, setAssetId] = useState(assets[0]?.asset_id ?? "");
  const [siteId, setSiteId] = useState(site.scopeId ?? site.selectableSites[0]?.site_id ?? "");
  const [expires, setExpires] = useState("");
  const [justification, setJustification] = useState("");
  const [busy, setBusy] = useState(false);
  const [submitError, setSubmitError] = useState<string>();

  const directional = DIRECTIONAL_CONTROLS.has(type);
  const built = buildTarget(type, form);
  const errors = "errors" in built ? [...built.errors] : [];
  if (directional && !direction) errors.push("Indica el sentido del tráfico.");
  if (scope === "asset" && !assetId) errors.push("Elige el activo del caso.");
  if (scope === "site" && !siteId) errors.push("Elige el site.");
  if (justification.trim().length < 10) errors.push("La justificación necesita al menos 10 caracteres.");
  const expiresAt = expires ? new Date(expires) : undefined;
  if (expiresAt && Number.isNaN(expiresAt.getTime())) errors.push("La caducidad no es válida.");
  const capability = capabilities?.items.find((item) => item.control_type === type);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (errors.length || !("target" in built)) return;
    // La caducidad se comprueba al enviar: «ahora» cambia mientras el formulario está abierto.
    if (expiresAt) {
      const now = Date.now();
      if (expiresAt.getTime() <= now) return setSubmitError("La caducidad debe ser una fecha futura.");
      if (expiresAt.getTime() > now + MAX_EXPIRY_DAYS * 86_400_000) {
        return setSubmitError(`La caducidad no puede superar ${MAX_EXPIRY_DAYS} días.`);
      }
    }
    setSubmitError(undefined);
    setBusy(true);
    const ok = await run(() =>
      networkControlsApi.request(incident.incident_id, {
        control_type: type,
        target: built.target,
        direction: directional ? (direction as ControlDirection) : null,
        asset_id: scope === "asset" ? assetId : null,
        site_id: scope === "site" ? siteId : null,
        justification: justification.trim(),
        expires_at: expiresAt ? expiresAt.toISOString() : null,
      }),
    );
    setBusy(false);
    if (ok) onClose();
  }

  return (
    <Modal title="Solicitar control de red" onClose={busy ? () => undefined : onClose} wide>
      <form className="incident-form" onSubmit={(e) => void submit(e)} noValidate>
        <div className="banner" role="note">
          Es una solicitud para que un administrador decida. Ni pedirla ni aprobarla aplica nada en la red.
        </div>
        <label>
          <span className="muted small">Tipo de control</span>
          <select
            className="input input--select"
            value={type}
            onChange={(e) => {
              setType(e.target.value as NetworkControlType);
              setDirection("");
            }}
            aria-label="Tipo de control"
          >
            {(Object.keys(CONTROL_TYPE_LABELS) as NetworkControlType[]).map((value) => (
              <option key={value} value={value}>
                {CONTROL_TYPE_LABELS[value]}
              </option>
            ))}
          </select>
        </label>
        <TargetFields type={type} form={form} onChange={(changes) => setForm((f) => ({ ...f, ...changes }))} />
        {directional ? (
          <label>
            <span className="muted small">Sentido</span>
            <select
              className="input input--select"
              value={direction}
              onChange={(e) => setDirection(e.target.value as ControlDirection | "")}
              aria-label="Sentido"
            >
              <option value="">Elige el sentido</option>
              {(Object.keys(DIRECTION_LABELS) as ControlDirection[]).map((value) => (
                <option key={value} value={value}>
                  {DIRECTION_LABELS[value]}
                </option>
              ))}
            </select>
          </label>
        ) : (
          <p className="muted small">Sentido: saliente (este tipo solo se aplica al tráfico saliente).</p>
        )}
        <fieldset className="form-field">
          <legend className="muted small">Alcance</legend>
          <label className="checkbox small">
            <input type="radio" name="scope" checked={scope === "asset"} onChange={() => setScope("asset")} /> Un activo del
            caso
          </label>
          {scope === "asset" && (
            <select
              className="input input--select"
              value={assetId}
              onChange={(e) => setAssetId(e.target.value)}
              aria-label="Activo del alcance"
            >
              <option value="">Elige un activo</option>
              {assets.map((asset) => (
                <option key={asset.asset_id} value={asset.asset_id}>
                  {asset.name}
                </option>
              ))}
            </select>
          )}
          <label className="checkbox small">
            <input type="radio" name="scope" checked={scope === "site"} onChange={() => setScope("site")} /> Un site
          </label>
          {scope === "site" && (
            <select
              className="input input--select"
              value={siteId}
              onChange={(e) => setSiteId(e.target.value)}
              aria-label="Site del alcance"
            >
              <option value="">Elige un site</option>
              {site.selectableSites.map((s) => (
                <option key={s.site_id} value={s.site_id}>
                  {s.name}
                </option>
              ))}
            </select>
          )}
          <label className="checkbox small">
            <input type="radio" name="scope" checked={scope === "global"} onChange={() => setScope("global")} /> Toda la
            instalación
          </label>
        </fieldset>
        <label>
          <span className="muted small">Caduca (opcional, máximo {MAX_EXPIRY_DAYS} días)</span>
          <input
            className="input"
            type="datetime-local"
            value={expires}
            onChange={(e) => setExpires(e.target.value)}
            aria-label="Caducidad de la solicitud"
          />
        </label>
        <label>
          <span className="muted small">Justificación (mínimo 10 caracteres)</span>
          <textarea
            className="input"
            maxLength={5000}
            rows={3}
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
            aria-label="Justificación"
          />
        </label>
        {capability && (
          <p className="muted small" aria-label="Qué haría falta">
            Para aplicarlo haría falta: {capability.needs} {capability.note}
          </p>
        )}
        {errors.length > 0 && (form !== EMPTY_TARGET || justification) && (
          <ul className="plain-list small text-crit" aria-label="Problemas de la solicitud">
            {errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        )}
        {submitError && (
          <div className="banner banner--warn" role="alert">
            {submitError}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || errors.length > 0}>
            {busy ? "Enviando…" : "Enviar solicitud"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

type Decision = "approve" | "reject" | "applied";

const DECISION_TITLES: Record<Decision, string> = {
  approve: "Aprobar solicitud",
  reject: "Rechazar solicitud",
  applied: "Registrar aplicación manual",
};

function DecisionDialog({
  control,
  decision,
  run,
  onClose,
}: {
  control: NetworkControlRead;
  decision: Decision;
  run: Run;
  onClose: () => void;
}) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const required = decision !== "approve";
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    const ok = await run(() =>
      decision === "approve"
        ? networkControlsApi.approve(control.control_id, control.version, note)
        : decision === "reject"
          ? networkControlsApi.reject(control.control_id, control.version, note)
          : networkControlsApi.markApplied(control.control_id, control.version, note),
    );
    setBusy(false);
    if (ok) onClose();
  }
  return (
    <Modal title={DECISION_TITLES[decision]} onClose={busy ? () => undefined : onClose}>
      <form className="incident-form" onSubmit={(e) => void submit(e)}>
        <p>
          {CONTROL_TYPE_LABELS[control.control_type]}:{" "}
          <span className="mono">{describeTarget(control.control_type, control.target)}</span> · {control.scope.label}
        </p>
        {decision === "approve" && (
          <div className="banner" role="note">
            Aprobar registra la decisión. Sentra no aplicará nada en la red: si se aplica, será fuera de Sentra y podrás
            dejarlo registrado después.
          </div>
        )}
        {decision === "applied" && (
          <p className="muted small">Indica dónde y cómo se aplicó fuera de Sentra (regla de firewall, política del proxy…).</p>
        )}
        <label>
          <span className="muted small">{required ? "Nota (obligatoria)" : "Nota (opcional)"}</span>
          <textarea
            className="input"
            maxLength={1000}
            rows={3}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            aria-label="Nota de la decisión"
          />
        </label>
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button
            type="submit"
            className={`button ${decision === "reject" ? "button--danger" : "button--primary"}`}
            disabled={busy || (required && note.trim().length < 3)}
          >
            {DECISION_TITLES[decision]}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Una solicitud con su estado, la decisión y lo que haría falta para aplicarla. */
export function ControlCard({
  control,
  canApprove,
  canCancel,
  run,
  busy,
}: {
  control: NetworkControlRead;
  canApprove: boolean;
  canCancel: boolean;
  run: Run;
  busy: boolean;
}) {
  const [decision, setDecision] = useState<Decision>();
  const live = control.status === "pending_approval" || control.status === "approved";
  return (
    <li className="task-card" aria-label={`Solicitud: ${CONTROL_TYPE_LABELS[control.control_type]}`}>
      <div className="task-card__head">
        <div>
          <strong>{CONTROL_TYPE_LABELS[control.control_type]}</strong>{" "}
          <span className="mono">{describeTarget(control.control_type, control.target)}</span>{" "}
          <span className={CONTROL_STATUS_BADGES[control.status]}>{CONTROL_STATUS_LABELS[control.status]}</span>
          {control.self_approved && (
            <span className="badge badge--warn" title="La aprobó la misma persona que la pidió">
              Autoaprobada
            </span>
          )}
        </div>
      </div>
      <dl className="fields fields--inline">
        <div className="field">
          <dt>Sentido</dt>
          <dd>{control.direction ? DIRECTION_LABELS[control.direction] : "Saliente"}</dd>
        </div>
        <div className="field">
          <dt>Alcance</dt>
          <dd>{control.scope.label}</dd>
        </div>
        <div className="field">
          <dt>Aplicación</dt>
          <dd>{ENFORCEMENT_LABELS[control.enforcement_status]}</dd>
        </div>
        <div className="field">
          <dt>Pedida</dt>
          <dd>
            {control.requested_by} · {formatRelative(control.created_at)}
          </dd>
        </div>
        <div className="field">
          <dt>Caduca</dt>
          <dd>{control.expires_at ? formatDateTime(control.expires_at) : "Sin caducidad"}</dd>
        </div>
      </dl>
      <p className="note-body small">{control.justification}</p>
      {control.decided_by && (
        <p className="small">
          {control.status === "rejected" ? "Rechazada" : "Decidida"} por {control.decided_by} ·{" "}
          {formatDateTime(control.decided_at)}
          {control.decision_note && <span className="muted"> · {control.decision_note}</span>}
        </p>
      )}
      {control.enforcement && (
        <div className="banner" role="note" aria-label="Qué haría falta para aplicarla">
          {control.enforcement.applied_by_sentra ? "Aplicada por Sentra." : "Sentra no la ha aplicado."}{" "}
          {control.enforcement.points.length === 0
            ? "No hay ningún punto de control instalado para este tipo."
            : `Puntos de control: ${control.enforcement.points.join(", ")}.`}{" "}
          Haría falta: {control.enforcement.needs} <span className="muted">{control.enforcement.note}</span>
        </div>
      )}
      {control.applied_by && (
        <p className="small">
          Aplicada fuera de Sentra por {control.applied_by} · {formatDateTime(control.applied_at)}
          {control.applied_note && <span className="muted"> · {control.applied_note}</span>}
        </p>
      )}
      {(canApprove || canCancel) && live && (
        <div className="actions" role="group" aria-label="Decisión sobre la solicitud">
          {canApprove && control.status === "pending_approval" && (
            <>
              <button type="button" className="button button--small button--primary" disabled={busy} onClick={() => setDecision("approve")}>
                Aprobar (sin aplicar)
              </button>
              <button type="button" className="button button--small" disabled={busy} onClick={() => setDecision("reject")}>
                Rechazar…
              </button>
            </>
          )}
          {canApprove && control.status === "approved" && control.enforcement_status !== "applied_manually" && (
            <button type="button" className="button button--small" disabled={busy} onClick={() => setDecision("applied")}>
              Registrar que se aplicó fuera de Sentra…
            </button>
          )}
          {canCancel && (
            <button
              type="button"
              className="button button--small button--ghost"
              disabled={busy}
              onClick={() => void run(() => networkControlsApi.cancel(control.control_id, control.version))}
            >
              Cancelar solicitud
            </button>
          )}
        </div>
      )}
      {control.enforcement_status === "applied_manually" && live && (
        <p className="muted small">Cancelarla no la retira: habría que retirarla en el punto de control donde se aplicó.</p>
      )}
      {decision && <DecisionDialog control={control} decision={decision} run={run} onClose={() => setDecision(undefined)} />}
    </li>
  );
}

/** Pestaña Controles de red del detalle de un incidente. */
export function NetworkControlsSection({ incident, onChanged }: { incident: IncidentDetail; onChanged?: () => void }) {
  const auth = useAuth();
  const fetcher = useCallback(
    (signal: AbortSignal) => networkControlsApi.forIncident(incident.incident_id, undefined, signal),
    [incident.incident_id],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, config.refreshIntervalMs);
  const fetchCapabilities = useCallback((signal: AbortSignal) => networkControlsApi.capabilities(signal), []);
  const capabilities = usePolling(fetchCapabilities, 3_600_000);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string>();
  const [conflict, setConflict] = useState(false);
  const [requesting, setRequesting] = useState(false);

  const run: Run = useCallback(
    async (action) => {
      setBusy(true);
      setActionError(undefined);
      setConflict(false);
      try {
        await action();
        refresh();
        onChanged?.();
        return true;
      } catch (err) {
        if (isVersionConflict(err)) setConflict(true);
        else setActionError(toMessage(err));
        return false;
      } finally {
        setBusy(false);
      }
    },
    [refresh, onChanged],
  );

  const writable = incident.status !== "closed" && incident.status !== "merged";
  const canRequest = auth.can("incidents:manage") && writable;
  const canApprove = auth.can("network_controls:approve");
  const username = auth.user?.username;

  return (
    <section className="panel panel--padded stack" aria-label="Controles de red">
      <div className="panel__toolbar">
        <h2>Solicitudes de control de red</h2>
        {canRequest && (
          <button type="button" className="button button--primary button--small" onClick={() => setRequesting(true)}>
            Solicitar control
          </button>
        )}
      </div>
      <NoEnforcementNotice capabilities={capabilities.data} />
      {conflict && (
        <div className="banner banner--warn" role="alert">
          Otra persona modificó esta solicitud mientras la tenías abierta. Tu cambio no se aplicó.{" "}
          <button
            type="button"
            className="button button--small"
            onClick={() => {
              setConflict(false);
              refresh();
            }}
          >
            Recargar
          </button>
        </div>
      )}
      {actionError && (
        <div className="banner banner--warn" role="alert">
          {actionError}
        </div>
      )}
      {loading ? (
        <LoadingState label="Cargando solicitudes…" />
      ) : !data ? (
        <ErrorState message={toMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />
      ) : data.items.length === 0 ? (
        <EmptyState title="Sin solicitudes">Este caso no tiene solicitudes de control de red.</EmptyState>
      ) : (
        <ul className="task-list">
          {data.items.map((control) => (
            <ControlCard
              key={control.control_id}
              control={control}
              canApprove={canApprove}
              // Cancelar: quien la pidió (con incidents:manage) o un aprobador.
              canCancel={canApprove || (auth.can("incidents:manage") && control.requested_by === username)}
              run={run}
              busy={busy}
            />
          ))}
        </ul>
      )}
      {requesting && (
        <RequestControlDialog
          incident={incident}
          capabilities={capabilities.data}
          run={run}
          onClose={() => setRequesting(false)}
        />
      )}
    </section>
  );
}

import { useCallback, useState, type FormEvent, type ReactNode } from "react";
import { ApiError } from "../../api/client";
import { isolationApi } from "../../api/sentra6e";
import type { IsolationOverview, IsolationSession } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import {
  ISOLATION_STATUS_BADGES,
  ISOLATION_STATUS_LABELS,
  ISOLATION_UNAVAILABLE,
  isLiveIsolation,
  REASON_MAX,
  RELEASE_REASON_MIN,
  validateIsolation,
} from "../../lib/isolation";
import { usePolling } from "../../lib/usePolling";
import { Modal } from "../Modal";
import { ErrorState, LoadingState } from "../StateViews";

// Mientras hay una sesión viva el estado cambia en segundos (aplicando, aislado, revirtiendo);
// sin ella basta un sondeo lento.
const LIVE_REFRESH_MS = 5_000;
const IDLE_REFRESH_MS = 60_000;

const toError = (err: unknown) => (err instanceof Error ? err : new Error(String(err)));

export function IsolationStatusBadge({ session }: { session: IsolationSession }) {
  return <span className={ISOLATION_STATUS_BADGES[session.status] ?? "badge"}>{ISOLATION_STATUS_LABELS[session.status] ?? session.status}</span>;
}

/**
 * Pestaña Aislamiento del activo (Fase 6E.7). Todo lo que dice si se puede aislar, por qué no,
 * el impacto y los límites viene del servidor (GET /assets/{id}/isolation). El botón de aislar
 * solo existe con containment:isolate y el de liberar con containment:release; la API lo vuelve
 * a comprobar. Un equipo sin agente (o sin helper, o macOS) muestra siempre el mismo texto y las
 * recomendaciones manuales.
 */
export function IsolationTab({ assetId }: { assetId: string }) {
  const auth = useAuth();
  const canIsolate = auth.can("containment:isolate");
  const canRelease = auth.can("containment:release");
  const [live, setLive] = useState(false);
  const fetchOverview = useCallback((signal: AbortSignal) => isolationApi.overview(assetId, signal), [assetId]);
  const overview = usePolling(fetchOverview, live ? LIVE_REFRESH_MS : IDLE_REFRESH_MS);
  const fetchHistory = useCallback((signal: AbortSignal) => isolationApi.history(assetId, 20, signal), [assetId]);
  const history = usePolling(fetchHistory, live ? LIVE_REFRESH_MS : IDLE_REFRESH_MS);
  const [isolating, setIsolating] = useState(false);
  const [releasing, setReleasing] = useState(false);

  const data = overview.data;
  const current = data?.current ?? null;
  const nowLive = current ? isLiveIsolation(current.status) : false;
  if (nowLive !== live) setLive(nowLive);

  const reload = () => {
    overview.refresh();
    history.refresh();
  };

  if (overview.loading) return <LoadingState label="Cargando aislamiento…" />;
  if (!data) return <ErrorState message={errorMessage(overview.error ?? new Error("Sin datos"))} onRetry={overview.refresh} />;

  return (
    <div className="stack">
      {overview.error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(overview.error)}. Se muestran los últimos datos recibidos.
        </div>
      )}
      {current && (
        <CurrentSession
          session={current}
          canRelease={canRelease && isLiveIsolation(current.status)}
          onRelease={() => setReleasing(true)}
        />
      )}
      {!data.available ? (
        <UnavailablePanel overview={data} />
      ) : (
        <section className="panel panel--padded stack" aria-label="Aislamiento disponible">
          <h2 className="panel__title">Aislamiento de red</h2>
          <p className="small">
            Bloquea todo el tráfico del equipo salvo la comunicación con Sentra y lo imprescindible (DHCP, DNS). Se revierte
            solo al expirar, aunque el servidor no esté disponible. Duración máxima: {data.max_minutes} minutos.
          </p>
          <ImpactList impact={data.impact} />
          {canIsolate && !(current && isLiveIsolation(current.status)) && (
            <div className="actions">
              <button type="button" className="button button--danger" onClick={() => setIsolating(true)}>
                Aislar equipo…
              </button>
            </div>
          )}
          {!canIsolate && <p className="muted small">Aislar un equipo requiere el rol de administrador.</p>}
        </section>
      )}
      <HistoryTable sessions={history.data?.items ?? []} loading={history.loading} />
      {isolating && (
        <IsolateDialog
          assetId={assetId}
          overview={data}
          onClose={() => setIsolating(false)}
          onDone={() => {
            setIsolating(false);
            reload();
          }}
        />
      )}
      {releasing && current && (
        <ReleaseDialog
          assetId={assetId}
          session={current}
          onClose={() => {
            setReleasing(false);
            reload();
          }}
          onDone={() => {
            setReleasing(false);
            reload();
          }}
        />
      )}
    </div>
  );
}

function ImpactList({ impact }: { impact: string[] }) {
  if (impact.length === 0) return null;
  return (
    <div>
      <h3 className="small strong">Impacto previsto</h3>
      <ul className="plain-list small" aria-label="Impacto del aislamiento">
        {impact.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

/** Equipo que no se puede aislar: texto fijo, motivos del servidor y recomendaciones manuales. */
function UnavailablePanel({ overview }: { overview: IsolationOverview }) {
  return (
    <section className="panel panel--padded stack" aria-label="Aislamiento no disponible">
      <h2 className="panel__title">{ISOLATION_UNAVAILABLE}</h2>
      {overview.unavailable_message && overview.unavailable_message !== ISOLATION_UNAVAILABLE && (
        <p className="small">{overview.unavailable_message}</p>
      )}
      {overview.reasons.length > 0 && (
        <div>
          <h3 className="small strong">Motivos</h3>
          <ul className="plain-list small" aria-label="Motivos">
            {overview.reasons.map((r) => (
              <li key={r.code}>
                {r.message} <span className="muted mono">({r.code})</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {!overview.server_enabled && (
        <p className="muted small">El aislamiento está desactivado por defecto en el servidor (ISOLATION_ENABLED).</p>
      )}
      {overview.manual_recommendations.length > 0 && (
        <div>
          <h3 className="small strong">Recomendaciones manuales</h3>
          <ul className="plain-list small" aria-label="Recomendaciones manuales">
            {overview.manual_recommendations.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function CurrentSession({
  session,
  canRelease,
  onRelease,
}: {
  session: IsolationSession;
  canRelease: boolean;
  onRelease: () => void;
}) {
  const live = isLiveIsolation(session.status);
  return (
    <section
      className={`panel panel--padded stack${live ? " panel--alerts" : ""}`}
      aria-label="Sesión de aislamiento actual"
    >
      <h2 className="panel__title">
        Sesión de aislamiento <IsolationStatusBadge session={session} />
      </h2>
      {session.status === "unknown" && (
        <div className="banner banner--warn" role="alert">
          El estado que informa el equipo no coincide con el del servidor. Comprueba el equipo antes de actuar.
        </div>
      )}
      <dl className="fields">
        <Field label="Motivo">{session.reason}</Field>
        <Field label="Solicitado">
          {session.requested_by} · {formatDateTime(session.requested_at)}
        </Field>
        <Field label="Expira">
          <time dateTime={session.expires_at} title={formatDateTime(session.expires_at)}>
            {formatDateTime(session.expires_at)} ({formatRelative(session.expires_at)})
          </time>
        </Field>
        <Field label="Verificado en el equipo">{session.verified ? "Sí (reglas leídas de vuelta)" : "No"}</Field>
        {session.method && <Field label="Método">{session.method}</Field>}
        {session.allowed.length > 0 && (
          <Field label="Tráfico permitido">
            <span className="mono">{session.allowed.join(", ")}</span>
          </Field>
        )}
        {session.error_code && (
          <Field label="Error">
            <span className="mono">{session.error_code}</span>
          </Field>
        )}
        {session.released_at && (
          <Field label="Liberado">
            {session.released_by} · {formatDateTime(session.released_at)}
            {session.release_reason && ` · ${session.release_reason}`}
          </Field>
        )}
      </dl>
      {canRelease && (
        <div className="actions">
          <button type="button" className="button button--primary" onClick={onRelease}>
            Liberar aislamiento…
          </button>
        </div>
      )}
    </section>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function HistoryTable({ sessions, loading }: { sessions: IsolationSession[]; loading: boolean }) {
  return (
    <section className="panel" aria-label="Historial de aislamiento">
      <div className="panel__toolbar">
        <h2>Historial</h2>
      </div>
      {loading ? (
        <LoadingState label="Cargando historial…" />
      ) : sessions.length === 0 ? (
        <p className="muted small panel--padded">Este equipo no se ha aislado nunca.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Estado</th>
                <th>Solicitado</th>
                <th>Duración</th>
                <th className="col-secondary">Motivo</th>
                <th className="col-secondary">Fin</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.id}>
                  <td>
                    <IsolationStatusBadge session={s} />
                  </td>
                  <td>
                    {formatDateTime(s.requested_at)} <span className="muted small">· {s.requested_by}</span>
                  </td>
                  <td>{s.duration_minutes} min</td>
                  <td className="col-secondary">{s.reason}</td>
                  <td className="col-secondary">{s.ended_at ? formatDateTime(s.ended_at) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/**
 * Confirmación escrita del aislamiento: el nombre exacto del equipo, un motivo y una duración
 * dentro del máximo. El botón no se habilita hasta que todo es válido, y el servidor vuelve a
 * validarlo (409 isolation_confirmation_mismatch, isolation_duration_exceeds_policy...).
 */
export function IsolateDialog({
  assetId,
  overview,
  onClose,
  onDone,
}: {
  assetId: string;
  overview: IsolationOverview;
  onClose: () => void;
  onDone: () => void;
}) {
  const [confirmName, setConfirmName] = useState("");
  const [reason, setReason] = useState("");
  const [minutes, setMinutes] = useState(String(overview.default_minutes));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [touched, setTouched] = useState(false);
  const errors = validateIsolation({
    confirmName,
    expectedName: overview.confirm_name,
    reason,
    minutes,
    maxMinutes: overview.max_minutes,
  });

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (errors.length > 0) return;
    setBusy(true);
    setError(undefined);
    try {
      await isolationApi.isolate(assetId, {
        confirm_name: confirmName,
        reason: reason.trim(),
        duration_minutes: Number(minutes),
      });
      onDone();
    } catch (err) {
      setError(errorMessage(toError(err)));
      setBusy(false);
    }
  };

  return (
    <Modal title="Aislar equipo" onClose={busy ? () => undefined : onClose}>
      <form className="stack" onSubmit={(e) => void submit(e)} noValidate>
        <div className="banner banner--warn" role="note">
          El equipo dejará de comunicarse con la red salvo con Sentra durante el tiempo indicado.
        </div>
        <ImpactList impact={overview.impact} />
        <label className="form-field">
          <span>
            Escribe <strong className="mono">{overview.confirm_name}</strong> para confirmar
          </span>
          <input
            className="input"
            value={confirmName}
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => setConfirmName(e.target.value)}
            disabled={busy}
            aria-label="Nombre del equipo"
          />
        </label>
        <label className="form-field">
          <span>Motivo</span>
          <textarea
            className="input"
            rows={3}
            value={reason}
            maxLength={REASON_MAX}
            onChange={(e) => setReason(e.target.value)}
            disabled={busy}
            aria-label="Motivo del aislamiento"
          />
        </label>
        <label className="form-field">
          <span>Duración (minutos, máximo {overview.max_minutes})</span>
          <input
            className="input"
            type="number"
            min={1}
            max={overview.max_minutes}
            value={minutes}
            onChange={(e) => setMinutes(e.target.value)}
            disabled={busy}
            aria-label="Duración en minutos"
          />
        </label>
        {touched && errors.length > 0 && (
          <ul className="plain-list small text-crit" role="alert" aria-label="Errores del formulario">
            {errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        )}
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--danger" disabled={busy || errors.length > 0}>
            {busy ? "Aislando…" : "Aislar"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function ReleaseDialog({
  assetId,
  session,
  onClose,
  onDone,
}: {
  assetId: string;
  session: IsolationSession;
  onClose: () => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const valid = reason.trim().length >= RELEASE_REASON_MIN;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!valid) return;
    setBusy(true);
    setError(undefined);
    try {
      await isolationApi.release(assetId, { version: session.version, reason: reason.trim() });
      onDone();
    } catch (err) {
      // 409 isolation_state_conflict: la sesión cambió (p. ej. ya expiró); el mensaje lo dice y
      // al cerrar el diálogo la pestaña muestra el estado real.
      setError(
        err instanceof ApiError && err.status === 409
          ? `${errorMessage(toError(err))} Cierra este diálogo para ver el estado actual.`
          : errorMessage(toError(err)),
      );
      setBusy(false);
    }
  };

  return (
    <Modal title="Liberar aislamiento" onClose={busy ? () => undefined : onClose}>
      <form className="stack" onSubmit={(e) => void submit(e)} noValidate>
        <p className="small">El equipo recuperará su conectividad normal en cuanto el agente aplique la reversión.</p>
        <label className="form-field">
          <span>Motivo de la liberación</span>
          <textarea
            className="input"
            rows={2}
            value={reason}
            maxLength={REASON_MAX}
            onChange={(e) => setReason(e.target.value)}
            disabled={busy}
            aria-label="Motivo de la liberación"
          />
        </label>
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || !valid}>
            {busy ? "Liberando…" : "Liberar"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

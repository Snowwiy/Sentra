import { useCallback, useState, type FormEvent } from "react";
import { usersApi } from "../api/sentra";
import type { AuditEvent, Role, User } from "../api/types";
import { ROLE_LABELS, useAuth } from "../auth/AuthContext";
import { ConfirmDialog, Modal } from "../components/Modal";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { config } from "../config";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { usePolling } from "../lib/usePolling";

const ROLES: Role[] = ["admin", "analyst", "viewer"];
const MIN_PASSWORD = 12;

const ROLE_HELP: Record<Role, string> = {
  admin: "Todo: usuarios, agentes, tokens de instalación, discovery y alertas.",
  analyst: "Consulta todo, inicia/cancela discovery y gestiona alertas. No administra usuarios ni agentes.",
  viewer: "Solo lectura.",
};

const ACTION_LABELS: Record<string, string> = {
  login_success: "Inicio de sesión",
  login_failed: "Inicio de sesión fallido",
  logout: "Cierre de sesión",
  user_created: "Usuario creado",
  role_changed: "Rol cambiado",
  user_disabled: "Usuario desactivado",
  user_enabled: "Usuario activado",
  password_reset: "Contraseña restablecida",
  password_changed: "Contraseña cambiada",
  sessions_revoked: "Sesiones cerradas",
  agent_revoked: "Agente revocado",
  agent_reactivated: "Agente reactivado",
  enrollment_token_created: "Token de instalación creado",
  enrollment_token_revoked: "Token de instalación revocado",
  discovery_started: "Discovery iniciado",
  discovery_cancelled: "Discovery cancelado",
  alert_acknowledged: "Alerta reconocida",
  alert_resolved: "Alerta resuelta",
  permission_denied: "Acción denegada",
};

function message(err: unknown): string {
  return err instanceof Error ? errorMessage(err) : String(err);
}

type Dialog =
  | { kind: "create" }
  | { kind: "password"; user: User }
  | { kind: "toggle"; user: User }
  | { kind: "sessions"; user: User };

/** Administración → Usuarios (solo admin; la API exige users:manage en cada llamada). */
export function UsersPage() {
  const auth = useAuth();
  const fetchUsers = useCallback((signal: AbortSignal) => usersApi.list(signal), []);
  const users = usePolling(fetchUsers, config.refreshIntervalMs);
  const fetchAudit = useCallback((signal: AbortSignal) => usersApi.audit(50, signal), []);
  const audit = usePolling(fetchAudit, config.refreshIntervalMs, auth.can("audit:read"));
  const [dialog, setDialog] = useState<Dialog>();
  const [rowError, setRowError] = useState<string>();
  const refresh = users.refresh;

  async function changeRole(user: User, role: Role) {
    setRowError(undefined);
    try {
      await usersApi.update(user.user_id, { role });
      refresh();
    } catch (err) {
      setRowError(`${user.username}: ${message(err)}`);
    }
  }

  if (users.loading) return <LoadingState label="Cargando usuarios…" />;
  if (!users.data && users.error) {
    return <ErrorState message={errorMessage(users.error)} onRetry={refresh} />;
  }
  const items = users.data?.items ?? [];

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Usuarios</h1>
          <p className="muted small">
            Cuentas del dashboard y sus roles. Los usuarios no se borran: se desactivan, para
            conservar la auditoría.
          </p>
        </div>
        <button type="button" className="button button--primary nowrap" onClick={() => setDialog({ kind: "create" })}>
          + Nuevo usuario
        </button>
      </div>

      {rowError && (
        <div className="banner banner--warn" role="alert">
          {rowError}
        </div>
      )}

      <section className="panel" aria-label="Usuarios">
        {items.length === 0 ? (
          <EmptyState title="Sin usuarios" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Usuario</th>
                  <th>Rol</th>
                  <th>Estado</th>
                  <th>Último acceso</th>
                  <th>Sesiones</th>
                  <th aria-label="Acciones" />
                </tr>
              </thead>
              <tbody>
                {items.map((user) => {
                  const self = user.username === auth.user?.username;
                  return (
                    <tr key={user.user_id}>
                      <td className="strong">
                        {user.username}
                        {self && <span className="muted small"> (tú)</span>}
                      </td>
                      <td>
                        <select
                          className="input input--select"
                          aria-label={`Rol de ${user.username}`}
                          value={user.role}
                          // Un admin no se quita a sí mismo el rol (el backend también lo impide).
                          disabled={self}
                          onChange={(event) => void changeRole(user, event.target.value as Role)}
                        >
                          {ROLES.map((role) => (
                            <option key={role} value={role}>
                              {ROLE_LABELS[role]}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td>{user.is_active ? "Activo" : <span className="muted">Desactivado</span>}</td>
                      <td title={formatDateTime(user.last_login_at)}>
                        {user.last_login_at ? formatRelative(user.last_login_at) : "Nunca"}
                      </td>
                      <td className="mono">{user.active_sessions}</td>
                      <td>
                        <span className="actions">
                          <button
                            type="button"
                            className="button button--small"
                            onClick={() => setDialog({ kind: "password", user })}
                          >
                            Restablecer contraseña
                          </button>
                          {user.active_sessions > 0 && (
                            <button
                              type="button"
                              className="button button--small"
                              onClick={() => setDialog({ kind: "sessions", user })}
                            >
                              Cerrar sesiones
                            </button>
                          )}
                          {!self && (
                            <button
                              type="button"
                              className={`button button--small${user.is_active ? " button--danger" : ""}`}
                              onClick={() => setDialog({ kind: "toggle", user })}
                            >
                              {user.is_active ? "Desactivar" : "Activar"}
                            </button>
                          )}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {auth.can("audit:read") && <AuditPanel events={audit.data?.items} error={audit.error} />}

      {dialog?.kind === "create" && (
        <CreateUserDialog
          onClose={() => setDialog(undefined)}
          onCreated={() => {
            setDialog(undefined);
            refresh();
          }}
        />
      )}
      {dialog?.kind === "password" && (
        <ResetPasswordDialog
          user={dialog.user}
          onClose={() => setDialog(undefined)}
          onDone={() => {
            setDialog(undefined);
            refresh();
          }}
        />
      )}
      {dialog?.kind === "toggle" && (
        <ConfirmDialog
          title={dialog.user.is_active ? "Desactivar usuario" : "Activar usuario"}
          confirmLabel={dialog.user.is_active ? "Desactivar" : "Activar"}
          danger={dialog.user.is_active}
          onConfirm={async () => {
            await usersApi.update(dialog.user.user_id, { is_active: !dialog.user.is_active });
            refresh();
          }}
          onClose={() => setDialog(undefined)}
        >
          {dialog.user.is_active
            ? `${dialog.user.username} no podrá iniciar sesión y sus sesiones abiertas se cerrarán ahora.`
            : `${dialog.user.username} podrá volver a iniciar sesión con su contraseña.`}
        </ConfirmDialog>
      )}
      {dialog?.kind === "sessions" && (
        <ConfirmDialog
          title="Cerrar sesiones"
          confirmLabel="Cerrar sesiones"
          danger
          onConfirm={async () => {
            await usersApi.revokeSessions(dialog.user.user_id);
            refresh();
          }}
          onClose={() => setDialog(undefined)}
        >
          Se cerrarán las {dialog.user.active_sessions} sesiones abiertas de {dialog.user.username}
          {dialog.user.username === auth.user?.username ? ", incluida esta" : ""}.
        </ConfirmDialog>
      )}
    </div>
  );
}

function PasswordInputs({
  password,
  confirm,
  onPassword,
  onConfirm,
}: {
  password: string;
  confirm: string;
  onPassword: (value: string) => void;
  onConfirm: (value: string) => void;
}) {
  return (
    <>
      <label className="form-field">
        <span>Contraseña (mínimo {MIN_PASSWORD} caracteres; mejor una frase larga)</span>
        <input
          className="input"
          type="password"
          autoComplete="new-password"
          maxLength={256}
          value={password}
          onChange={(event) => onPassword(event.target.value)}
        />
      </label>
      <label className="form-field">
        <span>Repetir contraseña</span>
        <input
          className="input"
          type="password"
          autoComplete="new-password"
          maxLength={256}
          value={confirm}
          onChange={(event) => onConfirm(event.target.value)}
        />
      </label>
    </>
  );
}

function passwordProblem(password: string, confirm: string): string | undefined {
  if (password.length < MIN_PASSWORD) return `La contraseña necesita al menos ${MIN_PASSWORD} caracteres.`;
  if (password !== confirm) return "Las contraseñas no coinciden.";
  return undefined;
}

function CreateUserDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [username, setUsername] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const problem = passwordProblem(password, confirm);
    if (problem) return setError(problem);
    setBusy(true);
    setError(undefined);
    try {
      await usersApi.create(username, password, role);
      onCreated();
    } catch (err) {
      setError(message(err));
      setBusy(false);
    }
  }

  return (
    <Modal title="Nuevo usuario" onClose={busy ? () => undefined : onClose}>
      <form className="stack" onSubmit={(event) => void submit(event)}>
        <label className="form-field">
          <span>Usuario (3-32: a-z, 0-9, punto, guion o guion bajo)</span>
          <input
            className="input"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            maxLength={32}
            value={username}
            onChange={(event) => setUsername(event.target.value)}
          />
        </label>
        <label className="form-field">
          <span>Rol</span>
          <select className="input input--select" value={role} onChange={(event) => setRole(event.target.value as Role)}>
            {ROLES.map((value) => (
              <option key={value} value={value}>
                {ROLE_LABELS[value]}
              </option>
            ))}
          </select>
          <span className="muted small">{ROLE_HELP[role]}</span>
        </label>
        <PasswordInputs password={password} confirm={confirm} onPassword={setPassword} onConfirm={setConfirm} />
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || !username}>
            {busy ? "Creando…" : "Crear usuario"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function ResetPasswordDialog({
  user,
  onClose,
  onDone,
}: {
  user: User;
  onClose: () => void;
  onDone: () => void;
}) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent) {
    event.preventDefault();
    const problem = passwordProblem(password, confirm);
    if (problem) return setError(problem);
    setBusy(true);
    setError(undefined);
    try {
      await usersApi.resetPassword(user.user_id, password);
      onDone();
    } catch (err) {
      setError(message(err));
      setBusy(false);
    }
  }

  return (
    <Modal title={`Restablecer contraseña de ${user.username}`} onClose={busy ? () => undefined : onClose}>
      <form className="stack" onSubmit={(event) => void submit(event)}>
        <p className="muted small">
          Se cerrarán todas las sesiones abiertas de {user.username}. Comunícale la contraseña
          nueva por un canal seguro.
        </p>
        <PasswordInputs password={password} confirm={confirm} onPassword={setPassword} onConfirm={setConfirm} />
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy}>
            {busy ? "Guardando…" : "Restablecer"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function auditTarget(event: AuditEvent): string {
  // El nombre (si la entrada lo guarda) se lee mejor que el identificador público.
  const name = event.details?.["username"] ?? event.details?.["hostname"] ?? event.details?.["target"];
  if (typeof name === "string" && name) return `${event.target_type ?? ""} ${name}`.trim();
  return event.target_type ? `${event.target_type} ${event.target_id ?? ""}`.trim() : "—";
}

function AuditPanel({ events, error }: { events: AuditEvent[] | undefined; error: Error | undefined }) {
  return (
    <section className="panel" aria-label="Auditoría">
      <div className="panel__toolbar">
        <h2>Auditoría</h2>
        <span className="muted small">Últimas 50 acciones administrativas y de seguridad.</span>
      </div>
      {error && !events ? (
        <ErrorState message={errorMessage(error)} />
      ) : !events ? (
        <LoadingState label="Cargando auditoría…" />
      ) : events.length === 0 ? (
        <EmptyState title="Sin acciones registradas" />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Cuándo</th>
                <th>Quién</th>
                <th>Acción</th>
                <th>Objetivo</th>
                <th>Resultado</th>
                <th>Origen</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event, index) => (
                <tr key={`${event.created_at}-${index}`}>
                  <td title={formatDateTime(event.created_at)}>{formatRelative(event.created_at)}</td>
                  <td>{event.actor}</td>
                  <td>{ACTION_LABELS[event.action] ?? event.action}</td>
                  <td className="mono small">{auditTarget(event)}</td>
                  <td>{event.result === "success" ? "Correcto" : event.result === "denied" ? "Denegado" : "Fallido"}</td>
                  <td className="mono small">{event.client_ip ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

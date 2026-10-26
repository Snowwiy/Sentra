import { useEffect, useState } from "react";
import { incidentsApi } from "../../api/sentra";
import type { AssignableUser } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";

/**
 * Responsable de un caso desde su creación (Fase 7A.6). Mismas reglas que asignar: un analyst
 * solo puede elegirse a sí mismo; un admin (incidents:admin) a cualquier analyst o admin activo.
 * La lista completa solo se pide para quien puede usarla; el servidor valida igualmente
 * (422 incident_invalid_reference si el responsable no es válido).
 */
export function OwnerSelect({
  value,
  onChange,
  disabled = false,
  label = "Responsable",
}: {
  value: string;
  onChange: (userId: string) => void;
  disabled?: boolean;
  label?: string;
}) {
  const auth = useAuth();
  const isAdmin = auth.can("incidents:admin");
  const me = auth.user;
  const [users, setUsers] = useState<AssignableUser[]>([]);
  const [error, setError] = useState(false);

  useEffect(() => {
    if (!isAdmin) return;
    const controller = new AbortController();
    incidentsApi
      .assignees(controller.signal)
      .then((list) => setUsers(list.items))
      .catch(() => {
        if (!controller.signal.aborted) setError(true);
      });
    return () => controller.abort();
  }, [isAdmin]);

  if (!auth.can("incidents:manage")) return null;
  const others = users.filter((user) => user.user_id !== me?.user_id);
  return (
    <label className="form-field">
      <span className="muted small">{label}</span>
      <select
        className="input input--select"
        value={value}
        disabled={disabled}
        onChange={(event) => onChange(event.target.value)}
        aria-label={label}
      >
        <option value="">Sin asignar</option>
        {me && <option value={me.user_id}>Yo ({me.username})</option>}
        {others.map((user) => (
          <option key={user.user_id} value={user.user_id}>
            {user.username} ({user.role})
          </option>
        ))}
      </select>
      {error && <span className="muted small">No se pudo cargar la lista de usuarios: solo puedes elegirte a ti.</span>}
    </label>
  );
}

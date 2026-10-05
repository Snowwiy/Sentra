import { useCallback } from "react";
import { consoleApi } from "../api/sentra";
import type { ConsoleInfo, Permission } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { usePolling } from "./usePolling";

// Los datos del asistente (TTL, URLs sugeridas) cambian poco: se consultan una vez por minuto.
const CHECK_MS = 60_000;

export interface ConsoleState {
  info: ConsoleInfo | undefined;
  loading: boolean;
  /**
   * El rol de la sesión tiene el permiso. Si no, la UI OCULTA las acciones (un viewer no
   * ve "Añadir agente", "Revocar" ni "Iniciar descubrimiento"). Ocultar no es la seguridad:
   * el backend responde 403 igualmente.
   */
  allowed: boolean;
  /** Permitido y listo para usarse (en agentes, cuando ya se cargaron los datos del asistente). */
  available: boolean;
  /** Por qué no está disponible pese a tener permiso (p. ej. la API no responde). */
  reason: string | undefined;
  refresh: () => void;
}

export function consoleUnavailableReason(
  error: Error | undefined,
  feature = "La gestión de agentes",
): string | undefined {
  if (!error) return undefined;
  return `${feature} no está disponible ahora mismo: ${error.message}`;
}

/**
 * Acciones administrativas del dashboard según el permiso de la sesión (Fase 4G).
 *
 * `permission` por defecto es la gestión de tokens/agentes, que además necesita los datos
 * de /console para el asistente; para discovery se pasa "discovery:run" y no se consulta
 * nada más. `feature` personaliza el motivo mostrado si algo falla.
 */
export function useConsole(
  feature?: string,
  permission: Permission = "enrollment:manage",
): ConsoleState {
  const auth = useAuth();
  const allowed = auth.can(permission);
  const needsInfo = permission === "enrollment:manage";
  const fetchInfo = useCallback((signal: AbortSignal) => consoleApi.info(signal), []);
  const { data, error, loading, refresh } = usePolling(fetchInfo, CHECK_MS, allowed && needsInfo);
  const available = allowed && (!needsInfo || data !== undefined);
  return {
    info: data,
    loading: allowed && needsInfo && loading,
    allowed,
    available,
    reason: allowed && !available ? consoleUnavailableReason(error, feature) : undefined,
    refresh,
  };
}

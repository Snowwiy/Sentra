import { useCallback } from "react";
import { ApiError } from "../api/client";
import { consoleApi } from "../api/sentra";
import type { ConsoleInfo } from "../api/types";
import { usePolling } from "./usePolling";

// Whether this browser may manage agents rarely changes (server setting, where the browser
// runs): checked once a minute.
const CHECK_MS = 60_000;

export interface ConsoleState {
  info: ConsoleInfo | undefined;
  loading: boolean;
  available: boolean;
  /** Why agent management is unavailable, for the operator. */
  reason: string | undefined;
  refresh: () => void;
}

export function consoleUnavailableReason(
  error: Error | undefined,
  feature = "La gestión de agentes",
): string | undefined {
  if (!error) return undefined;
  if (error instanceof ApiError && error.code === "console_disabled") {
    return `${feature} desde el dashboard está desactivada. Añade DASHBOARD_ADMIN_ENABLED=true al .env del servidor y reinicia la API.`;
  }
  if (error instanceof ApiError && error.code === "console_not_local") {
    return `${feature} solo está disponible desde un navegador en el propio servidor Sentra (http://localhost). Mientras no exista login, no se permite desde otros equipos.`;
  }
  return `No se pudo comprobar la consola de administración: ${error.message}`;
}

/**
 * `feature` personaliza el motivo mostrado ("La gestión de agentes", "El descubrimiento de
 * red"...): la guarda del servidor es la misma consola local para todas las acciones.
 */
export function useConsole(feature?: string): ConsoleState {
  const fetchInfo = useCallback((signal: AbortSignal) => consoleApi.info(signal), []);
  const { data, error, loading, refresh } = usePolling(fetchInfo, CHECK_MS);
  // A refusal by the server (disabled, not local) disables the actions at once; a passing
  // network blip keeps the last good answer, like every other panel.
  const refused = error instanceof ApiError && error.code.startsWith("console_");
  const available = data !== undefined && !refused;
  return {
    info: data,
    loading,
    available,
    reason: available ? undefined : consoleUnavailableReason(error, feature),
    refresh,
  };
}

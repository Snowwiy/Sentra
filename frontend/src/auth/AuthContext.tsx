import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { ApiError, onUnauthorized, setCsrfToken } from "../api/client";
import { authApi } from "../api/sentra";
import type { AuthState, CurrentUser, Permission } from "../api/types";

export type AuthStatus = "loading" | "authenticated" | "anonymous" | "error";

export interface AuthValue {
  status: AuthStatus;
  user: CurrentUser | undefined;
  /** Error al comprobar la sesión (API caída): distinto de "no hay sesión". */
  error: Error | undefined;
  /** Motivo por el que se volvió al login (sesión caducada), para explicarlo allí. */
  notice: string | undefined;
  can: (permission: Permission) => boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  retry: () => void;
}

export const AuthContext = createContext<AuthValue | undefined>(undefined);

const EXPIRED = "Tu sesión ha caducado o se ha cerrado. Inicia sesión de nuevo.";

/**
 * Estado de la sesión del dashboard.
 *
 * Al cargar llama a /auth/me: si la cookie HttpOnly sigue siendo válida, la sesión se
 * restaura sin pedir de nuevo la contraseña. Nada de esto se guarda en el navegador: el
 * usuario, los permisos y el token CSRF viven solo en memoria y se pierden al cerrar la
 * pestaña, que es lo que queremos.
 *
 * Los permisos sirven para mostrar u ocultar acciones; NO son la seguridad. El backend
 * vuelve a comprobar cada permiso en cada petición.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{
    status: AuthStatus;
    auth?: AuthState;
    error?: Error;
    notice?: string;
  }>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);

  const apply = useCallback((auth: AuthState | undefined, notice?: string) => {
    setCsrfToken(auth?.csrf_token);
    setState(auth ? { status: "authenticated", auth } : { status: "anonymous", notice });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    authApi
      .me(controller.signal)
      .then((auth) => apply(auth))
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        if (error instanceof ApiError && error.status === 401) apply(undefined);
        else setState({ status: "error", error: error instanceof Error ? error : new Error(String(error)) });
      });
    return () => controller.abort();
  }, [apply, attempt]);

  useEffect(() => {
    // Un 401 en cualquier panel significa que la sesión ya no vale (caducó, la revocó un
    // admin o se desactivó el usuario). Se limpia el estado una sola vez y las rutas
    // protegidas llevan al login; los paneles se desmontan y dejan de consultar, sin bucles.
    onUnauthorized(() => {
      setCsrfToken(undefined);
      setState((current) =>
        current.status === "authenticated" ? { status: "anonymous", notice: EXPIRED } : current,
      );
    });
    return () => onUnauthorized(undefined);
  }, []);

  const login = useCallback(
    async (username: string, password: string) => {
      apply(await authApi.login(username, password));
    },
    [apply],
  );

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch {
      // Aunque falle (sesión ya caducada, red), el navegador se queda sin sesión local.
    }
    apply(undefined);
  }, [apply]);

  const value = useMemo<AuthValue>(() => {
    const permissions = new Set(state.auth?.permissions ?? []);
    return {
      status: state.status,
      user: state.auth?.user,
      error: state.error,
      notice: state.notice,
      can: (permission) => permissions.has(permission),
      login,
      logout,
      retry: () => {
        setState({ status: "loading" });
        setAttempt((n) => n + 1);
      },
    };
  }, [state, login, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside <AuthProvider>");
  return value;
}

export const ROLE_LABELS: Record<string, string> = {
  admin: "Administrador",
  analyst: "Analista",
  viewer: "Solo lectura",
};

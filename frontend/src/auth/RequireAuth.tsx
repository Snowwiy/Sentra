import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import type { Permission } from "../api/types";
import { ErrorState, LoadingState } from "../components/StateViews";
import { useAuth } from "./AuthContext";

/** Rutas que exigen sesión: sin ella, al login recordando a dónde se quería ir. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const auth = useAuth();
  const location = useLocation();
  if (auth.status === "loading") return <LoadingState label="Comprobando sesión…" />;
  if (auth.status === "error") {
    return (
      <ErrorState
        title="No se pudo comprobar la sesión"
        message={auth.error?.message ?? "Error desconocido"}
        onRetry={auth.retry}
      />
    );
  }
  if (auth.status === "anonymous") {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  }
  return <>{children}</>;
}

/** Página que solo ve quien tiene el permiso. El backend también lo exige (403). */
export function RequirePermission({
  permission,
  children,
}: {
  permission: Permission;
  children: ReactNode;
}) {
  const auth = useAuth();
  if (!auth.can(permission)) {
    return (
      <div className="page">
        <h1>Acceso restringido</h1>
        <p className="muted">Tu rol no permite ver esta página.</p>
      </div>
    );
  }
  return <>{children}</>;
}

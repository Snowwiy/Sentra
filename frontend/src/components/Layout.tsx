import { useState } from "react";
import { Link, Outlet, useNavigate } from "react-router-dom";
import { ROLE_LABELS, useAuth } from "../auth/AuthContext";
import { HealthIndicator } from "./HealthIndicator";

export function Layout() {
  const auth = useAuth();
  const navigate = useNavigate();
  const [leaving, setLeaving] = useState(false);

  async function logout() {
    setLeaving(true);
    await auth.logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="app">
      <header className="topbar">
        <Link to="/" className="brand">
          <img src="/favicon.svg" alt="" width={22} height={22} />
          <span>Sentra</span>
        </Link>
        <nav className="topbar__nav">
          <Link to="/">Activos</Link>
          <Link to="/agents">Agentes</Link>
          <Link to="/network">Red</Link>
          <Link to="/risk">Riesgo</Link>
          {auth.can("vulnerabilities:read") && <Link to="/vulnerabilities">Vulnerabilidades</Link>}
          <Link to="/detections">Detecciones</Link>
          {auth.can("incidents:read") && <Link to="/incidents">Incidentes</Link>}
          <Link to="/alerts">Alertas</Link>
          {auth.can("ai:use") && <Link to="/ai">AI Insights</Link>}
          {auth.can("ai:use") && <Link to="/settings/ai">Configuración</Link>}
          {/* Solo navegación: la página y la API exigen users:manage igualmente. */}
          {auth.can("users:manage") && <Link to="/admin/users">Usuarios</Link>}
        </nav>
        <HealthIndicator />
        {auth.user && (
          <div className="userbar" aria-label="Sesión">
            <span className="strong">{auth.user.username}</span>
            <span className="role-badge">{ROLE_LABELS[auth.user.role] ?? auth.user.role}</span>
            <button type="button" className="button button--small" disabled={leaving} onClick={() => void logout()}>
              Cerrar sesión
            </button>
          </div>
        )}
      </header>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}

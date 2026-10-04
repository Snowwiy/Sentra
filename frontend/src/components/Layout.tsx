import { Link, Outlet } from "react-router-dom";
import { HealthIndicator } from "./HealthIndicator";

export function Layout() {
  return (
    <div className="app">
      <header className="topbar">
        <Link to="/" className="brand">
          <img src="/favicon.svg" alt="" width={22} height={22} />
          <span>Sentra</span>
        </Link>
        <nav className="topbar__nav">
          <Link to="/">Activos</Link>
          <Link to="/network">Red</Link>
          <Link to="/alerts">Alertas</Link>
        </nav>
        <HealthIndicator />
      </header>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}

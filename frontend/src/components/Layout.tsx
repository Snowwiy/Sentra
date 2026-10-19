import { useEffect, useMemo, useRef, useState } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import type { Permission } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { activeItem, visibleGroups } from "../navigation/navigation";
import { SiteProvider } from "../site/SiteContext";
import { SiteSelector } from "../site/SiteSelector";
import { useNavigationStyle, useSidebarCompact, type NavigationStyle } from "../ui/preferences";
import { useViewport, type Viewport } from "../ui/useMediaQuery";
import { HealthIndicator } from "./HealthIndicator";
import { Icon } from "./icons";
import { SideNav } from "./layout/SideNav";
import { TopNav } from "./layout/TopNav";
import { UserMenu } from "./layout/UserMenu";
import { trapTab } from "./layout/navKeys";
import { observeTables } from "../ui/stackTables";

/** Cómo se presenta la navegación con la preferencia y el tamaño de ventana actuales. */
export type ResolvedNavigation =
  | { kind: "sidebar"; compact: boolean; drawer: boolean }
  | { kind: "topbar"; drawer: boolean }
  | { kind: "drawer"; drawer: true };

/**
 * Fase 6C: el estilo elegido se respeta mientras quepa. En móvil (< 768 px) ninguno de los
 * dos cabe sin desbordar, así que siempre se usa el drawer con el botón ≡. En "Automático" el
 * escritorio usa el menú lateral (hay demasiadas secciones para una barra) y la tablet el
 * menú compacto de iconos, con el drawer completo detrás de ≡.
 */
export function resolveNavigation(style: NavigationStyle, viewport: Viewport, compactPreference: boolean): ResolvedNavigation {
  if (viewport === "mobile") return { kind: "drawer", drawer: true };
  if (style === "topbar") return { kind: "topbar", drawer: false };
  if (viewport === "tablet") return { kind: "sidebar", compact: true, drawer: true };
  return { kind: "sidebar", compact: compactPreference, drawer: false };
}

export function Layout() {
  const auth = useAuth();
  const location = useLocation();
  const viewport = useViewport();
  const [style] = useNavigationStyle();
  const [compactPreference, setCompactPreference] = useSidebarCompact();
  const nav = resolveNavigation(style, viewport, compactPreference);
  const groups = useMemo(() => visibleGroups((permission) => auth.can(permission as Permission)), [auth]);
  const active = activeItem(groups, location.pathname);

  // El drawer se abre "para" una ruta y un tamaño de ventana: al navegar (enlace,
  // atrás/adelante) o al cambiar de móvil a escritorio queda cerrado, sin un efecto que lo
  // cierre después de pintar, y no reaparece al volver al tamaño anterior.
  const [drawerFor, setDrawerFor] = useState<string>();
  const drawerKey = `${viewport}:${location.pathname}`;
  const drawerOpen = nav.drawer && drawerFor === drawerKey;
  const setDrawerPath = (path: string | undefined) => setDrawerFor(path === undefined ? undefined : `${viewport}:${path}`);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const drawerRef = useRef<HTMLDivElement>(null);
  const mainRef = useRef<HTMLElement>(null);

  useEffect(() => {
    if (!mainRef.current) return;
    return observeTables(mainRef.current);
  }, []);

  const closeDrawer = () => {
    setDrawerPath(undefined);
    menuButtonRef.current?.focus();
  };

  useEffect(() => {
    if (!drawerOpen) return;
    // Sin scroll del fondo mientras el drawer cubre la página, y foco dentro del drawer.
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    drawerRef.current?.querySelector<HTMLElement>("a, button")?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setDrawerFor(undefined);
        menuButtonRef.current?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = previous;
      document.removeEventListener("keydown", onKey);
    };
  }, [drawerOpen]);

  const onMenuButton = () => {
    if (nav.drawer) setDrawerPath(drawerOpen ? undefined : location.pathname);
    else if (nav.kind === "sidebar") setCompactPreference(!nav.compact);
  };
  const showMenuButton = nav.kind !== "topbar";
  const menuExpanded = nav.drawer ? drawerOpen : nav.kind === "sidebar" && !nav.compact;
  const shellClass = [
    "shell",
    `shell--${nav.kind}`,
    nav.kind === "sidebar" && nav.compact ? "shell--compact" : "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    // Fase 5F: el alcance de site es global a todas las páginas con sesión.
    <SiteProvider>
      <div className={shellClass}>
        <a className="skip-link" href="#main-content">
          Saltar al contenido
        </a>
        <header className="appbar">
          {showMenuButton && (
            <button
              type="button"
              ref={menuButtonRef}
              className="iconbutton appbar__menu"
              aria-label={nav.drawer ? (drawerOpen ? "Cerrar menú" : "Abrir menú") : nav.compact ? "Expandir menú" : "Contraer menú"}
              aria-expanded={menuExpanded}
              aria-controls={nav.drawer ? "nav-drawer" : "nav-sidebar"}
              onClick={onMenuButton}
            >
              <Icon name={drawerOpen ? "close" : "menu"} />
            </button>
          )}
          <Link to="/" className="brand">
            <img src="/favicon.svg" alt="" width={24} height={24} />
            <span className="brand__name">Sentra</span>
          </Link>
          {nav.kind === "topbar" && <TopNav groups={groups} active={active} />}
          <div className="appbar__tools">
            <SiteSelector />
            <HealthIndicator />
            <UserMenu />
          </div>
        </header>
        {nav.kind === "sidebar" && (
          <aside className="sidebar" aria-label="Menú lateral">
            <SideNav id="nav-sidebar" groups={groups} active={active} compact={nav.compact} />
          </aside>
        )}
        {drawerOpen && (
          <div className="drawer-layer">
            <div className="drawer-backdrop" onClick={closeDrawer} aria-hidden="true" />
            <div
              ref={drawerRef}
              id="nav-drawer"
              className="drawer"
              role="dialog"
              aria-modal="true"
              aria-label="Menú de navegación"
              onKeyDown={trapTab}
            >
              <div className="drawer__header">
                <span className="brand">
                  <img src="/favicon.svg" alt="" width={24} height={24} />
                  <span className="brand__name">Sentra</span>
                </span>
                <button type="button" className="iconbutton" aria-label="Cerrar menú" onClick={closeDrawer}>
                  <Icon name="close" />
                </button>
              </div>
              <SideNav id="nav-drawer-list" groups={groups} active={active} onNavigate={() => setDrawerPath(undefined)} />
            </div>
          </div>
        )}
        <main id="main-content" className="content" tabIndex={-1} ref={mainRef}>
          <Outlet />
        </main>
      </div>
    </SiteProvider>
  );
}

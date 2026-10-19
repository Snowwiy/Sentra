import { useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ROLE_LABELS, useAuth } from "../../auth/AuthContext";
import { Icon, type IconName } from "../icons";
import {
  NAVIGATION_STYLE_LABELS,
  NAVIGATION_STYLES,
  useNavigationStyle,
  type NavigationStyle,
} from "../../ui/preferences";
import { usePopover } from "./usePopover";

const STYLE_ICONS: Record<NavigationStyle, IconName> = {
  auto: "layout-auto",
  sidebar: "layout-sidebar",
  topbar: "layout-top",
};

/**
 * Menú de usuario de la cabecera. Está visible en todos los tamaños de ventana, así que es
 * también el sitio del selector de estilo de navegación: si una barra quedase mal en algún
 * tamaño, el usuario siempre puede cambiar de estilo desde aquí.
 */
export function UserMenu() {
  const auth = useAuth();
  const navigate = useNavigate();
  const rootRef = useRef<HTMLDivElement>(null);
  const popover = usePopover<"user">(rootRef);
  const [style, setStyle] = useNavigationStyle();
  const [leaving, setLeaving] = useState(false);
  const [notSaved, setNotSaved] = useState(false);

  if (!auth.user) return null;
  const isOpen = popover.open === "user";
  const role = ROLE_LABELS[auth.user.role] ?? auth.user.role;

  async function logout() {
    setLeaving(true);
    await auth.logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="usermenu" ref={rootRef}>
      <button
        type="button"
        className="iconbutton usermenu__trigger"
        aria-expanded={isOpen}
        aria-controls="usermenu-panel"
        aria-label={`Sesión de ${auth.user.username} (${role})`}
        onClick={() => popover.toggle("user")}
      >
        <Icon name="user" />
        <span className="usermenu__name">{auth.user.username}</span>
        <span className="role-badge usermenu__role">{role}</span>
        <Icon name="chevron-down" size={14} />
      </button>
      {isOpen && (
        <div className="usermenu__panel" id="usermenu-panel">
          <div className="usermenu__identity">
            <span className="strong">{auth.user.username}</span>
            <span className="muted small">{role}</span>
          </div>
          <fieldset className="usermenu__section">
            <legend>Estilo de navegación</legend>
            {NAVIGATION_STYLES.map((value) => (
              <label key={value} className="usermenu__option">
                <input
                  type="radio"
                  name="usermenu-navigation"
                  value={value}
                  checked={style === value}
                  onChange={() => setNotSaved(!setStyle(value))}
                />
                <Icon name={STYLE_ICONS[value]} size={18} />
                <span>{NAVIGATION_STYLE_LABELS[value]}</span>
              </label>
            ))}
            {notSaved && (
              <span className="small muted" role="status">
                El navegador no permite guardar preferencias: se aplicará solo en esta pestaña.
              </span>
            )}
          </fieldset>
          <div className="usermenu__section">
            <Link to="/settings" className="usermenu__link" onClick={popover.close}>
              <Icon name="settings" size={18} />
              <span>Configuración</span>
            </Link>
            <button type="button" className="usermenu__link" disabled={leaving} onClick={() => void logout()}>
              <Icon name="logout" size={18} />
              <span>{leaving ? "Cerrando sesión…" : "Cerrar sesión"}</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { Icon, type IconName } from "../components/icons";
import {
  NAVIGATION_STYLE_LABELS,
  NAVIGATION_STYLES,
  useNavigationStyle,
  type NavigationStyle,
} from "../ui/preferences";

const STYLE_HELP: Record<NavigationStyle, string> = {
  auto: "Menú lateral en escritorio, menú compacto de iconos en tablet y menú ≡ en móvil.",
  sidebar: "Menú lateral con iconos y nombres; el botón ≡ lo contrae a solo iconos.",
  topbar: "Barra superior agrupada; lo que no cabe pasa a «Más». En móvil se usa el menú ≡.",
};

const STYLE_ICONS: Record<NavigationStyle, IconName> = {
  auto: "layout-auto",
  sidebar: "layout-sidebar",
  topbar: "layout-top",
};

/**
 * Configuración (Fase 6C). La sección Interfaz es de cada navegador y está disponible para
 * todos los roles; las secciones del servidor enlazan a sus páginas, que mantienen su propio
 * permiso (las entradas solo se muestran a quien puede abrirlas).
 */
export function SettingsPage() {
  const auth = useAuth();
  const [style, setStyle] = useNavigationStyle();
  const [notSaved, setNotSaved] = useState(false);

  const sections: { to: string; icon: IconName; title: string; text: string; visible: boolean }[] = [
    {
      to: "/settings/sites",
      icon: "site",
      title: "Sites",
      text: "Ubicaciones, redes autorizadas y alcance de sensores.",
      visible: auth.can("monitoring:read"),
    },
    {
      to: "/settings/ai",
      icon: "ai",
      title: "IA local",
      text: "Estado del runtime local y modelos disponibles.",
      visible: auth.can("ai:use"),
    },
    {
      to: "/admin/users",
      icon: "users",
      title: "Usuarios",
      text: "Cuentas del dashboard y roles.",
      visible: auth.can("users:manage"),
    },
    {
      to: "/admin/lifecycle",
      icon: "lifecycle",
      title: "Ciclo de vida",
      text: "Activos inactivos, duplicados y limpieza segura.",
      visible: auth.can("assets:manage"),
    },
  ];

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Configuración</h1>
          <p className="muted">Preferencias de esta interfaz y acceso a la configuración del servidor.</p>
        </div>
      </div>

      <section className="panel panel--padded stack" aria-labelledby="settings-ui">
        <div>
          <h2 id="settings-ui">Interfaz</h2>
          <p className="small muted">
            Se guarda en este navegador. No contiene datos de la sesión ni del servidor.
          </p>
        </div>
        <fieldset className="stack fieldset--plain">
          <legend className="section-title">Estilo de navegación</legend>
          <div className="option-cards">
            {NAVIGATION_STYLES.map((value) => (
              <label key={value} className="option-card">
                <span className="option-card__head">
                  <input
                    type="radio"
                    name="settings-navigation"
                    value={value}
                    checked={style === value}
                    onChange={() => setNotSaved(!setStyle(value))}
                  />
                  <Icon name={STYLE_ICONS[value]} />
                  {NAVIGATION_STYLE_LABELS[value]}
                </span>
                <span className="small muted">{STYLE_HELP[value]}</span>
              </label>
            ))}
          </div>
          {notSaved && (
            <div className="banner banner--warn" role="status">
              El navegador no permite guardar preferencias (modo privado o almacenamiento bloqueado): el estilo
              elegido se aplica solo hasta cerrar esta pestaña.
            </div>
          )}
          <p className="small muted">También puedes cambiarlo desde el menú de usuario de la cabecera.</p>
        </fieldset>
      </section>

      {sections.some((s) => s.visible) && (
        <section className="stack" aria-labelledby="settings-server">
          <h2 id="settings-server">Servidor</h2>
          <div className="link-cards">
            {sections
              .filter((s) => s.visible)
              .map((s) => (
                <Link key={s.to} to={s.to} className="link-card">
                  <Icon name={s.icon} />
                  <span>
                    <span className="strong">{s.title}</span>
                    <span className="small muted block">
                      {s.text}
                    </span>
                  </span>
                </Link>
              ))}
          </div>
        </section>
      )}
    </div>
  );
}

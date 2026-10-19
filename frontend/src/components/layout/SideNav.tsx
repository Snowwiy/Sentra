import { useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../icons";
import type { NavGroup, NavItem } from "../../navigation/navigation";
import { useCollapsedGroups } from "../../ui/preferences";
import { moveFocusWithArrows } from "./navKeys";

interface Tip {
  label: string;
  top: number;
  left: number;
}

/**
 * Lista de navegación agrupada del menú lateral y del drawer móvil.
 *
 * En modo compacto solo hay iconos: el nombre va en aria-label (lectores de pantalla) y en
 * un tooltip con posición fija, porque un ::after dentro del aside con scroll quedaría
 * recortado por su overflow.
 */
export function SideNav({
  groups,
  active,
  compact = false,
  onNavigate,
  id,
}: {
  groups: NavGroup[];
  active: NavItem | undefined;
  compact?: boolean;
  onNavigate?: () => void;
  id?: string;
}) {
  const [collapsed, setCollapsed] = useCollapsedGroups();
  const [tip, setTip] = useState<Tip>();

  const toggle = (groupId: string) =>
    setCollapsed(collapsed.includes(groupId) ? collapsed.filter((g) => g !== groupId) : [...collapsed, groupId]);

  const showTip = (label: string, element: HTMLElement) => {
    if (!compact) return;
    const rect = element.getBoundingClientRect();
    setTip({ label, top: rect.top + rect.height / 2, left: rect.right + 8 });
  };

  return (
    <nav
      id={id}
      className={`sidenav${compact ? " sidenav--compact" : ""}`}
      aria-label="Navegación principal"
      onKeyDown={(event) => moveFocusWithArrows(event, "vertical")}
    >
      {groups.map((group) => {
        // Un grupo que contiene la página actual nunca se pliega: la entrada activa debe verse.
        const containsActive = active ? group.items.includes(active) : false;
        const isCollapsed = !compact && collapsed.includes(group.id) && !containsActive;
        const listId = `${id ?? "nav"}-${group.id}`;
        return (
          <div className="sidenav__group" key={group.id}>
            {compact ? (
              <div className="sidenav__divider" role="presentation" />
            ) : (
              <button
                type="button"
                className="sidenav__group-toggle"
                aria-expanded={!isCollapsed}
                aria-controls={listId}
                onClick={() => toggle(group.id)}
              >
                <span>{group.label}</span>
                <Icon name={isCollapsed ? "chevron-right" : "chevron-down"} size={14} />
              </button>
            )}
            {!isCollapsed && (
              <ul className="sidenav__list" id={listId} aria-label={compact ? group.label : undefined}>
                {group.items.map((item) => {
                  const isActive = item === active;
                  return (
                    <li key={item.to}>
                      <Link
                        to={item.to}
                        className={`sidenav__link${isActive ? " sidenav__link--active" : ""}`}
                        aria-current={isActive ? "page" : undefined}
                        aria-label={compact ? item.label : undefined}
                        onClick={onNavigate}
                        onMouseEnter={(event) => showTip(item.label, event.currentTarget)}
                        onMouseLeave={() => setTip(undefined)}
                        onFocus={(event) => showTip(item.label, event.currentTarget)}
                        onBlur={() => setTip(undefined)}
                      >
                        <Icon name={item.icon} />
                        {!compact && <span className="sidenav__label">{item.label}</span>}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>
        );
      })}
      {compact && tip && (
        <span className="tooltip tooltip--fixed" role="tooltip" style={{ top: tip.top, left: tip.left }}>
          {tip.label}
        </span>
      )}
    </nav>
  );
}

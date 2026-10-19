import { useLayoutEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Icon } from "../icons";
import type { NavGroup, NavItem } from "../../navigation/navigation";
import { moveFocusWithArrows } from "./navKeys";
import { usePopover } from "./usePopover";

const MORE = "__more__";

/**
 * Barra de navegación horizontal (modo "Barra superior").
 *
 * Muestra un botón por grupo con su menú. Cuando no caben todos en el ancho disponible, los
 * últimos grupos pasan a "Más": la barra nunca crece más que su contenedor, que es lo que
 * antes empujaba la página y obligaba a desplazarla en horizontal.
 */
export function TopNav({ groups, active }: { groups: NavGroup[]; active: NavItem | undefined }) {
  const rootRef = useRef<HTMLElement>(null);
  const popover = usePopover(rootRef);
  const listRef = useRef<HTMLUListElement>(null);
  const widths = useRef<number[]>([]);
  const [visibleCount, setVisibleCount] = useState(groups.length);

  useLayoutEffect(() => {
    const list = listRef.current;
    if (!list || typeof ResizeObserver === "undefined") return;
    const measure = () => {
      // Los anchos se miden con todos los grupos visibles (primer render) y se reutilizan:
      // un botón oculto ya no tiene ancho que medir.
      const buttons = Array.from(list.querySelectorAll<HTMLElement>("[data-group-button]"));
      buttons.forEach((button, index) => {
        if (button.offsetWidth > 0) widths.current[index] = button.offsetWidth;
      });
      const available = list.clientWidth;
      const moreWidth = 84;
      let used = 0;
      let count = 0;
      for (let i = 0; i < groups.length; i++) {
        const width = (widths.current[i] ?? 140) + 4;
        const remaining = groups.length - (i + 1);
        if (used + width + (remaining > 0 ? moreWidth : 0) > available) break;
        used += width;
        count++;
      }
      setVisibleCount(Math.max(0, count));
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(list);
    return () => observer.disconnect();
  }, [groups]);

  const shown = groups.slice(0, visibleCount);
  const hidden = groups.slice(visibleCount);

  const menu = (id: string, label: string, items: { group?: string; item: NavItem }[], isActive: boolean) => {
    const isOpen = popover.open === id;
    const menuId = `topnav-menu-${id}`;
    return (
      <li className="topnav__entry" key={id}>
        <button
          type="button"
          data-group-button={id === MORE ? undefined : true}
          className={`topnav__button${isActive ? " topnav__button--active" : ""}`}
          aria-expanded={isOpen}
          aria-controls={menuId}
          onClick={() => popover.toggle(id)}
        >
          {id === MORE && <Icon name="more" size={18} />}
          <span>{label}</span>
          <Icon name="chevron-down" size={14} />
        </button>
        {isOpen && (
          <div className="topnav__menu" id={menuId} onKeyDown={(event) => {
              // Sin propagar: la barra (ul) también reacciona a Inicio/Fin.
              event.stopPropagation();
              moveFocusWithArrows(event, "vertical");
            }}
          >
            <ul>
              {items.map(({ group, item }, index) => (
                <li key={item.to}>
                  {group && (index === 0 || items[index - 1]?.group !== group) && (
                    <span className="topnav__menu-heading">{group}</span>
                  )}
                  <Link
                    to={item.to}
                    className={`topnav__link${item === active ? " topnav__link--active" : ""}`}
                    aria-current={item === active ? "page" : undefined}
                    onClick={popover.close}
                  >
                    <Icon name={item.icon} size={18} />
                    <span>{item.label}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        )}
      </li>
    );
  };

  return (
    <nav className="topnav" aria-label="Navegación principal" ref={rootRef}>
      <ul className="topnav__list" ref={listRef} onKeyDown={(event) => moveFocusWithArrows(event, "horizontal")}>
        {shown.map((group) =>
          menu(
            group.id,
            group.label,
            group.items.map((item) => ({ item })),
            active ? group.items.includes(active) : false,
          ),
        )}
        {hidden.length > 0 &&
          menu(
            MORE,
            "Más",
            hidden.flatMap((group) => group.items.map((item) => ({ group: group.label, item }))),
            active ? hidden.some((group) => group.items.includes(active)) : false,
          )}
      </ul>
    </nav>
  );
}

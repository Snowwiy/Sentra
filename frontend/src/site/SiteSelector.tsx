import { useId } from "react";
import type { Site } from "../api/types";
import { useSite } from "./SiteContext";

/** Nombre visible de un site en listas y selectores ("(deshabilitado)" si no está activo). */
export function siteOptionLabel(site: Site): string {
  const suffix = site.is_default ? " (por defecto)" : site.status === "disabled" ? " (deshabilitado)" : "";
  return `${site.name}${suffix}`;
}

/**
 * Selector de alcance de la barra superior: "Todos los sites" o un site no archivado.
 * Discreto (un select pequeño) pero con etiqueta visible para lectores de pantalla y teclado.
 */
export function SiteSelector() {
  const site = useSite();
  const id = useId();
  // Con un solo site (instalación clásica) no hay nada que elegir: no se muestra.
  if (site.selectableSites.length <= 1 && site.selection === "all") return null;
  return (
    <div className="site-selector">
      <label htmlFor={id} className="site-selector__label">
        Site
      </label>
      <select
        id={id}
        className="input input--select site-selector__select"
        value={site.selection}
        onChange={(event) => site.setSelection(event.target.value)}
      >
        <option value="all">Todos los sites</option>
        {site.selectableSites.map((s) => (
          <option key={s.site_id} value={s.site_id}>
            {siteOptionLabel(s)}
          </option>
        ))}
      </select>
    </div>
  );
}

/**
 * Chip que deja claro qué alcance se está viendo en una página filtrada. `siteId` permite
 * mostrar el eco del servidor (p. ej. DashboardSummary.site_id) en lugar de la selección local.
 */
export function SiteScopeChip({ siteId }: { siteId?: string | null }) {
  const site = useSite();
  const effective = siteId === undefined ? site.scopeId : (siteId ?? undefined);
  if (!effective) {
    // Sin varios sites no aporta nada decir "todos".
    if (site.selectableSites.length <= 1) return null;
    return (
      <span className="badge badge--muted site-chip" title="Alcance: todos los sites">
        Site: todos
      </span>
    );
  }
  const name = site.sites.find((s) => s.site_id === effective)?.name ?? effective.slice(0, 8);
  return (
    <span className="badge badge--info site-chip" title={`Alcance: site ${name}`}>
      Site: {name}
    </span>
  );
}

/**
 * Chip de alcance y, con un site elegido, aviso de que las tarjetas de resumen de la página
 * son globales (sus endpoints de resumen no se filtran por site; la tabla sí).
 */
export function ScopeNote() {
  const site = useSite();
  return (
    <p className="muted small page__scope">
      <SiteScopeChip />
      {site.scopeId && <span>Las tarjetas de resumen incluyen todos los sites; la tabla muestra solo este site.</span>}
    </p>
  );
}

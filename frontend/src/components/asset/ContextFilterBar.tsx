import { ENVIRONMENT_LABELS, ENVIRONMENT_ORDER, ROLE_LABELS, ROLE_ORDER, ZONE_LABELS, ZONE_ORDER } from "../../lib/assetContext";
import { CONTEXT_FILTER_KEYS, contextFilterCount, type DeviceFilters } from "../../lib/deviceFilters";
import { CRITICALITY_LABELS, CRITICALITY_ORDER } from "../../lib/risk";
import { FilterSelect } from "../ListControls";

/**
 * Filtros de contexto (Fase 4L) y de ciclo de vida (Fase 5C.2) de la lista de dispositivos,
 * plegados para no ocupar la cabecera. Se aplican en el servidor. Antes vivían en el
 * dashboard; desde la Fase 7A.5 los usa Red › Dispositivos.
 */
export function ContextFilterBar({
  filters,
  onChange,
}: {
  filters: DeviceFilters;
  onChange: (changes: Partial<DeviceFilters>) => void;
}) {
  const active = contextFilterCount(filters);
  const select = <K extends (typeof CONTEXT_FILTER_KEYS)[number]>(key: K) => (value: string) =>
    onChange({ [key]: value } as Partial<DeviceFilters>);
  return (
    <details className="context-filters" open={active > 0}>
      <summary className="small">Filtros de contexto{active > 0 && ` (${active})`}</summary>
      <div className="panel__toolbar panel__toolbar--filters">
        <FilterSelect
          label="Criticidad"
          value={filters.criticality}
          options={CRITICALITY_ORDER.map((value) => ({ value, label: CRITICALITY_LABELS[value] }))}
          onChange={select("criticality")}
        />
        <FilterSelect
          label="Rol"
          value={filters.role}
          options={ROLE_ORDER.map((value) => ({ value, label: ROLE_LABELS[value] }))}
          onChange={select("role")}
        />
        <FilterSelect
          label="Entorno"
          value={filters.environment}
          options={ENVIRONMENT_ORDER.map((value) => ({ value, label: ENVIRONMENT_LABELS[value] }))}
          onChange={select("environment")}
        />
        <FilterSelect
          label="Zona"
          value={filters.zone}
          options={ZONE_ORDER.map((value) => ({ value, label: ZONE_LABELS[value] }))}
          onChange={select("zone")}
        />
        <FilterSelect
          label="Internet"
          value={filters.internet}
          options={[
            { value: "true", label: "Expuesto" },
            { value: "false", label: "No expuesto" },
            { value: "unknown", label: "Desconocida" },
          ]}
          onChange={select("internet")}
        />
        <FilterSelect
          label="Ciclo de vida"
          value={filters.lifecycle}
          options={[
            { value: "stale", label: "Stale (inactivos)" },
            { value: "cleanup_candidate", label: "Candidatos a limpieza" },
          ]}
          onChange={select("lifecycle")}
        />
        <input
          className="input"
          aria-label="Equipo/Departamento"
          placeholder="Equipo/Departamento"
          value={filters.department}
          maxLength={64}
          onChange={(e) => onChange({ department: e.target.value })}
        />
        <input
          className="input"
          aria-label="Tag"
          placeholder="Tag"
          value={filters.tag}
          maxLength={32}
          onChange={(e) => onChange({ tag: e.target.value })}
        />
        {active > 0 && (
          <button
            type="button"
            className="button button--ghost button--small"
            onClick={() => onChange(Object.fromEntries(CONTEXT_FILTER_KEYS.map((key) => [key, ""])))}
          >
            Limpiar
          </button>
        )}
      </div>
    </details>
  );
}

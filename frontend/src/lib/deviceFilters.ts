// Fase 7A.5: filtros de Red › Dispositivos en la URL (?status=offline&q=...). Así un enlace del
// Panel, del Resumen o de un descubrimiento abre la tabla ya filtrada y el filtro sobrevive a
// recargar o a guardarlo como marcador. Todo valor se valida aquí y otra vez en el servidor.
import type { AssetQuery, AssetSortKey } from "../api/sentra";
import type {
  AssetCriticality,
  AssetEnvironment,
  AssetRole,
  AssetStatus,
  LifecycleFilter,
  MonitoringMethod,
  NetworkZone,
} from "../api/types";
import { ENVIRONMENT_ORDER, ROLE_ORDER, ZONE_ORDER } from "./assetContext";
import { CRITICALITY_ORDER } from "./risk";

export const DEVICES_PATH = "/network/devices";

export type DeviceSortKey =
  | "name"
  | "ip"
  | "type"
  | "status"
  | "method"
  | "criticality"
  | "first"
  | "network"
  | "last"
  | "ports";

/** Columna de la tabla -> orden de GET /assets. */
export const DEVICE_SORT_KEYS: Record<DeviceSortKey, AssetSortKey> = {
  name: "name",
  ip: "ip",
  type: "type",
  status: "status",
  method: "method",
  criticality: "criticality",
  first: "first_seen",
  network: "network_seen",
  last: "last_seen",
  ports: "ports",
};

export type InternetFilter = "true" | "false" | "unknown";

export interface DeviceFilters {
  q: string;
  status: AssetStatus | "";
  method: MonitoringMethod | "";
  /** Tipo de dispositivo o "unknown" (sin tipo). */
  type: string;
  subnet: string;
  criticality: AssetCriticality | "";
  role: AssetRole | "";
  environment: AssetEnvironment | "";
  zone: NetworkZone | "";
  internet: InternetFilter | "";
  lifecycle: LifecycleFilter | "";
  department: string;
  tag: string;
  /** Mostrar también los archivados (por defecto se ocultan). */
  archived: boolean;
  sort: DeviceSortKey;
  dir: "asc" | "desc";
}

export const DEFAULT_DEVICE_FILTERS: DeviceFilters = {
  q: "",
  status: "",
  method: "",
  type: "",
  subnet: "",
  criticality: "",
  role: "",
  environment: "",
  zone: "",
  internet: "",
  lifecycle: "",
  department: "",
  tag: "",
  archived: false,
  sort: "name",
  dir: "asc",
};

/** Filtros de contexto (Fase 4L) y de ciclo de vida: los del panel plegable. */
export const CONTEXT_FILTER_KEYS = [
  "criticality",
  "role",
  "environment",
  "zone",
  "internet",
  "lifecycle",
  "department",
  "tag",
] as const;

const STATUSES: readonly AssetStatus[] = ["online", "offline", "unknown"];
export const METHODS: readonly MonitoringMethod[] = ["discovered", "agentless", "agent"];
const INTERNET: readonly InternetFilter[] = ["true", "false", "unknown"];
const LIFECYCLES: readonly LifecycleFilter[] = ["stale", "cleanup_candidate"];
const SORTS = Object.keys(DEVICE_SORT_KEYS) as DeviceSortKey[];
// Igual que el patrón del servidor para device_type: un valor raro se descarta, no se envía.
const TYPE_PATTERN = /^[a-z_]{1,32}$/;
// Límites de texto del servidor (q 200, departamento 64, tag 32 normalizado).
const TEXT_LIMITS = { q: 200, subnet: 64, department: 64, tag: 64 } as const;

function oneOf<T extends string>(value: string | null, allowed: readonly T[]): T | "" {
  return value !== null && (allowed as readonly string[]).includes(value) ? (value as T) : "";
}

function text(value: string | null, max: number): string {
  return (value ?? "").slice(0, max);
}

/** Filtros leídos de la URL; lo que no es válido vuelve a su valor por defecto. */
export function readDeviceFilters(params: URLSearchParams): DeviceFilters {
  const type = params.get("type") ?? "";
  return {
    q: text(params.get("q"), TEXT_LIMITS.q),
    status: oneOf(params.get("status"), STATUSES),
    method: oneOf(params.get("method"), METHODS),
    type: TYPE_PATTERN.test(type) ? type : "",
    subnet: text(params.get("subnet"), TEXT_LIMITS.subnet).trim(),
    criticality: oneOf(params.get("criticality"), CRITICALITY_ORDER),
    role: oneOf(params.get("role"), ROLE_ORDER),
    environment: oneOf(params.get("environment"), ENVIRONMENT_ORDER),
    zone: oneOf(params.get("zone"), ZONE_ORDER),
    internet: oneOf(params.get("internet"), INTERNET),
    lifecycle: oneOf(params.get("lifecycle"), LIFECYCLES),
    department: text(params.get("department"), TEXT_LIMITS.department),
    tag: text(params.get("tag"), TEXT_LIMITS.tag),
    archived: params.get("archived") === "include",
    sort: oneOf(params.get("sort"), SORTS) || DEFAULT_DEVICE_FILTERS.sort,
    dir: params.get("dir") === "desc" ? "desc" : "asc",
  };
}

/** Query string con solo lo que difiere del valor por defecto ("" si no hay nada). */
export function deviceSearch(filters: Partial<DeviceFilters>): string {
  const full = { ...DEFAULT_DEVICE_FILTERS, ...filters };
  const params = new URLSearchParams();
  for (const key of Object.keys(DEFAULT_DEVICE_FILTERS) as (keyof DeviceFilters)[]) {
    const value = full[key];
    if (key === "archived") {
      if (value) params.set("archived", "include");
    } else if (key === "sort" || key === "dir") {
      // El orden se guarda entero si no es el de por defecto: dir sin sort no significa nada.
      if (full.sort !== DEFAULT_DEVICE_FILTERS.sort || full.dir !== DEFAULT_DEVICE_FILTERS.dir) {
        params.set(key, String(value));
      }
    } else if (typeof value === "string" && value !== "") {
      params.set(key, value);
    }
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

/** Enlace a Red › Dispositivos con estos filtros. */
export function devicesLink(filters: Partial<DeviceFilters> = {}): string {
  return `${DEVICES_PATH}${deviceSearch(filters)}`;
}

/** Filtros de la tabla -> GET /assets (sin paginación ni site, que pone quien llama). */
export function toAssetQuery(f: DeviceFilters): AssetQuery {
  return {
    q: f.q.trim() || undefined,
    status: f.status || undefined,
    method: f.method || undefined,
    deviceType: f.type || undefined,
    subnet: f.subnet || undefined,
    criticality: f.criticality || undefined,
    role: f.role || undefined,
    environment: f.environment || undefined,
    networkZone: f.zone || undefined,
    internetExposed: f.internet || undefined,
    lifecycle: f.lifecycle || undefined,
    department: f.department.trim() || undefined,
    tag: f.tag.trim() || undefined,
    archived: f.archived ? "include" : undefined,
    // Por nombre ascendente es el orden por defecto del servidor: no hace falta enviarlo.
    sort: f.sort === "name" && f.dir === "asc" ? undefined : DEVICE_SORT_KEYS[f.sort],
    order: f.sort === "name" && f.dir === "asc" ? undefined : f.dir,
  };
}

/** Cuántos filtros de contexto o ciclo de vida hay activos. */
export function contextFilterCount(f: DeviceFilters): number {
  return CONTEXT_FILTER_KEYS.filter((key) => f[key] !== "").length;
}

/** ¿Hay algún filtro que acote la lista (además del orden)? */
export function isFiltered(f: DeviceFilters): boolean {
  return Boolean(f.q.trim() || f.status || f.method || f.type || f.subnet) || contextFilterCount(f) > 0;
}

// API de la Fase 7A.6: tareas de caso y solicitudes de control de red.
//
// Módulo aparte de sentra.ts: solo lo importan vistas cargadas con React.lazy (detalle del
// incidente y Mis tareas). Toda mutación lleva la `version` leída: si otro operador cambió la
// fila, la API responde 409 (task_conflict / network_control_conflict) y la UI recarga.
import { apiGet, apiPatch, apiPost } from "./client";
import type {
  CaseEvidenceType,
  TaskRead,
  TaskCreate,
  TaskList,
  CaseTaskStatus,
  TaskUpdate,
  ControlCapabilities,
  NetworkControlRead,
  NetworkControlCreate,
  NetworkControlList,
  NetworkControlStatus,
} from "./types";

const enc = encodeURIComponent;

function query(params: Record<string, string | number | boolean | string[] | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === false) continue;
    if (Array.isArray(value)) value.forEach((item) => search.append(key, item));
    else search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

export interface TaskQuery {
  /** Solo las tareas asignadas al usuario de la sesión. */
  mine?: boolean;
  status?: CaseTaskStatus[];
  limit?: number;
  offset?: number;
}

export const tasksApi = {
  forIncident: (incidentId: string, signal?: AbortSignal) =>
    apiGet<TaskList>(`/incidents/${enc(incidentId)}/tasks`, { signal }),
  list: (q: TaskQuery = {}, signal?: AbortSignal) =>
    apiGet<TaskList>(
      `/tasks${query({ mine: q.mine, status: q.status, limit: q.limit, offset: q.offset || undefined })}`,
      { signal },
    ),
  create: (incidentId: string, input: TaskCreate) =>
    apiPost<TaskRead>(`/incidents/${enc(incidentId)}/tasks`, input),
  update: (taskId: string, version: number, changes: TaskUpdate) =>
    apiPatch<TaskRead>(`/tasks/${enc(taskId)}`, { version, ...changes }),
  /** Sin `userId`: asignársela uno mismo. No ejecuta ninguna acción técnica. */
  assign: (taskId: string, version: number, userId?: string) =>
    apiPost<TaskRead>(`/tasks/${enc(taskId)}/assign`, { version, user_id: userId ?? null }),
  unassign: (taskId: string, version: number) => apiPost<TaskRead>(`/tasks/${enc(taskId)}/unassign`, { version }),
  addEvidence: (taskId: string, version: number, type: CaseEvidenceType, id: string) =>
    apiPost<TaskRead>(`/tasks/${enc(taskId)}/evidence`, { version, type, id }),
};

export const networkControlsApi = {
  forIncident: (incidentId: string, status?: NetworkControlStatus[], signal?: AbortSignal) =>
    apiGet<NetworkControlList>(`/network-controls${query({ incident_id: incidentId, status, limit: 200 })}`, {
      signal,
    }),
  capabilities: (signal?: AbortSignal) => apiGet<ControlCapabilities>("/network-controls/capabilities", { signal }),
  request: (incidentId: string, input: NetworkControlCreate) =>
    apiPost<NetworkControlRead>(`/incidents/${enc(incidentId)}/network-controls`, input),
  /** Aprobar registra la decisión; no aplica nada en la red. */
  approve: (controlId: string, version: number, note?: string) =>
    apiPost<NetworkControlRead>(`/network-controls/${enc(controlId)}/approve`, { version, note: note?.trim() || null }),
  reject: (controlId: string, version: number, note: string) =>
    apiPost<NetworkControlRead>(`/network-controls/${enc(controlId)}/reject`, { version, note: note.trim() }),
  cancel: (controlId: string, version: number) =>
    apiPost<NetworkControlRead>(`/network-controls/${enc(controlId)}/cancel`, { version }),
  /** Registra que alguien lo aplicó FUERA de Sentra (dónde y cómo, en la nota). */
  markApplied: (controlId: string, version: number, note: string) =>
    apiPost<NetworkControlRead>(`/network-controls/${enc(controlId)}/mark-applied`, { version, note: note.trim() }),
};

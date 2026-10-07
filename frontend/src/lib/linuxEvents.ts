// Eventos Linux del journal (Fase 5C.1): etiquetas en español de los tipos normalizados que
// envía el agente (agent/sentra_agent/linux_events.py) y de los estados de cobertura.
import type { Asset, EventCoverageState } from "../api/types";

export const LINUX_EVENT_TYPES: Record<string, string> = {
  auth_failure: "Autenticación fallida",
  auth_success: "Autenticación correcta",
  ssh_invalid_user: "SSH: usuario inexistente",
  ssh_max_auth_exceeded: "SSH: demasiados intentos",
  pam_auth_failure: "PAM: fallo (duplicado de sshd)",
  session_opened: "Sesión abierta",
  session_closed: "Sesión cerrada",
  login_failure: "Login fallido (consola)",
  sudo_command: "Comando con sudo",
  sudo_auth_failure: "sudo: contraseña incorrecta",
  sudo_not_allowed: "sudo: no autorizado",
  sudo_error: "sudo: error",
  account_created: "Cuenta creada",
  account_deleted: "Cuenta eliminada",
  account_changed: "Cuenta modificada",
  account_locked: "Cuenta bloqueada",
  account_unlocked: "Cuenta desbloqueada",
  password_changed: "Contraseña cambiada",
  group_created: "Grupo creado",
  group_deleted: "Grupo eliminado",
  group_member_added: "Añadido a grupo",
  group_member_removed: "Retirado de grupo",
  service_started: "Servicio iniciado",
  service_stopped: "Servicio detenido",
  service_failed: "Servicio con fallo",
  service_start_failed: "Servicio no arrancó",
  service_exited: "Servicio terminó con error",
  systemd_reload: "Recarga de systemd",
  oom_kill: "Kernel: proceso terminado por memoria (OOM)",
  filesystem_error: "Kernel: error de sistema de ficheros",
  hardware_error: "Kernel: error de hardware",
  kernel_bug: "Kernel: fallo interno",
  kernel_error: "Kernel: error",
};

/** Fuentes que el agente lee del journal (provider de los eventos). */
export const LINUX_PROVIDERS = ["sshd", "sudo", "systemd", "kernel", "auditd", "su", "login", "useradd", "usermod", "userdel", "gpasswd", "passwd"];

export const COVERAGE_LABELS: Record<EventCoverageState, string> = {
  active: "Activo",
  unavailable: "No disponible",
  no_permission: "Sin permiso",
  error: "Error",
  disabled: "Desactivado",
};

export const COVERAGE_CLASSES: Record<EventCoverageState, string> = {
  active: "badge--ok",
  unavailable: "badge--muted",
  no_permission: "badge--crit",
  error: "badge--crit",
  disabled: "badge--muted",
};

export const COVERAGE_SOURCES: { key: string; label: string; hint: string }[] = [
  { key: "journal", label: "Journal", hint: "Lectura del journal de systemd (grupo systemd-journal)" },
  { key: "sshd", label: "sshd", hint: "Accesos SSH; no disponible si sshd no está instalado" },
  { key: "sudo", label: "sudo", hint: "Comandos con sudo y fallos de autenticación" },
  { key: "accounts", label: "Cuentas", hint: "su, login, useradd/usermod/userdel, grupos, passwd" },
  { key: "systemd", label: "systemd", hint: "Servicios iniciados, detenidos y con fallo" },
  { key: "kernel", label: "Kernel", hint: "OOM, errores de disco/sistema de ficheros y hardware" },
  { key: "auditd", label: "auditd", hint: "Opcional: solo si auditd envía sus registros al journal" },
];

export function eventTypeLabel(type: string | null): string {
  if (!type) return "—";
  if (type.startsWith("audit_")) return `auditd: ${type.slice(6).replace(/_/g, " ")}`;
  return LINUX_EVENT_TYPES[type] ?? type;
}

export function isLinux(asset: Pick<Asset, "os_name">): boolean {
  return (asset.os_name ?? "").toLowerCase().includes("linux");
}

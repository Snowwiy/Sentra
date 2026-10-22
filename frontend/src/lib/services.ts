// Corrección 6C: qué servicio hay detrás de cada puerto abierto y cómo llegar a él.
//
// Solo se traduce el número de puerto a un protocolo conocido; nunca se sondea nada desde el
// navegador ni se pide nada al backend. Un enlace solo se ofrece para HTTP/HTTPS y siempre a
// una URL construida aquí con esquema http/https, la IP del activo (o un nombre DNS confirmado)
// y el puerto: nada que venga de la red se usa como URL.
import type { ObservedName } from "../api/types";
import { ipv4ToNumber } from "./net";

export type WebScheme = "http" | "https";

export interface PortService {
  port: number;
  /** Protocolo para mostrar ("HTTPS", "SSH"); null si el puerto no es uno conocido. */
  protocol: string | null;
  /** Esquema web si el puerto sirve HTTP/HTTPS (o probablemente lo hace). */
  web: WebScheme | null;
  /** true si el protocolo es solo lo habitual en ese puerto, no su asignación estándar. */
  inferred: boolean;
}

// Puertos con asignación IANA para HTTP/HTTPS: se presentan como el protocolo, sin más.
const STANDARD_WEB: Record<number, WebScheme> = { 80: "http", 443: "https" };

// Puertos alternativos donde HTTP/HTTPS es lo habitual (paneles de routers, NAS, cámaras,
// servidores de desarrollo) pero no está garantizado: se etiquetan como "probable".
const LIKELY_WEB: Record<number, WebScheme> = {
  8000: "http",
  8008: "http",
  8080: "http",
  8081: "http",
  8888: "http",
  8443: "https",
  9443: "https",
};

// Protocolos que no son web: se nombran y se copia el destino, nunca se enlazan como HTTP.
const OTHER_PROTOCOLS: Record<number, string> = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  110: "POP3",
  135: "RPC",
  139: "NetBIOS",
  143: "IMAP",
  389: "LDAP",
  445: "SMB",
  465: "SMTPS",
  548: "AFP",
  554: "RTSP",
  587: "SMTP",
  631: "IPP",
  636: "LDAPS",
  993: "IMAPS",
  995: "POP3S",
  1433: "MSSQL",
  1883: "MQTT",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  5900: "VNC",
  8009: "Cast",
  8883: "MQTTS",
  9100: "JetDirect",
};

export function portService(port: number): PortService {
  const standard = STANDARD_WEB[port];
  if (standard) return { port, protocol: standard.toUpperCase(), web: standard, inferred: false };
  const likely = LIKELY_WEB[port];
  if (likely) return { port, protocol: likely.toUpperCase(), web: likely, inferred: true };
  return { port, protocol: OTHER_PROTOCOLS[port] ?? null, web: null, inferred: false };
}

const IPV6 = /^[0-9a-f:.]+$/i;
// Nombre DNS: etiquetas de 1-63 caracteres alfanuméricos o guion, sin guion en los extremos.
const DNS_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i;

function validHostname(name: string): boolean {
  if (name.length > 253) return false;
  const labels = name.split(".");
  // Al menos dos etiquetas: un nombre suelto dependería del sufijo DNS del navegador.
  return labels.length >= 2 && labels.every((label) => DNS_LABEL.test(label));
}

/** Host para una URL o un destino: IPv4 tal cual, IPv6 entre corchetes; null si no es una IP. */
export function hostForAddress(address: string): string | null {
  if (ipv4ToNumber(address) !== null) return address;
  if (address.includes(":") && IPV6.test(address)) return `[${address.toLowerCase()}]`;
  return null;
}

/** "192.168.1.5:22" o "[fd00::5]:22"; null si la dirección no es una IP válida. */
export function serviceDestination(address: string, port: number): string | null {
  const host = hostForAddress(address);
  if (host === null || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return `${host}:${port}`;
}

/**
 * URL http(s)://host:puerto. Se reconstruye con URL y se comprueba que el resultado sigue
 * siendo exactamente ese esquema, host y puerto: si algo no cuadra no hay enlace.
 */
export function serviceUrl(scheme: WebScheme, host: string, port: number): string | null {
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  let url: URL;
  try {
    url = new URL(`${scheme}://${host}:${port}/`);
  } catch {
    return null;
  }
  const defaultPort = scheme === "http" ? 80 : 443;
  const expectedPort = port === defaultPort ? "" : String(port);
  if (url.protocol !== `${scheme}:` || url.port !== expectedPort || url.username || url.password) {
    return null;
  }
  if (url.hostname.toLowerCase() !== host.toLowerCase()) return null;
  return url.href;
}

/**
 * Nombre DNS que se puede ofrecer para abrir un servicio: el DNS inverso del activo solo si
 * el servidor confirmó que resuelve a su IP (FCrDNS) y no es un nombre genérico. El puerto
 * no "apunta" a ese nombre: el nombre resuelve a la IP, y el servicio podría responder
 * distinto según el nombre con el que se le llame.
 */
export function confirmedHostname(asset: {
  reverse_dns: string | null;
  observed_names?: ObservedName[];
}): string | null {
  const name = asset.reverse_dns?.replace(/\.$/, "") ?? "";
  if (!name || !validHostname(name)) return null;
  const confirmed = (asset.observed_names ?? []).some(
    (item) => item.source === "reverse_dns" && item.confirmed === true && item.kind !== "generic" && !item.stale,
  );
  return confirmed ? name.toLowerCase() : null;
}

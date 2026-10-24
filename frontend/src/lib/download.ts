// Mensajes de error de las descargas de ficheros (Fase 6D.6).
//
// Antes, cualquier fallo de una descarga acababa en el mensaje genérico del cliente y "No se
// pudo conectar con la API de Sentra" aparecía también cuando la API sí había respondido (un
// 502/504 del proxy de Vite, un cuerpo cortado a mitad). Aquí cada causa tiene su texto para
// que quien lo lee sepa qué hacer. Ningún fallo se oculta salvo la cancelación, que la pide la
// propia interfaz (desmontar la página, pulsar de nuevo) y no es un error.
import { ApiError, type DownloadedFile } from "../api/client";
import { ChecksumUnavailableError, sha256Hex } from "./reports";

const GATEWAY_STATUSES = new Set([502, 503, 504]);

/** true si el error es una cancelación pedida por la interfaz (no se muestra aviso). */
export function isAbortError(error: unknown): boolean {
  return (
    (error instanceof DOMException && error.name === "AbortError") ||
    (error instanceof Error && error.name === "AbortError")
  );
}

/**
 * Texto para el usuario de un error de descarga, o undefined si fue una cancelación.
 * `what` nombra lo que se descargaba ("el informe").
 */
export function describeDownloadError(error: unknown, what = "el fichero"): string | undefined {
  if (isAbortError(error)) return undefined;
  if (!(error instanceof ApiError)) {
    const detail = error instanceof Error && error.message ? `: ${error.message}` : "";
    return `No se pudo completar la descarga${detail}.`;
  }
  if (error.code === "timeout") {
    return "La API de Sentra no respondió a tiempo. Vuelve a intentarlo en unos segundos.";
  }
  if (error.code === "download_interrupted") return error.message;
  if (error.status === 0) {
    return "No se pudo conectar con la API de Sentra: comprueba que el servidor está en marcha y que hay conexión de red.";
  }
  // Un 502/503/504 SIN el sobre de error de Sentra lo genera el proxy que hay delante de la API
  // (Vite en desarrollo, el proxy inverso en producción): la API no contestó o tardó demasiado.
  if (GATEWAY_STATUSES.has(error.status) && error.code === "network_error") {
    return error.status === 504
      ? `El proxy delante de la API cortó la descarga por tiempo de espera (HTTP 504). ${capitalize(what)} sigue en el servidor: vuelve a intentarlo.`
      : `El proxy delante de la API no obtuvo respuesta de Sentra (HTTP ${error.status}). Comprueba que la API está en marcha y vuelve a intentarlo.`;
  }
  if (error.status === 401) return "La sesión ha caducado. Inicia sesión de nuevo para descargar.";
  if (error.status === 403) return `Tu rol no permite descargar ${what}.`;
  if (error.status === 404 || error.status === 410) {
    return error.code === "report_artifact_unavailable"
      ? error.message
      : `${capitalize(what)} ya no existe o ha caducado. Recarga la página para ver su estado.`;
  }
  if (error.status >= 500) {
    // Con sobre de error se conserva el mensaje (ya traducido) del servidor; sin él, el código.
    return error.code === "http_error"
      ? `Error del servidor (HTTP ${error.status}) sin más detalle.`
      : `Error del servidor (HTTP ${error.status}): ${error.message}`;
  }
  return error.message;
}

function capitalize(text: string): string {
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : text;
}

/**
 * Comprobación OBLIGATORIA del SHA-256 de una descarga antes de guardarla (falla cerrado).
 * Devuelve el motivo del rechazo, o undefined si los bytes coinciden con el hash esperado
 * (la cabecera X-Sentra-SHA256 o, si falta, el valor conocido por el JSON del recurso).
 * El hash se calcula sobre los bytes leídos de la respuesta, nunca releyendo el Blob.
 */
export async function verifyDownload(file: DownloadedFile, knownSha256?: string | null): Promise<string | undefined> {
  const expected = (file.sha256 || knownSha256 || "").trim().toLowerCase();
  if (!expected) return "El servidor no indicó el SHA-256 del fichero: no se ha guardado.";
  let actual: string;
  try {
    actual = await sha256Hex(file.bytes);
  } catch (err) {
    return err instanceof ChecksumUnavailableError
      ? "Este navegador no puede verificar el SHA-256: no se ha guardado."
      : "No se pudo verificar el SHA-256 del fichero descargado: no se ha guardado.";
  }
  if (actual !== expected) {
    return "El fichero descargado no coincide con su SHA-256: no se ha guardado. Vuelve a intentarlo.";
  }
  return undefined;
}

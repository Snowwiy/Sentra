import { useEffect, useRef, useState } from "react";
import { ApiError } from "../../api/client";
import { forensicsApi } from "../../api/sentra6e";
import { describeDownloadError, verifyDownload } from "../../lib/download";
import { safeFilename, saveBlob } from "../../lib/reports";

/**
 * Descarga del paquete de evidencias (Fase 6E.6): POST con la sesión → bytes → comprobación
 * OBLIGATORIA del SHA-256 de X-Sentra-SHA256 → enlace temporal. Si el hash falta, no coincide o
 * no se puede calcular, no se guarda nada (falla cerrado, igual que los informes).
 *
 * Si la investigación tiene artefactos cuyo hash no coincidió con el del agente, el servidor
 * responde 409 evidence_integrity_mismatch: se explica el riesgo y solo se reintenta con
 * acknowledge_mismatch=true si la persona lo acepta de forma explícita.
 */
export function PackageDownload({
  investigationId,
  mismatchCount,
  onDownloaded,
}: {
  investigationId: string;
  mismatchCount: number;
  onDownloaded: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [needsAck, setNeedsAck] = useState(false);
  const [done, setDone] = useState<string>();
  const controllerRef = useRef<AbortController | null>(null);
  useEffect(() => () => controllerRef.current?.abort(), []);

  const download = async (acknowledge: boolean) => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setBusy(true);
    setError(undefined);
    setDone(undefined);
    try {
      const file = await forensicsApi.downloadPackage(investigationId, acknowledge, controller.signal);
      if (controller.signal.aborted) return;
      // Sin fallback al JSON: el hash de un paquete recién generado solo viaja en la cabecera.
      const rejected = await verifyDownload(file);
      if (controller.signal.aborted) return;
      if (rejected) {
        setError(rejected);
        return;
      }
      saveBlob(file.blob, safeFilename(file.filename, `sentra-investigation-${investigationId}.zip`));
      setNeedsAck(false);
      setDone(`Paquete verificado (SHA-256 ${file.sha256 ?? ""}) y guardado.`);
      onDownloaded();
    } catch (err) {
      if (controller.signal.aborted) return;
      if (err instanceof ApiError && err.code === "evidence_integrity_mismatch") {
        setNeedsAck(true);
        return;
      }
      const message = describeDownloadError(err, "el paquete de evidencias");
      if (message) setError(message);
    } finally {
      if (controllerRef.current === controller) {
        controllerRef.current = null;
        setBusy(false);
      }
    }
  };

  return (
    <div className="stack">
      <div className="actions">
        <button
          type="button"
          className="button button--primary"
          disabled={busy}
          aria-busy={busy}
          onClick={() => void download(false)}
        >
          {busy ? "Generando paquete…" : "Descargar paquete de evidencias"}
        </button>
      </div>
      {needsAck && (
        <div className="banner banner--warn stack" role="alert" aria-label="Aviso de integridad">
          <strong>Hay evidencias cuyo SHA-256 no coincide con el que calculó el agente</strong>
          <span className="small">
            {mismatchCount > 0 ? `${mismatchCount} artefacto(s) ` : "Algún artefacto "}
            pudo alterarse entre el equipo y el servidor. El paquete los incluirá marcados como no verificados en el
            manifest, y la descarga quedará registrada con esta aceptación.
          </span>
          <div className="actions">
            <button type="button" className="button" disabled={busy} onClick={() => setNeedsAck(false)}>
              Cancelar
            </button>
            <button type="button" className="button button--danger" disabled={busy} onClick={() => void download(true)}>
              Acepto el aviso: descargar igualmente
            </button>
          </div>
        </div>
      )}
      {error && (
        <span className="text-crit small" role="alert">
          {error}
        </span>
      )}
      {done && (
        <span className="text-ok small" role="status">
          {done}
        </span>
      )}
    </div>
  );
}

import { useEffect, useRef, useState } from "react";
import { reportsApi } from "../../api/sentra";
import type { Report, ReportStatus } from "../../api/types";
import { describeDownloadError } from "../../lib/download";
import {
  ChecksumUnavailableError,
  REPORT_STATUS_BADGES,
  REPORT_STATUS_LABELS,
  safeFilename,
  saveBlob,
  sha256Hex,
} from "../../lib/reports";

export function ReportStatusBadge({ status, cancelRequested = false }: { status: ReportStatus; cancelRequested?: boolean }) {
  return (
    <span className={REPORT_STATUS_BADGES[status] ?? "badge"}>
      {REPORT_STATUS_LABELS[status] ?? status}
      {cancelRequested && status === "running" ? " · cancelando" : ""}
    </span>
  );
}

/**
 * Descarga el artefacto: fetch con la sesión → Blob → comprobación OBLIGATORIA del SHA-256 →
 * enlace temporal con `download`. Si el hash no coincide o no se puede calcular, no se crea
 * ningún ObjectURL ni enlace: falla cerrado. El contenido nunca se muestra en la app.
 *
 * Fase 6D.6: la descarga se cancela al desmontar el botón (cambio de página) y una
 * cancelación no muestra aviso; cada fallo real tiene su propio mensaje (lib/download.ts) y el
 * botón vuelve siempre a su estado normal.
 */
export function DownloadReportButton({ report, small = true }: { report: Report; small?: boolean }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const controllerRef = useRef<AbortController | null>(null);
  useEffect(() => () => controllerRef.current?.abort(), []);
  if (report.status !== "succeeded" || !report.artifact) return null;
  const artifact = report.artifact;
  const download = async () => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setBusy(true);
    setError(undefined);
    try {
      const file = await reportsApi.download(report.id, controller.signal);
      if (controller.signal.aborted) return;
      const expected = (file.sha256 || artifact.sha256 || "").trim().toLowerCase();
      if (!expected) {
        setError("El servidor no indicó el SHA-256 del fichero: no se ha guardado.");
        return;
      }
      let actual: string;
      try {
        actual = await sha256Hex(file.blob);
      } catch (err) {
        setError(
          err instanceof ChecksumUnavailableError
            ? "Este navegador no puede verificar el SHA-256 (requiere HTTPS o localhost): no se ha guardado."
            : "No se pudo verificar el SHA-256 del fichero descargado: no se ha guardado.",
        );
        return;
      }
      if (controller.signal.aborted) return;
      if (actual !== expected) {
        setError("El fichero descargado no coincide con su SHA-256: no se ha guardado. Vuelve a intentarlo.");
        return;
      }
      saveBlob(file.blob, safeFilename(artifact.filename || file.filename, `sentra-report-${report.id}`));
    } catch (err) {
      // Cancelación (desmontaje o nuevo intento): sin aviso. El resto, con su causa concreta.
      const message = controller.signal.aborted ? undefined : describeDownloadError(err, "el informe");
      if (message) setError(message);
    } finally {
      // Solo la descarga vigente libera el botón: una anterior cancelada no lo toca.
      if (controllerRef.current === controller) {
        controllerRef.current = null;
        setBusy(false);
      }
    }
  };
  return (
    <span className="stack">
      <button
        type="button"
        className={`button${small ? " button--small" : " button--primary"}`}
        disabled={busy}
        aria-busy={busy}
        onClick={() => void download()}
      >
        {busy ? "Descargando…" : "Descargar"}
      </button>
      {error && (
        <span className="text-crit small" role="alert">
          {error}
        </span>
      )}
    </span>
  );
}

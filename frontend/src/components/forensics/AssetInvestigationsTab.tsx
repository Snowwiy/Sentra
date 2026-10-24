import { useCallback, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { forensicsApi } from "../../api/sentra6e";
import { useAuth } from "../../auth/AuthContext";
import { errorMessage } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { ErrorState, LoadingState } from "../StateViews";
import { InvestigationTable } from "./InvestigationTable";

const REFRESH_MS = 60_000;
const TITLE_MIN = 3;
const TITLE_MAX = 200;

/**
 * Pestaña Investigaciones del activo (Fase 6E.6): sus investigaciones y, con forensics:acquire,
 * abrir una nueva. La recogida de evidencias se lanza desde el detalle de la investigación.
 */
export function AssetInvestigationsTab({ assetId, managed }: { assetId: string; managed: boolean }) {
  const auth = useAuth();
  const navigate = useNavigate();
  const fetcher = useCallback((signal: AbortSignal) => forensicsApi.list({ assetId, limit: 100 }, signal), [assetId]);
  const { data, error, loading, refresh } = usePolling(fetcher, REFRESH_MS);
  const [title, setTitle] = useState("");
  const [busy, setBusy] = useState(false);
  const [createError, setCreateError] = useState<string>();
  const trimmed = title.trim();
  const valid = trimmed.length >= TITLE_MIN && trimmed.length <= TITLE_MAX;

  const create = async (event: FormEvent) => {
    event.preventDefault();
    if (!valid) return;
    setBusy(true);
    setCreateError(undefined);
    try {
      const created = await forensicsApi.create({ asset_id: assetId, title: trimmed });
      navigate(`/investigations/${encodeURIComponent(created.id)}`);
    } catch (err) {
      setCreateError(errorMessage(err instanceof Error ? err : new Error(String(err))));
      setBusy(false);
    }
  };

  return (
    <div className="stack">
      {auth.can("forensics:acquire") && (
        <section className="panel panel--padded stack" aria-label="Nueva investigación">
          <h2 className="panel__title">Nueva investigación</h2>
          {!managed && (
            <p className="muted small">
              Este equipo no tiene agente: se puede abrir la investigación, pero no recoger evidencias del equipo.
            </p>
          )}
          <form className="actions" onSubmit={(e) => void create(e)}>
            <input
              className="input"
              value={title}
              maxLength={TITLE_MAX}
              placeholder="Título (p. ej. Conexiones sospechosas a 203.0.113.7)"
              aria-label="Título de la investigación"
              onChange={(e) => setTitle(e.target.value)}
              disabled={busy}
            />
            <button type="submit" className="button button--primary" disabled={busy || !valid}>
              {busy ? "Abriendo…" : "Abrir investigación"}
            </button>
          </form>
          {createError && (
            <div className="banner banner--warn" role="alert">
              {createError}
            </div>
          )}
        </section>
      )}
      <section className="panel" aria-label="Investigaciones del equipo">
        <div className="panel__toolbar">
          <h2>Investigaciones</h2>
        </div>
        {loading ? (
          <LoadingState label="Cargando investigaciones…" />
        ) : !data ? (
          <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />
        ) : data.items.length === 0 ? (
          <p className="muted small panel--padded">Este equipo no tiene investigaciones.</p>
        ) : (
          <InvestigationTable items={data.items} showAsset={false} />
        )}
      </section>
    </div>
  );
}

import { useState } from "react";
import { Link } from "react-router-dom";
import { consoleApi } from "../../api/sentra";
import type { EnrollmentToken } from "../../api/types";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { ConfirmDialog } from "../Modal";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";
import { TokenStateBadge } from "./AgentBadges";

const ORIGIN_LABELS: Record<string, string> = { dashboard: "Dashboard", cli: "CLI", api: "API" };

/** One-time installation tokens: state only, the token value is never listed. */
export function TokensPanel({
  tokens,
  loading,
  error,
  available,
  reason,
  onChanged,
}: {
  tokens: EnrollmentToken[] | undefined;
  loading: boolean;
  error: Error | undefined;
  available: boolean;
  reason: string | undefined;
  onChanged: () => void;
}) {
  const [revoking, setRevoking] = useState<EnrollmentToken>();

  return (
    <section className="panel" aria-label="Tokens de instalación">
      <div className="panel__toolbar">
        <h2>Tokens de instalación</h2>
        <span className="muted small">
          Un token solo se muestra al crearlo; aquí solo aparece su estado.
        </span>
      </div>
      {!available ? (
        <EmptyState title="No disponible">{reason}</EmptyState>
      ) : tokens && tokens.length > 0 ? (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Creado</th>
                <th>Expira</th>
                <th>Plataforma</th>
                <th>Hostname esperado</th>
                <th>Estado</th>
                <th>Origen</th>
                <th>Usado por</th>
                <th aria-label="Acciones" />
              </tr>
            </thead>
            <tbody>
              {tokens.map((token) => (
                <tr key={token.token_id}>
                  <td title={formatDateTime(token.created_at)}>{formatRelative(token.created_at)}</td>
                  <td title={formatDateTime(token.expires_at)}>{formatDateTime(token.expires_at)}</td>
                  <td>{token.expected_platform ?? <span className="muted">cualquiera</span>}</td>
                  <td className="mono small">{token.expected_hostname ?? <span className="muted">—</span>}</td>
                  <td>
                    <TokenStateBadge state={token.state} />
                  </td>
                  <td className="muted">{ORIGIN_LABELS[token.created_via] ?? token.created_via}</td>
                  <td>
                    {token.last_asset_id ? (
                      <Link to={`/assets/${token.last_asset_id}`}>Ver activo</Link>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td>
                    {token.state === "active" && (
                      <button
                        type="button"
                        className="button button--small button--danger"
                        onClick={() => setRevoking(token)}
                      >
                        Revocar
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : loading ? (
        <LoadingState label="Cargando tokens…" />
      ) : error ? (
        <ErrorState message={errorMessage(error)} />
      ) : (
        <EmptyState title="Sin tokens">Pulsa «Añadir agente» para generar uno.</EmptyState>
      )}

      {revoking && (
        <ConfirmDialog
          title="Revocar token de instalación"
          confirmLabel="Revocar token"
          danger
          onClose={() => setRevoking(undefined)}
          onConfirm={async () => {
            await consoleApi.revokeEnrollmentToken(revoking.token_id);
            onChanged();
          }}
        >
          <p>
            El token creado {formatRelative(revoking.created_at)}
            {revoking.expected_hostname && ` para ${revoking.expected_hostname}`} dejará de servir
            inmediatamente. Ningún equipo podrá registrarse con él.
          </p>
        </ConfirmDialog>
      )}
    </section>
  );
}

import { useState } from "react";
import { useAuth } from "../../auth/AuthContext";
import { ActionsCatalog } from "./ActionsCatalog";
import { ExecutionsTable, RunsTable } from "./HistoryTables";
import { RunPlaybookDialog } from "./RunPlaybookDialog";

/**
 * Sección Response del activo (Fase 5D): acciones disponibles con sus bloqueos en este activo,
 * ejecuciones recientes y playbooks. Las acciones sobre incidentes se lanzan desde el incidente.
 */
export function AssetResponseTab({ assetId, assetLabel }: { assetId: string; assetLabel: string }) {
  const auth = useAuth();
  const [runningPlaybook, setRunningPlaybook] = useState(false);
  // Cambiar la clave vuelve a montar el historial tras ejecutar algo, para verlo al momento.
  const [historyKey, setHistoryKey] = useState(0);
  const refreshHistory = () => setHistoryKey((k) => k + 1);
  return (
    <div className="stack">
      {auth.can("response:execute") && (
        <div className="actions">
          <button type="button" className="button button--primary" onClick={() => setRunningPlaybook(true)}>
            Ejecutar playbook
          </button>
        </div>
      )}
      <section className="panel panel--padded">
        <h2 className="panel__title">Acciones disponibles</h2>
        <ActionsCatalog assetId={assetId} hideIncidentActions onExecuted={refreshHistory} />
      </section>
      <section className="panel panel--padded">
        <h2 className="panel__title">Ejecuciones recientes</h2>
        <ExecutionsTable key={`e${historyKey}`} assetId={assetId} compact />
      </section>
      <section className="panel panel--padded">
        <h2 className="panel__title">Playbooks ejecutados</h2>
        <RunsTable key={`r${historyKey}`} assetId={assetId} compact />
      </section>
      {runningPlaybook && (
        <RunPlaybookDialog
          targets={[{ assetId, label: assetLabel }]}
          onClose={() => setRunningPlaybook(false)}
          onDone={refreshHistory}
        />
      )}
    </div>
  );
}

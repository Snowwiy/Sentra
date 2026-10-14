import { lazy, Suspense, useState } from "react";
import { useAuth } from "../../auth/AuthContext";
import type { TargetOption } from "./RunPlaybookDialog";

// El diálogo se carga al pulsar: la página de detección no arrastra todo Response al bundle principal.
const RunPlaybookDialog = lazy(() => import("./RunPlaybookDialog").then((m) => ({ default: m.RunPlaybookDialog })));

// Playbooks integrados de investigación (solo lectura y reevaluaciones, riesgo bajo).
export const INVESTIGATE_PLAYBOOKS = ["investigate_detection", "investigate_endpoint"];

/**
 * "Investigar": lanza un playbook de investigación sobre un activo con el contexto (incidente o
 * detección) que lo origina, para que la ejecución aparezca en el timeline del caso. Solo se
 * muestra con response:execute; el servidor vuelve a comprobarlo.
 */
export function InvestigateButton({
  targets,
  incidentId,
  detectionId,
  playbookKeys = INVESTIGATE_PLAYBOOKS,
}: {
  targets: TargetOption[];
  incidentId?: string;
  detectionId?: string;
  playbookKeys?: string[];
}) {
  const auth = useAuth();
  const [open, setOpen] = useState(false);
  if (!auth.can("response:execute")) return null;
  return (
    <>
      <button
        type="button"
        className="button"
        disabled={targets.length === 0}
        title={targets.length === 0 ? "No hay ningún activo existente que investigar" : undefined}
        onClick={() => setOpen(true)}
      >
        Investigar
      </button>
      {open && (
        <Suspense fallback={null}>
          <RunPlaybookDialog
          title="Investigar"
          targets={targets}
          playbookKeys={playbookKeys}
          incidentId={incidentId}
          detectionId={detectionId}
          onClose={() => setOpen(false)}
          />
        </Suspense>
      )}
    </>
  );
}

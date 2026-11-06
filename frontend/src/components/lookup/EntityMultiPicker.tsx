import { useEffect, useState } from "react";
import { lookupApi } from "../../api/sentra7b";
import type { LookupItem, LookupKind } from "../../api/types";
import { EntityPicker } from "./EntityPicker";

/**
 * Fase 7C.3: varios elementos elegidos por nombre (alcance de un informe, por ejemplo). Los ids
 * ya presentes (un enlace con ?asset=...) se muestran con su nombre; cada chip se quita con
 * su botón y el selector añade uno más.
 */
export function EntityMultiPicker({
  kind,
  label,
  values,
  onChange,
  siteId,
  required,
  max = 50,
}: {
  kind: LookupKind;
  label: string;
  values: string[];
  onChange: (ids: string[]) => void;
  siteId?: string;
  required?: boolean;
  max?: number;
}) {
  const [known, setKnown] = useState<Record<string, LookupItem>>({});
  const missing = values.filter((id) => !(id in known));
  const missingKey = missing.join(",");

  useEffect(() => {
    if (!missingKey) return;
    const controller = new AbortController();
    lookupApi
      .resolve(kind, missingKey.split(","), controller.signal)
      .then((result) =>
        setKnown((current) => ({
          ...current,
          ...Object.fromEntries(result.items.map((i) => [i.id, i])),
        })),
      )
      .catch(() => undefined);
    return () => controller.abort();
  }, [kind, missingKey]);

  return (
    <div className="picker multi-picker">
      {values.length > 0 && (
        <ul className="multi-picker__chips" aria-label={`${label} elegidos`}>
          {values.map((id) => (
            <li key={id} className="chip">
              <span>{known[id]?.label ?? id}</span>
              <button
                type="button"
                className="multi-picker__remove"
                aria-label={`Quitar ${known[id]?.label ?? id}`}
                onClick={() => onChange(values.filter((v) => v !== id))}
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      )}
      {values.length < max && (
        <EntityPicker
          kind={kind}
          label={label}
          value=""
          required={required && values.length === 0}
          siteId={siteId}
          onChange={(id, item) => {
            if (!id || values.includes(id)) return;
            if (item) setKnown((current) => ({ ...current, [id]: item }));
            onChange([...values, id]);
          }}
        />
      )}
    </div>
  );
}

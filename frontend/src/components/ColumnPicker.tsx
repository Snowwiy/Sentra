import { useEffect, useRef } from "react";

export interface ColumnOption {
  id: string;
  label: string;
}

/**
 * Selector de columnas opcionales (Fase 7B.3). Es un <details> nativo: se abre con teclado
 * (Enter/Espacio sobre el resumen) sin JavaScript propio, y Escape lo cierra devolviendo el
 * foco al botón. Las columnas básicas no aparecen aquí: siempre se muestran.
 */
export function ColumnPicker({
  options,
  visible,
  onChange,
  onReset,
}: {
  options: ColumnOption[];
  visible: readonly string[];
  onChange: (next: string[]) => void;
  onReset: () => void;
}) {
  const ref = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    const details = ref.current;
    if (!details) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && details.open) {
        details.open = false;
        details.querySelector("summary")?.focus();
        // Un panel o diálogo abierto detrás no debe cerrarse con la misma tecla.
        event.stopPropagation();
      }
    };
    details.addEventListener("keydown", onKey);
    return () => details.removeEventListener("keydown", onKey);
  }, []);
  const toggle = (id: string, on: boolean) => {
    // Se conserva el orden de la tabla, no el de los clics.
    const next = options.map((o) => o.id).filter((key) => (key === id ? on : visible.includes(key)));
    onChange(next);
  };
  return (
    <details ref={ref} className="column-picker">
      <summary className="button button--small">Columnas</summary>
      <fieldset className="column-picker__menu">
        <legend className="small muted">Columnas opcionales</legend>
        {options.map((option) => (
          <label key={option.id} className="checkbox small">
            <input
              type="checkbox"
              checked={visible.includes(option.id)}
              onChange={(event) => toggle(option.id, event.target.checked)}
            />{" "}
            {option.label}
          </label>
        ))}
        <button type="button" className="button button--small" onClick={onReset}>
          Restablecer
        </button>
      </fieldset>
    </details>
  );
}

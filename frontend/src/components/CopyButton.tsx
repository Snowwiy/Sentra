import { useEffect, useState } from "react";

/** Copies `text` to the clipboard. The text is never logged or stored anywhere else. */
export function CopyButton({
  text,
  label = "Copiar",
  ariaLabel,
}: {
  text: string;
  label?: string;
  /** Nombre accesible cuando el texto visible no basta ("Copiar" junto a cada puerto). */
  ariaLabel?: string;
}) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  useEffect(() => {
    if (state === "idle") return;
    const timer = window.setTimeout(() => setState("idle"), 2500);
    return () => window.clearTimeout(timer);
  }, [state]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      // No clipboard access (plain http on a non-localhost origin, permissions): the text is
      // on screen and can be selected by hand.
      setState("failed");
    }
  };
  return (
    <button
      type="button"
      className="button button--small"
      aria-label={ariaLabel}
      onClick={(event) => {
        // Corrección 6C: dentro de una fila clicable (tabla de activos) copiar no navega.
        event.stopPropagation();
        void copy();
      }}
    >
      {state === "copied" ? "Copiado ✓" : state === "failed" ? "Selecciona y copia a mano" : label}
    </button>
  );
}

import { useEffect, useState } from "react";

/** Copies `text` to the clipboard. The text is never logged or stored anywhere else. */
export function CopyButton({ text, label = "Copiar" }: { text: string; label?: string }) {
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
    <button type="button" className="button button--small" onClick={() => void copy()}>
      {state === "copied" ? "Copiado ✓" : state === "failed" ? "Selecciona y copia a mano" : label}
    </button>
  );
}

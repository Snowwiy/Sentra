import { useEffect, useRef, useState, type ReactNode } from "react";
import { errorMessage } from "../lib/format";

/** Centered dialog over the page. Escape and the close button call `onClose`. */
export function Modal({
  title,
  onClose,
  children,
  wide = false,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    dialogRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="modal-backdrop">
      <div
        ref={dialogRef}
        className={`modal${wide ? " modal--wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
      >
        <div className="modal__header">
          <h2>{title}</h2>
          <button type="button" className="button button--ghost" onClick={onClose} aria-label="Cerrar">
            ✕
          </button>
        </div>
        <div className="modal__body">{children}</div>
      </div>
    </div>
  );
}

/** Asks before an important action; shows progress and the API error, if any. */
export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  danger = false,
  onConfirm,
  onClose,
}: {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  /** Resolves when done (the dialog then closes); a rejection is shown in the dialog. */
  onConfirm: () => Promise<unknown>;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const confirm = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await onConfirm();
      onClose();
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
      setBusy(false);
    }
  };
  return (
    <Modal title={title} onClose={busy ? () => undefined : onClose}>
      <div className="stack">
        <div>{children}</div>
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button
            type="button"
            className={`button ${danger ? "button--danger" : "button--primary"}`}
            onClick={() => void confirm()}
            disabled={busy}
          >
            {busy ? "Procesando…" : confirmLabel}
          </button>
        </div>
      </div>
    </Modal>
  );
}

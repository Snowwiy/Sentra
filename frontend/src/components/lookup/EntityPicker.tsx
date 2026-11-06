import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import { lookupApi } from "../../api/sentra7b";
import type { LookupItem, LookupKind, LookupResult } from "../../api/types";
import { errorMessage } from "../../lib/format";

/**
 * Fase 7C.3: selector contextual. El usuario escribe lo que reconoce (nombre, IP, MAC,
 * etiqueta, regla, INC-n...) y elige de la lista; el id público se resuelve aquí y nunca hay
 * que teclearlo. Varias coincidencias exactas (dos equipos con el mismo nombre) se enseñan
 * como opciones: nada se elige solo si hay ambigüedad.
 *
 * Combobox accesible (patrón WAI-ARIA 1.2): flechas para moverse, Intro para elegir, Escape
 * para cerrar. Un id pegado tal cual también se acepta y se resuelve a su nombre.
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DEBOUNCE_MS = 250;

const PLACEHOLDERS: Record<LookupKind, string> = {
  asset: "Nombre, IP, MAC, etiqueta o descripción",
  detection: "Regla (SCR-001), título o activo",
  incident: "INC-12, número o título",
};

const MATCH_LABELS: Record<string, string> = {
  id: "id",
  label: "etiqueta",
  name: "nombre",
  hostname: "hostname",
  dns: "DNS",
  model: "modelo",
  tag: "etiqueta",
  ip: "IP",
  mac: "MAC",
  rule: "regla",
  title: "título",
  asset: "activo",
  number: "número",
};

export interface EntityPickerProps {
  kind: LookupKind;
  /** Id público elegido ("" = ninguno). */
  value: string;
  onChange: (id: string, item?: LookupItem) => void;
  label: string;
  siteId?: string;
  required?: boolean;
  disabled?: boolean;
  includeArchived?: boolean;
  placeholder?: string;
  /** Texto de ayuda bajo el campo. */
  hint?: string;
  /** Nombre ya conocido del `value` inicial (evita una consulta y sirve sin acceso a lookup). */
  initialLabel?: string;
}

type Search = { query: string; result?: LookupResult; error?: string };

function knownItem(kind: LookupKind, id: string, label: string): LookupItem {
  return {
    kind,
    id,
    label,
    secondary: null,
    match_field: "id",
    exact: true,
    archived: false,
    site_name: null,
    ip: null,
    mac: null,
    device_type: null,
    status: null,
    severity: null,
    asset_id: null,
    asset_label: null,
    last_seen_at: null,
  };
}

export function EntityPicker({
  kind,
  value,
  onChange,
  label,
  siteId,
  required,
  disabled,
  includeArchived,
  placeholder,
  hint,
  initialLabel,
}: EntityPickerProps) {
  const inputId = useId();
  const listId = `${inputId}-list`;
  const [text, setText] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [search, setSearch] = useState<Search>();
  const [selected, setSelected] = useState<LookupItem | undefined>(() =>
    value && initialLabel ? knownItem(kind, value, initialLabel) : undefined,
  );
  const [resolveError, setResolveError] = useState<string>();
  const inputRef = useRef<HTMLInputElement>(null);

  // Un id que llega de fuera (preset del workspace, URL) se enseña con su nombre. Con value
  // vacío no hace falta limpiar `selected`: el chip solo se pinta si coincide con value.
  useEffect(() => {
    if (!value || selected?.id === value) return;
    const controller = new AbortController();
    lookupApi
      .resolve(kind, [value], controller.signal)
      .then((result) => {
        const item = result.items[0];
        setSelected(item);
        setResolveError(item ? undefined : "No se encuentra o no tienes acceso a este elemento.");
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setResolveError(errorMessage(err instanceof Error ? err : new Error(String(err))));
      });
    return () => controller.abort();
  }, [kind, value, selected?.id]);

  const query = text.trim();
  // Una búsqueda anterior no se borra: `current` solo usa la que corresponde al texto actual.
  useEffect(() => {
    if (query.length < 2 && !UUID.test(query)) return;
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      const request = UUID.test(query)
        ? lookupApi.resolve(kind, [query], controller.signal)
        : lookupApi.search(kind, query, { siteId, includeArchived, limit: 10 }, controller.signal);
      request
        .then((result) => {
          setSearch({ query, result });
          setActive(0);
        })
        .catch((err: unknown) => {
          if (!controller.signal.aborted) {
            setSearch({ query, error: errorMessage(err instanceof Error ? err : new Error(String(err))) });
          }
        });
    }, DEBOUNCE_MS);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [kind, query, siteId, includeArchived]);

  const current = search?.query === query ? search : undefined;
  const items = current?.result?.items ?? [];
  const choose = (item: LookupItem) => {
    setSelected(item);
    setResolveError(undefined);
    setText("");
    setOpen(false);
    onChange(item.id, item);
  };
  const clear = () => {
    setSelected(undefined);
    onChange("");
    window.setTimeout(() => inputRef.current?.focus(), 0);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setOpen(true);
      setActive((n) => Math.min(n + 1, Math.max(items.length - 1, 0)));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((n) => Math.max(n - 1, 0));
    } else if (event.key === "Enter") {
      if (open && items[active]) {
        event.preventDefault();
        choose(items[active]!);
      }
    } else if (event.key === "Escape") {
      setOpen(false);
    }
  };

  if (selected && value === selected.id) {
    return (
      <div className="picker">
        <span className="picker__label" id={`${inputId}-label`}>
          {label}
          {required && " *"}
        </span>
        <div className="picker__chosen" role="group" aria-labelledby={`${inputId}-label`}>
          <div className="picker__chosen-text">
            <strong>{selected.label}</strong>
            {selected.secondary && <span className="small muted">{selected.secondary}</span>}
          </div>
          {selected.archived && <span className="badge badge--muted">Archivado</span>}
          {!disabled && (
            <button type="button" className="button button--small" onClick={clear}>
              Cambiar
            </button>
          )}
        </div>
      </div>
    );
  }

  const resolution = current?.result?.resolution;
  const expanded = open && query.length > 0 && current !== undefined;
  return (
    <div className="picker">
      <label className="picker__label" htmlFor={inputId}>
        {label}
        {required && " *"}
      </label>
      <div className="picker__box">
        <input
          ref={inputRef}
          id={inputId}
          className="input"
          role="combobox"
          aria-autocomplete="list"
          aria-expanded={expanded}
          aria-controls={listId}
          aria-activedescendant={expanded && items[active] ? `${listId}-${active}` : undefined}
          aria-required={required}
          aria-invalid={Boolean(resolveError) || undefined}
          autoComplete="off"
          disabled={disabled}
          value={text}
          maxLength={128}
          placeholder={placeholder ?? PLACEHOLDERS[kind]}
          onChange={(event) => {
            setText(event.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          onBlur={() => window.setTimeout(() => setOpen(false), 150)}
          onKeyDown={onKeyDown}
        />
        {expanded && (
          <div className="picker__popup">
            {current?.error ? (
              <p className="picker__note" role="alert">
                {current.error}
              </p>
            ) : items.length === 0 ? (
              <p className="picker__note">Sin coincidencias para «{query}».</p>
            ) : (
              <>
                {resolution === "ambiguous" && (
                  <p className="picker__note picker__note--warn" role="status">
                    Varias coincidencias exactas: elige la correcta.
                  </p>
                )}
                <ul id={listId} role="listbox" className="picker__list" aria-label={`Opciones de ${label}`}>
                  {items.map((item, index) => (
                    <li
                      key={item.id}
                      id={`${listId}-${index}`}
                      role="option"
                      aria-selected={index === active}
                      className={`picker__option${index === active ? " picker__option--active" : ""}`}
                      onMouseDown={(event) => event.preventDefault()}
                      onClick={() => choose(item)}
                      onMouseEnter={() => setActive(index)}
                    >
                      <span className="picker__option-main">
                        <strong>{item.label}</strong>
                        {item.archived && <span className="badge badge--muted">Archivado</span>}
                      </span>
                      <span className="picker__option-meta small muted">
                        {item.secondary}
                        <span className={`picker__match${item.exact ? " picker__match--exact" : ""}`}>
                          {item.exact ? "exacta" : "parcial"} · {MATCH_LABELS[item.match_field] ?? item.match_field}
                        </span>
                      </span>
                    </li>
                  ))}
                </ul>
                {current?.result?.truncated && (
                  <p className="picker__note">Hay más resultados: escribe algo más concreto.</p>
                )}
              </>
            )}
          </div>
        )}
      </div>
      {resolveError ? (
        <span className="small picker__error" role="alert">
          {resolveError}
        </span>
      ) : (
        hint && <span className="small muted">{hint}</span>
      )}
    </div>
  );
}

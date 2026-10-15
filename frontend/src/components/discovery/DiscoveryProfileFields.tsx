import type { DiscoveryLimits, DiscoveryProfile, DiscoveryProfileCatalog } from "../../api/types";
import { BASIC_PROFILE_LABEL, TUNABLE_LIMITS, type LimitCheck, type LimitDraft } from "../../lib/discovery";

/** "basic" = descubrimiento de siempre (sin `profile` en la petición). */
export type ProfileChoice = "basic" | DiscoveryProfile["name"];

export interface ProfileFieldsProps {
  catalog: DiscoveryProfileCatalog | undefined;
  catalogError: Error | undefined;
  value: ProfileChoice;
  onChange: (value: ProfileChoice) => void;
  /** Motivo por el que los perfiles avanzados no se pueden elegir (sensor sin capacidad). */
  advancedBlocked: string | undefined;
  /** Puertos elegidos del perfil (subconjunto de profile.ports). */
  selectedPorts: number[];
  onTogglePort: (port: number) => void;
  extraPorts: string;
  onExtraPorts: (value: string) => void;
  portsError: string | undefined;
  limits: LimitDraft | undefined;
  onLimit: (key: keyof LimitDraft, value: string) => void;
  limitCheck: LimitCheck | undefined;
  disabled: boolean;
}

const METHOD_FLAGS: { key: "icmp" | "tcp" | "arp" | "reverse_dns" | "forward_dns"; label: string }[] = [
  { key: "icmp", label: "ICMP" },
  { key: "tcp", label: "TCP connect" },
  { key: "arp", label: "ARP" },
  { key: "reverse_dns", label: "DNS inverso" },
  { key: "forward_dns", label: "DNS directo" },
];

function methodsText(profile: DiscoveryProfile): string {
  return METHOD_FLAGS.filter((m) => profile[m.key]).map((m) => m.label).join(" · ") || "—";
}

/**
 * Perfil del descubrimiento, puertos y límites (Fase 6A).
 *
 * Los límites solo se ven editables con discovery:tune (`catalog.can_tune`); el resto los ve
 * en solo lectura. Toda la validación de aquí es una ayuda: el servidor manda.
 */
export function DiscoveryProfileFields(props: ProfileFieldsProps) {
  const { catalog, value, advancedBlocked, disabled } = props;
  const profile = catalog?.profiles.find((p) => p.name === value);
  const canTune = Boolean(catalog?.can_tune);

  return (
    <>
      <fieldset className="form-field">
        <legend>Perfil</legend>
        <div className="stack">
          <label className="checkbox">
            <input
              type="radio"
              name="discovery-profile"
              value="basic"
              checked={value === "basic"}
              onChange={() => props.onChange("basic")}
              disabled={disabled}
            />{" "}
            {BASIC_PROFILE_LABEL}{" "}
            <span className="muted small">— el descubrimiento de siempre, con la configuración del servidor.</span>
          </label>
          {(catalog?.profiles ?? []).map((p) => (
            <label key={p.name} className="checkbox">
              <input
                type="radio"
                name="discovery-profile"
                value={p.name}
                checked={value === p.name}
                onChange={() => props.onChange(p.name)}
                disabled={disabled || Boolean(advancedBlocked)}
                aria-describedby={`profile-${p.name}-desc`}
              />{" "}
              {p.label}{" "}
              <span className="muted small" id={`profile-${p.name}-desc`}>
                — {p.description}
              </span>
            </label>
          ))}
        </div>
        {!catalog && props.catalogError && (
          <span className="muted small">
            El servidor no ofrece perfiles avanzados ({props.catalogError.message}): solo el descubrimiento básico.
          </span>
        )}
      </fieldset>

      {advancedBlocked && catalog && (
        <div className="banner banner--warn" role="note">
          {advancedBlocked}
        </div>
      )}

      {profile && catalog && (
        <div className="stack" aria-label={`Parámetros del perfil ${profile.label}`} role="group">
          <dl className="fields fields--inline">
            <div className="field">
              <dt>Métodos</dt>
              <dd className="small">{methodsText(profile)}</dd>
            </div>
            {!canTune && <ReadOnlyLimits limits={profile.limits} />}
          </dl>

          <fieldset className="form-field">
            <legend>Puertos TCP del perfil</legend>
            <div className="port-choices">
              {profile.ports.map((port) => (
                <label key={port} className="checkbox mono">
                  <input
                    type="checkbox"
                    checked={props.selectedPorts.includes(port)}
                    onChange={() => props.onTogglePort(port)}
                    disabled={disabled}
                  />{" "}
                  {port}
                </label>
              ))}
            </div>
            {canTune && (
              <label className="form-field">
                <span className="small">Puertos adicionales (separados por comas)</span>
                <input
                  type="text"
                  className="input"
                  inputMode="numeric"
                  value={props.extraPorts}
                  onChange={(event) => props.onExtraPorts(event.target.value)}
                  disabled={disabled}
                  aria-invalid={Boolean(props.portsError)}
                  placeholder="p. ej. 8080, 8443"
                />
              </label>
            )}
            <span className="muted small">
              {canTune
                ? `Máximo ${catalog.caps.max_ports} puertos.`
                : "Solo puedes elegir un subconjunto de los puertos del perfil."}
            </span>
            {props.portsError && (
              <span className="form-error small" role="alert">
                {props.portsError}
              </span>
            )}
          </fieldset>

          {canTune && props.limits && (
            <fieldset className="form-field">
              <legend>Límites</legend>
              <div className="limits-grid">
                {TUNABLE_LIMITS.map(({ key, label, unit, min }) => {
                  const error = props.limitCheck?.errors[key];
                  const errorId = `limit-${key}-error`;
                  return (
                    <label key={key} className="form-field">
                      <span className="small">
                        {label}
                        {unit ? ` (${unit})` : ""}
                      </span>
                      <input
                        type="number"
                        className="input"
                        min={min}
                        max={catalog.caps[key]}
                        step={1}
                        value={props.limits?.[key] ?? ""}
                        onChange={(event) => props.onLimit(key, event.target.value)}
                        disabled={disabled}
                        aria-invalid={Boolean(error)}
                        aria-describedby={error ? errorId : undefined}
                      />
                      <span className="muted small">Tope del servidor: {catalog.caps[key]}</span>
                      {error && (
                        <span className="form-error small" id={errorId}>
                          {error}
                        </span>
                      )}
                    </label>
                  );
                })}
              </div>
            </fieldset>
          )}
        </div>
      )}
    </>
  );
}

function ReadOnlyLimits({ limits }: { limits: DiscoveryLimits }) {
  return (
    <>
      {TUNABLE_LIMITS.map(({ key, label, unit }) => (
        <div className="field" key={key}>
          <dt>{label}</dt>
          <dd className="small">
            {limits[key]}
            {unit ? ` ${unit}` : ""}
          </dd>
        </div>
      ))}
    </>
  );
}

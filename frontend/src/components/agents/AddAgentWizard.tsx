import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { consoleApi } from "../../api/sentra";
import type { ConsoleInfo, EnrollmentTokenCreated } from "../../api/types";
import { errorMessage } from "../../lib/format";
import {
  checkServerUrl,
  installSteps,
  lifetimeMinutes,
  timeLeft,
  windowsInstallSteps,
  WINDOWS_PACKAGE,
  type InstallMethod,
  type InstallPackage,
  type InstallStep,
  type WindowsInstallMethod,
} from "../../lib/install";
import { usePolling } from "../../lib/usePolling";
import { CopyButton } from "../CopyButton";
import { Modal } from "../Modal";

// While a token waits for its host, check often so the new agent shows up within seconds.
const WAIT_POLL_MS = 5_000;

export type Platform = "linux" | "windows";
type Step = "platform" | "configure" | "install";

const PLATFORM_NAMES: Record<Platform, string> = { linux: "Linux", windows: "Windows" };

export interface WizardPreset {
  /** Expected hostname (re-enrollment of a known host). */
  hostname?: string;
  /** Plataforma del agente que se vuelve a registrar (el token queda limitado a ella). */
  platform?: Platform;
  /** Shown above the form, e.g. why a new token is needed. */
  note?: string;
}

/**
 * Agentes → Añadir agente → Linux o Windows → Generar token → copiar instalación → registrado.
 *
 * The one-time token lives only in this component's state: it is shown once, never stored
 * (no browser storage, no URL) and never logged, and it is gone when the dialog
 * closes. The server cannot show it again.
 */
export function AddAgentWizard({
  info,
  preset,
  onClose,
  onRegistered,
}: {
  info: ConsoleInfo;
  preset?: WizardPreset;
  onClose: () => void;
  /** Called once when the token is used by a host (the agent list can refresh). */
  onRegistered?: (assetId: string) => void;
}) {
  const [step, setStep] = useState<Step>(preset ? "configure" : "platform");
  const [platform, setPlatform] = useState<Platform>(preset?.platform ?? "linux");
  const [serverUrl, setServerUrl] = useState(info.suggested_server_urls[0] ?? "");
  const [hostname, setHostname] = useState(preset?.hostname ?? "");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string>();
  const [created, setCreated] = useState<EnrollmentTokenCreated>();

  const server = checkServerUrl(serverUrl);

  const generate = async () => {
    setCreating(true);
    setCreateError(undefined);
    try {
      const token = await consoleApi.createEnrollmentToken({
        expected_platform: platform,
        max_uses: 1,
        ...(hostname.trim() ? { expected_hostname: hostname.trim() } : {}),
      });
      setCreated(token);
      setStep("install");
    } catch (err) {
      setCreateError(errorMessage(err instanceof Error ? err : new Error(String(err))));
    } finally {
      setCreating(false);
    }
  };

  return (
    <Modal title="Añadir agente" onClose={onClose} wide>
      <ol className="wizard__steps" aria-label="Pasos">
        <li className={step === "platform" ? "is-current" : "is-done"}>Plataforma</li>
        <li className={step === "configure" ? "is-current" : step === "install" ? "is-done" : ""}>
          Token de instalación
        </li>
        <li className={step === "install" ? "is-current" : ""}>Instalación</li>
      </ol>

      {step === "platform" && (
        <div className="stack">
          <p className="muted">¿En qué sistema vas a instalar el agente?</p>
          <div className="choice-grid" role="radiogroup" aria-label="Plataforma">
            <button
              type="button"
              role="radio"
              aria-checked={platform === "linux"}
              className={`choice${platform === "linux" ? " choice--active" : ""}`}
              onClick={() => setPlatform("linux")}
            >
              <strong>Linux</strong>
              <span className="muted small">Ubuntu 24.04, Linux Mint 22, Debian (amd64) · systemd</span>
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={platform === "windows"}
              className={`choice${platform === "windows" ? " choice--active" : ""}`}
              onClick={() => setPlatform("windows")}
            >
              <strong>Windows</strong>
              <span className="muted small">Windows 10/11, Server 2019+ (x64) · servicio Windows</span>
            </button>
          </div>
          <div className="modal__actions">
            <button type="button" className="button" onClick={onClose}>
              Cancelar
            </button>
            <button type="button" className="button button--primary" onClick={() => setStep("configure")}>
              Continuar
            </button>
          </div>
        </div>
      )}

      {step === "configure" && (
        <div className="stack">
          {preset?.note && (
            <div className="banner" role="status">
              {preset.note}
            </div>
          )}
          <label className="form-field">
            <span>URL del servidor Sentra (la que usará el equipo para conectarse)</span>
            <input
              className="input"
              list="sentra-server-urls"
              value={serverUrl}
              onChange={(event) => setServerUrl(event.target.value)}
              placeholder="http://192.168.1.10:8000"
              spellCheck={false}
              autoComplete="off"
            />
            <datalist id="sentra-server-urls">
              {info.suggested_server_urls.map((url) => (
                <option key={url} value={url} />
              ))}
            </datalist>
            <span className="muted small">
              {info.server_url_configured
                ? "Configurada en el servidor (AGENT_SERVER_URL)."
                : "Sugerida a partir de las direcciones de este servidor; edítala si hace falta. La API debe escuchar en la red (p. ej. start_backend.ps1 -BindHost 0.0.0.0) y el firewall permitir el puerto."}
            </span>
          </label>
          {serverUrl.trim() && !server.valid && (
            <div className="banner banner--warn" role="alert">
              URL no válida: usa http(s)://dirección[:puerto], por ejemplo http://192.168.1.10:8000.
            </div>
          )}
          {server.loopback && (
            <div className="banner banner--warn" role="alert">
              localhost/127.0.0.1 es el propio equipo {PLATFORM_NAMES[platform]}, no este servidor: usa la
              dirección IP o el nombre del servidor en la red.
            </div>
          )}
          {server.insecure && (
            <div className="banner banner--warn" role="note">
              HTTP no cifra las credenciales durante el transporte. Use HTTPS en producción.
            </div>
          )}
          <label className="form-field">
            <span>Hostname esperado (opcional)</span>
            <input
              className="input"
              value={hostname}
              onChange={(event) => setHostname(event.target.value)}
              placeholder="p. ej. pc-ana"
              spellCheck={false}
              autoComplete="off"
              maxLength={255}
            />
            <span className="muted small">
              Si lo indicas, el token solo servirá para un equipo con ese nombre (comando <code>hostname</code>
              {platform === "windows" ? " en PowerShell" : ""}).
            </span>
          </label>
          <p className="muted small">
            Plataforma {PLATFORM_NAMES[platform]} · un solo uso · caduca en {info.enrollment_token_ttl_minutes}{" "}
            minutos.
          </p>
          {createError && (
            <div className="banner banner--warn" role="alert">
              No se pudo generar el token: {createError}
            </div>
          )}
          <div className="modal__actions">
            {!preset && (
              <button type="button" className="button" onClick={() => setStep("platform")} disabled={creating}>
                Atrás
              </button>
            )}
            <button
              type="button"
              className="button button--primary"
              onClick={() => void generate()}
              disabled={creating || !server.valid}
            >
              {creating ? "Generando…" : "Generar token de instalación"}
            </button>
          </div>
        </div>
      )}

      {step === "install" && created && (
        <InstallInstructions
          token={created}
          serverUrl={server.url}
          platform={platform}
          reenroll={Boolean(preset)}
          onClose={onClose}
          onRegistered={onRegistered}
        />
      )}
    </Modal>
  );
}

function InstallInstructions({
  token,
  serverUrl,
  platform,
  reenroll,
  onClose,
  onRegistered,
}: {
  token: EnrollmentTokenCreated;
  serverUrl: string;
  platform: Platform;
  /** Re-registro de un agente existente (Windows necesita -Reenroll). */
  reenroll: boolean;
  onClose: () => void;
  onRegistered?: (assetId: string) => void;
}) {
  const [method, setMethod] = useState<InstallMethod>("file");
  const [windowsMethod, setWindowsMethod] = useState<WindowsInstallMethod>("prompt");
  const [pkg, setPkg] = useState<InstallPackage>("tarball");
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  // Watch this token (the listing never returns the token value) while the dialog is open.
  const fetchTokens = useCallback((signal: AbortSignal) => consoleApi.listEnrollmentTokens(signal), []);
  const watch = usePolling(fetchTokens, WAIT_POLL_MS);
  const current = watch.data?.items.find((item) => item.token_id === token.token_id);
  const state = current?.state ?? "active";
  const assetId = current?.last_asset_id ?? null;
  const notified = useRef(false);
  useEffect(() => {
    if (state !== "consumed" || !assetId || notified.current) return;
    notified.current = true;
    onRegistered?.(assetId);
  }, [state, assetId, onRegistered]);

  const minutes = lifetimeMinutes(token.created_at, token.expires_at);
  const left = timeLeft(token.expires_at, now);
  const steps: InstallStep[] =
    platform === "windows"
      ? windowsInstallSteps({ serverUrl, method: windowsMethod, reenroll })
      : installSteps({ serverUrl, token: token.token, method, pkg });

  return (
    <div className="stack">
      {state === "consumed" ? (
        <div className="banner banner--ok" role="status">
          <strong>Equipo registrado.</strong> El token se ha consumido y ya no sirve.{" "}
          {assetId && <Link to={`/assets/${assetId}`}>Ver el activo</Link>}
        </div>
      ) : state !== "active" || !left ? (
        <div className="banner banner--warn" role="alert">
          {state === "revoked" ? "Este token ha sido revocado." : "Este token ha caducado."} Cierra y genera
          uno nuevo.
        </div>
      ) : (
        <div className="banner banner--warn" role="alert">
          <strong>
            Este token solo puede utilizarse una vez y expira en {minutes} minutos.
          </strong>{" "}
          Se muestra ahora y no se podrá volver a ver. Tiempo restante: <span className="mono">{left}</span>
        </div>
      )}

      {state === "active" && left && (
        <>
          <div className="token-box">
            <code className="token-box__value" aria-label="Token de instalación">
              {token.token}
            </code>
            <CopyButton text={token.token} label="Copiar token" />
          </div>

          {platform === "windows" ? (
            <WindowsMethodChooser method={windowsMethod} onChange={setWindowsMethod} />
          ) : (
            <>
              <div className="segmented" role="tablist" aria-label="Método de instalación">
                <button
                  type="button"
                  role="tab"
                  aria-selected={method === "file"}
                  className={`segmented__item${method === "file" ? " segmented__item--active" : ""}`}
                  onClick={() => setMethod("file")}
                >
                  Método recomendado (archivo)
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={method === "inline"}
                  className={`segmented__item${method === "inline" ? " segmented__item--active" : ""}`}
                  onClick={() => setMethod("inline")}
                >
                  Método rápido (--token)
                </button>
              </div>
              <label className="form-field form-field--inline">
                <span>Paquete</span>
                <select className="input input--select" value={pkg} onChange={(e) => setPkg(e.target.value as InstallPackage)}>
                  <option value="tarball">Tarball (.tar.gz)</option>
                  <option value="deb">Paquete Debian (.deb)</option>
                </select>
              </label>
              {method === "file" ? (
                <p className="muted small">
                  El token se pega en un aviso que no lo muestra y se guarda en un archivo solo legible por ti;
                  no queda en el historial de la shell ni en la lista de procesos. El instalador borra el
                  archivo al registrarse.
                </p>
              ) : (
                <div className="banner banner--warn" role="note">
                  Con --token el token queda en el historial de la shell (~/.bash_history). Úsalo solo si
                  no puedes usar el archivo; en Ubuntu, empezar el comando con un espacio evita que se guarde.
                </div>
              )}
              <p className="muted small">
                En el equipo Linux, con el paquete copiado en la carpeta actual:
              </p>
            </>
          )}
          <ol className="command-list">
            {steps.map((item) => (
              <li key={item.command}>
                <span className="small">{item.title}</span>
                <div className="command">
                  <pre className="mono">{item.command}</pre>
                  <CopyButton text={item.command} />
                </div>
              </li>
            ))}
          </ol>
          <p className="muted small" role="status">
            <span className="spinner spinner--inline" aria-hidden="true" /> Esperando a que el equipo se
            registre… (esta ventana se actualiza sola)
          </p>
        </>
      )}

      <div className="modal__actions">
        <button type="button" className="button button--primary" onClick={onClose}>
          {state === "consumed" ? "Listo" : "Cerrar"}
        </button>
      </div>
    </div>
  );
}

function WindowsMethodChooser({
  method,
  onChange,
}: {
  method: WindowsInstallMethod;
  onChange: (method: WindowsInstallMethod) => void;
}) {
  return (
    <>
      <div className="segmented" role="tablist" aria-label="Método de instalación">
        <button
          type="button"
          role="tab"
          aria-selected={method === "prompt"}
          className={`segmented__item${method === "prompt" ? " segmented__item--active" : ""}`}
          onClick={() => onChange("prompt")}
        >
          Método recomendado (aviso oculto)
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={method === "file"}
          className={`segmented__item${method === "file" ? " segmented__item--active" : ""}`}
          onClick={() => onChange("file")}
        >
          Archivo (-TokenFile)
        </button>
      </div>
      <p className="muted small">
        {method === "prompt"
          ? "El instalador pide el token en un aviso que no lo muestra: no queda en el historial de PowerShell ni en la línea de comandos de ningún proceso."
          : "El token se guarda en enrollment.token en la carpeta del paquete; el instalador lo borra al registrarse. Útil para despliegues automatizados."}
      </p>
      <p className="muted small">
        Copia {WINDOWS_PACKAGE} al equipo Windows y abre PowerShell <strong>como administrador</strong> en esa
        carpeta. No hace falta Git, Python ni dejar PowerShell abierto: el agente queda como servicio
        «Sentra Agent». -ExecutionPolicy Bypass solo afecta a ese proceso.
      </p>
    </>
  );
}

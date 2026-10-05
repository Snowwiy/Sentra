// Install instructions for the Linux agent (agent/packaging/linux, docs/agent-linux-installation.md)
// y para Windows (agent/packaging/windows, docs/agent-windows-installation.md).
// Pure functions: the one-time token only passes through here to build the text the operator
// copies; nothing is stored or logged.

export type InstallMethod = "file" | "inline";
/** Windows: "prompt" (aviso oculto del instalador, recomendado) o "file" (-TokenFile). */
export type WindowsInstallMethod = "prompt" | "file";
export type InstallPackage = "tarball" | "deb";

export interface InstallStep {
  title: string;
  command: string;
  /** The command contains the one-time token itself. */
  secret?: boolean;
}

export interface ServerUrlCheck {
  /** Normalized URL (trimmed, no trailing slash). */
  url: string;
  valid: boolean;
  /** http://: credentials travel unencrypted. */
  insecure: boolean;
  /** localhost/127.x/::1: another machine cannot reach it. */
  loopback: boolean;
}

// Same rule as the installer's --server check (install-sentra-agent.sh).
const SERVER_URL = /^https?:\/\/[A-Za-z0-9.:_[\]-]+(\/[A-Za-z0-9._~/-]*)?$/;
// What the server generates: prefix + URL-safe base64. Anything else is never put into a
// shell command.
const TOKEN = /^sentra_et_[A-Za-z0-9_-]{20,200}$/;

export function checkServerUrl(raw: string): ServerUrlCheck {
  const url = raw.trim().replace(/\/+$/, "");
  const valid = SERVER_URL.test(url);
  let loopback = false;
  if (valid) {
    try {
      const host = new URL(url).hostname.replace(/^\[|\]$/g, "").toLowerCase();
      loopback = host === "localhost" || host === "::1" || /^127\./.test(host);
    } catch {
      return { url, valid: false, insecure: false, loopback: false };
    }
  }
  return { url, valid, insecure: valid && url.startsWith("http://"), loopback };
}

export function isEnrollmentToken(value: string): boolean {
  return TOKEN.test(value);
}

/** POSIX single-quote quoting. */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export const TOKEN_FILE = "enrollment.token";

/**
 * Commands to run on the Linux host, in order.
 * - "file" (recommended): the token is typed at a silent prompt into a 0600 file, so it never
 *   appears in a command line, the shell history or `ps`; the installer deletes the file.
 * - "inline": `--token`; quicker, but the token stays in the shell history.
 */
export function installSteps(options: {
  serverUrl: string;
  token: string;
  method: InstallMethod;
  pkg: InstallPackage;
}): InstallStep[] {
  const { serverUrl, token, method, pkg } = options;
  const server = checkServerUrl(serverUrl);
  if (!server.valid) throw new Error("URL del servidor no válida");
  if (!isEnrollmentToken(token)) throw new Error("Token de instalación no válido");

  const steps: InstallStep[] =
    pkg === "tarball"
      ? [
          {
            title: "Extrae el paquete (sentra-agent-<versión>-linux-x86_64.tar.gz) y entra en la carpeta",
            command:
              "tar xzf sentra-agent-*-linux-x86_64.tar.gz && cd sentra-agent-*-linux-x86_64",
          },
        ]
      : [
          {
            title: "Instala el paquete .deb",
            command: "sudo apt install ./sentra-agent_*_amd64.deb",
          },
        ];
  const installer = pkg === "tarball" ? "sudo ./install-sentra-agent.sh" : "sudo sentra-agent-setup";
  const serverArg = `--server ${shellQuote(server.url)}`;

  if (method === "file") {
    steps.push(
      {
        title: "Guarda el token en un archivo privado: pega el token cuando lo pida (no se muestra ni queda en el historial)",
        command: `(umask 077; read -rsp 'Token de instalación: ' t && printf '%s\\n' "$t" > ${TOKEN_FILE}); echo`,
      },
      {
        title: "Instala, registra y arranca el agente (el archivo del token se borra al terminar)",
        command: `${installer} ${serverArg} --token-file ./${TOKEN_FILE}`,
      },
    );
  } else {
    steps.push({
      title: "Instala, registra y arranca el agente",
      command: `${installer} ${serverArg} --token ${shellQuote(token)}`,
      secret: true,
    });
  }
  steps.push({ title: "Comprueba el servicio", command: "systemctl status sentra-agent" });
  return steps;
}

/** Comillas simples de PowerShell: dentro solo hay que duplicar la comilla simple. */
export function psQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

export const WINDOWS_PACKAGE = "sentra-agent-<versión>-windows-x86_64.zip";

/**
 * Comandos para el equipo Windows, en orden, en PowerShell abierto como administrador.
 * El token nunca va en un comando: el instalador lo pide en un aviso sin eco (no queda en el
 * historial de PSReadLine ni en la línea de comandos de ningún proceso), o se guarda antes en
 * un archivo con -TokenFile, que el instalador borra al registrarse.
 * `reenroll` añade -Reenroll: un agente revocado y reactivado conserva su identidad, y sin esa
 * opción el instalador la reutilizaría sin pedir token.
 */
export function windowsInstallSteps(options: {
  serverUrl: string;
  method: WindowsInstallMethod;
  reenroll?: boolean;
}): InstallStep[] {
  const { serverUrl, method, reenroll = false } = options;
  const server = checkServerUrl(serverUrl);
  if (!server.valid) throw new Error("URL del servidor no válida");

  const installer =
    "powershell -NoProfile -ExecutionPolicy Bypass -File .\\install-sentra-agent.ps1" +
    ` -Server ${psQuote(server.url)}${reenroll ? " -Reenroll" : ""}`;
  const steps: InstallStep[] = [
    {
      title: `Descomprime el paquete (${WINDOWS_PACKAGE}) y entra en la carpeta`,
      command:
        "Expand-Archive -Path .\\sentra-agent-*-windows-x86_64.zip -DestinationPath . -Force; " +
        "Set-Location .\\sentra-agent-*-windows-x86_64",
    },
  ];
  if (method === "prompt") {
    steps.push({
      title:
        "Instala, registra y arranca el servicio: pega el token cuando lo pida (no se muestra ni queda en el historial)",
      command: installer,
    });
  } else {
    steps.push(
      {
        title: "Guarda el token en un archivo: pégalo cuando lo pida (no se muestra)",
        command:
          "$t = Read-Host 'Token de instalación' -AsSecureString; " +
          `[IO.File]::WriteAllText("$PWD\\${TOKEN_FILE}", [Net.NetworkCredential]::new('', $t).Password)`,
      },
      {
        title: "Instala, registra y arranca el servicio (el archivo del token se borra al terminar)",
        command: `${installer} -TokenFile .\\${TOKEN_FILE}`,
      },
    );
  }
  steps.push({ title: "Comprueba el servicio", command: "Get-Service SentraAgent" });
  return steps;
}

/** Whole minutes between two ISO timestamps (the token lifetime shown to the operator). */
export function lifetimeMinutes(createdAt: string, expiresAt: string): number {
  return Math.round((new Date(expiresAt).getTime() - new Date(createdAt).getTime()) / 60_000);
}

/** "mm:ss" left until `expiresAt`, or null when already expired. */
export function timeLeft(expiresAt: string, now = Date.now()): string | null {
  const seconds = Math.floor((new Date(expiresAt).getTime() - now) / 1000);
  if (seconds <= 0) return null;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}

"""Helper de aislamiento de Sentra (Fase 6E.7): `python -m sentra_agent.isolation_helper`.

Servicio OPCIONAL y separado del agente, el único componente de Sentra que toca el firewall
(servicio Windows "SentraIsolation" como LocalSystem / unidad systemd `sentra-isolation` como
root). No habla con la red: solo con el agente, por ficheros en el directorio de intercambio.

Garantías que no dependen del servidor ni del agente:
- política local propia (isolation.toml), desactivada por defecto;
- las direcciones permitidas las calcula el helper (servidor Sentra a partir de la api_url
  del agent.toml local, loopback, DHCP, DNS si allow_dns, extra_allow); la petición no puede
  traer direcciones;
- duración máxima local y expiración aplicada por el propio helper (y en Windows además por
  una tarea programada de respaldo como SYSTEM);
- al arrancar revierte un estado caducado, a medio aplicar o con la política desactivada;
- el estado del que depende la reversión vive en un directorio privado del helper.

Todo lo que toca el sistema (firewall, resolución DNS, reloj) es inyectable: los tests usan
dobles y nunca ejecutan nft, netsh ni PowerShell reales.
"""

import argparse
import ipaddress
import logging
import os
import socket
import sys
import threading
import time
import tomllib
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse
from uuid import UUID

from sentra_agent.identity import write_atomic
from sentra_agent.isolation import (
    HELPER_DISABLED,
    HELPER_ERROR,
    HELPER_READY,
    STATE_APPLYING,
    STATE_FAILED,
    STATE_ISOLATED,
    STATE_NONE,
    STATE_REVERTING,
    IsolationError,
)
from sentra_agent.isolation.addresses import Network, allowed_networks
from sentra_agent.isolation.exchange import (
    STATE_FILE,
    STATUS_FILE,
    ExchangeDir,
    Request,
    parse_iso,
    parse_request,
    read_json,
)
from sentra_agent.isolation.policy import HelperPolicy, PolicyError, load_policy

logger = logging.getLogger("sentra_agent.isolation")

SERVICE_NAME = "SentraIsolation"
DISPLAY_NAME = "Sentra Isolation Helper"
PRIVATE_STATE = "isolation_state.json"
STEP_SECONDS = 2.0
STATUS_REFRESH_SECONDS = 30.0
PRESENCE_CHECK_SECONDS = 60.0


class FirewallBackend(Protocol):
    method: str

    def precheck(self) -> None: ...

    def apply(
        self, allowed: list[Network], session_id: UUID, expires_at: datetime
    ) -> list[dict[str, Any]]: ...

    def verify(self, allowed: list[Network]) -> bool: ...

    def present(self) -> bool: ...

    def revert(self) -> None: ...


@dataclass
class HelperState:
    state: str = STATE_NONE
    session_id: str | None = None
    applied_at: str | None = None
    expires_at: str | None = None
    method: str | None = None
    allowed: list[str] = field(default_factory=list)
    rules: list[dict[str, Any]] = field(default_factory=list)
    verified: bool = False
    error_code: str | None = None
    last_action: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "HelperState":
        if not data:
            return cls()
        known = {f for f in cls.__dataclass_fields__}
        try:
            return cls(**{k: v for k, v in data.items() if k in known})
        except TypeError:
            return cls()


def default_paths(platform: str | None = None) -> dict[str, Path]:
    platform = platform or sys.platform
    if platform == "win32":
        base = Path(os.environ.get("PROGRAMDATA") or r"C:\ProgramData") / "Sentra"
        return {
            "policy": base / "Isolation" / "isolation.toml",
            "state_dir": base / "Isolation" / "state",
            "log_dir": base / "Isolation" / "logs",
            "exchange_dir": base / "Agent" / "isolation",
        }
    return {
        "policy": Path("/etc/sentra-agent/isolation.toml"),
        "state_dir": Path("/var/lib/sentra-isolation"),
        "log_dir": Path("/var/log/sentra-isolation"),
        "exchange_dir": Path("/var/lib/sentra-agent/isolation"),
    }


def resolve_host(host: str, port: int) -> list[str]:
    """IPs del servidor Sentra (literal o resuelto ahora, antes de aislar)."""
    try:
        return [str(ipaddress.ip_address(host.strip("[]")))]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    return sorted({str(info[4][0]).split("%", 1)[0] for info in infos})


def default_dns_servers(platform: str | None = None) -> list[str]:
    platform = platform or sys.platform
    from sentra_agent.inventory import collect_network, parse_resolv_conf

    servers = list((collect_network() or {}).get("dns_servers", []))
    if platform.startswith("linux"):
        # systemd-resolved: /etc/resolv.conf apunta a 127.0.0.53 (loopback, ya permitido);
        # los servidores reales están aquí y también hay que dejarlos pasar.
        try:
            text = Path("/run/systemd/resolve/resolv.conf").read_text(encoding="utf-8")
            servers.extend(parse_resolv_conf(text))
        except OSError:
            pass
    return list(dict.fromkeys(servers))


def default_dhcp_server(platform: str | None = None) -> str | None:
    """Servidor DHCP actual en Windows; en Linux se cubre por puertos en la regla nft."""
    if (platform or sys.platform) != "win32":
        return None
    import json

    from sentra_agent.endpoint import CollectorUnavailableError, run_powershell

    script = (
        "@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' "
        "| Where-Object { $_.DHCPEnabled } | ForEach-Object { [string]$_.DHCPServer }) "
        "| ConvertTo-Json -Compress"
    )
    try:
        data = json.loads(run_powershell(script) or "null")
    except (CollectorUnavailableError, PermissionError, ValueError):
        return None
    for value in data if isinstance(data, list) else [data]:
        try:
            return str(ipaddress.ip_address(str(value)))
        except ValueError:
            continue
    return None


def default_backend(platform: str, state_dir: Path) -> FirewallBackend | None:
    if platform == "win32":
        from sentra_agent.isolation.windows import WindowsFirewallBackend

        return WindowsFirewallBackend()
    if platform.startswith("linux"):
        from sentra_agent.isolation.nft import NftablesBackend

        return NftablesBackend(state_dir)
    return None  # macOS: sin aislamiento en 6E


class IsolationHelper:
    def __init__(
        self,
        policy_path: Path,
        exchange: ExchangeDir,
        state_dir: Path,
        backend: FirewallBackend | None,
        *,
        resolve: Callable[[str, int], list[str]] = resolve_host,
        dns_servers: Callable[[], list[str]] = default_dns_servers,
        dhcp_server: Callable[[], str | None] = default_dhcp_server,
        wall: Callable[[], float] = time.time,
    ) -> None:
        self.policy_path = policy_path
        self.exchange = exchange
        self.state_dir = state_dir
        self.backend = backend
        self._resolve = resolve
        self._dns = dns_servers
        self._dhcp = dhcp_server
        self._wall = wall
        self.state = HelperState()
        self.policy: HelperPolicy | None = None
        self.policy_error: str | None = None
        self._status_written_at = -1e18
        self._checked_at = -1e18
        self._dirty = True
        self._helper_written: str | None = None

    # Utilidades ----------------------------------------------------------------------

    def _now(self) -> datetime:
        return datetime.fromtimestamp(self._wall(), UTC)

    def _load_policy(self) -> None:
        try:
            self.policy = load_policy(self.policy_path)
            self.policy_error = None
        except PolicyError as exc:
            # Política ilegible = desactivado (nunca se aísla con una política dudosa).
            self.policy = None
            self.policy_error = "policy_invalid"
            logger.error("isolation policy invalid", extra={"error": str(exc)})

    def helper_status(self) -> str:
        if self.policy_error or self.backend is None:
            return HELPER_ERROR
        if self.policy is None or not self.policy.enabled:
            return HELPER_DISABLED
        return HELPER_READY

    def _save(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        write_atomic(self.state_dir / PRIVATE_STATE, _json(asdict(self.state)), private=True)
        self._dirty = True

    def _load_state(self) -> None:
        self.state = HelperState.from_dict(read_json(self.state_dir / PRIVATE_STATE))

    def _record(self, session_id: str | None, action: str, ok: bool, code: str | None) -> None:
        self.state.last_action = {
            "session_id": session_id,
            "action": action,
            "outcome": "succeeded" if ok else "failed",
            "error_code": code,
            "at": self._now().isoformat(),
        }

    def write_status(self, force: bool = False) -> None:
        now = self._wall()
        helper = self.helper_status()
        # Un cambio de política (activar/desactivar) se publica en el siguiente paso, no a
        # los 30 s: el agente decide con ese estado si anuncia isolate_host.
        changed = helper != self._helper_written
        if not (
            force
            or changed
            or self._dirty
            or now - self._status_written_at >= STATUS_REFRESH_SECONDS
        ):
            return
        status = {
            "helper": helper,
            "state": self.state.state,
            "session_id": self.state.session_id,
            "applied_at": self.state.applied_at,
            "expires_at": self.state.expires_at,
            "method": self.state.method,
            "verified": self.state.verified,
            "error_code": self.state.error_code or self.policy_error,
            "updated_at": self._now().isoformat(),
            "allowed": self.state.allowed,
            "rules": self.state.rules,
            "last_action": self.state.last_action,
        }
        try:
            self.exchange.write(STATUS_FILE, status)
            self.exchange.write(STATE_FILE, asdict(self.state))
        except (OSError, IsolationError) as exc:
            logger.error("cannot write isolation status", extra={"error": str(exc)})
            return
        self._status_written_at = now
        self._helper_written = helper
        self._dirty = False

    def _revert_quietly(self) -> bool:
        if self.backend is None:
            return False
        try:
            self.backend.revert()
            return not self.backend.present()
        except IsolationError as exc:
            logger.error("isolation revert failed", extra={"error": exc.code})
            return False

    # Ciclo de vida -------------------------------------------------------------------

    def startup(self) -> None:
        self._load_policy()
        try:
            self.exchange.prepare()
        except (OSError, IsolationError) as exc:
            logger.error("isolation exchange directory unusable", extra={"error": str(exc)})
        self._load_state()
        self.recover()
        self.write_status(force=True)

    def recover(self) -> None:
        """Al arrancar: nunca deja un aislamiento caducado, a medias o sin política."""
        state = self.state
        if state.state == STATE_NONE:
            return
        expired = self._expired()
        disabled = self.policy is None or not self.policy.enabled
        if state.state in (STATE_APPLYING, STATE_REVERTING, STATE_FAILED) or expired or disabled:
            reason = (
                "expired" if expired else "policy_disabled" if disabled else "incomplete_on_start"
            )
            ok = self._revert_quietly()
            logger.warning("reverted isolation on start", extra={"reason": reason, "ok": ok})
            self._record(state.session_id, "expire" if expired else "recover", ok, reason)
            self._clear(None if ok else "revert_failed")
            self._save()
            return
        if self.backend is not None and not self.backend.present():
            # Linux: la tabla nft no es persistente; tras reiniciar el equipo ya no existe.
            # No se vuelve a aplicar: aislar exige una petición nueva.
            self._record(state.session_id, "recover", True, "rules_lost")
            self._clear("rules_lost")
            self._save()

    def _clear(self, error_code: str | None) -> None:
        last = self.state.last_action
        self.state = HelperState(error_code=error_code, last_action=last)
        self.state.state = STATE_NONE if error_code in (None, "rules_lost") else STATE_FAILED

    def _expired(self) -> bool:
        if not self.state.expires_at:
            return False
        try:
            return self._now() >= parse_iso(self.state.expires_at)
        except ValueError:
            return True

    def step(self) -> None:
        self._load_policy()
        self._handle_request()
        self._check_expiry()
        self._check_presence()
        self.write_status()

    def _check_expiry(self) -> None:
        if self.state.state == STATE_ISOLATED and self._expired():
            session = self.state.session_id
            ok = self._revert_quietly()
            logger.info("isolation expired and reverted", extra={"ok": ok})
            self._record(session, "expire", ok, None if ok else "revert_failed")
            self._clear(None if ok else "revert_failed")
            self._save()
        elif self.state.state == STATE_ISOLATED and (
            self.policy is None or not self.policy.enabled
        ):
            # El administrador desactivó la política durante un aislamiento: se revierte.
            session = self.state.session_id
            ok = self._revert_quietly()
            self._record(session, "recover", ok, "policy_disabled")
            self._clear(None if ok else "revert_failed")
            self._save()

    def _check_presence(self) -> None:
        now = self._wall()
        if self.state.state != STATE_ISOLATED or now - self._checked_at < PRESENCE_CHECK_SECONDS:
            return
        self._checked_at = now
        if self.backend is not None and not self.backend.present():
            logger.warning("isolation rules disappeared (removed outside Sentra)")
            self._record(self.state.session_id, "recover", True, "rules_removed_externally")
            self._clear("rules_lost")
            self._save()

    def _handle_request(self) -> None:
        try:
            raw = self.exchange.take_request(self._wall())
        except IsolationError as exc:
            logger.warning("isolation request rejected", extra={"error": exc.code})
            return
        except OSError as exc:
            logger.error("cannot read isolation request", extra={"error": str(exc)})
            return
        if raw is None:
            return
        try:
            request = parse_request(raw)
        except IsolationError as exc:
            logger.warning("isolation request invalid", extra={"error": str(exc)})
            return
        logger.info(
            "isolation request",
            extra={"action": request.action, "session_id": str(request.session_id)},
        )
        try:
            if request.action == "isolate":
                self._isolate(request)
            else:
                self._release(request)
        except IsolationError as exc:
            self._record(str(request.session_id), request.action, False, exc.code)
            self._dirty = True
        self._save()

    def _allowed(self, policy: HelperPolicy) -> list[Network]:
        """Lo permitido, calculado SOLO con datos locales (nunca de la petición)."""
        if policy.agent_config is None:
            raise IsolationError("agent_config_missing", "isolation.toml has no agent_config")
        try:
            config = tomllib.loads(policy.agent_config.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise IsolationError("agent_config_unreadable", str(exc)) from exc
        api_url = config.get("api_url")
        parsed = urlparse(api_url if isinstance(api_url, str) else "")
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise IsolationError("agent_config_unreadable", "api_url missing or invalid")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        servers = self._resolve(parsed.hostname, port)
        if not servers:
            # Sin la IP del servidor el equipo quedaría incomunicado: no se aísla.
            raise IsolationError("server_unresolvable", "cannot resolve the Sentra server")
        return allowed_networks(
            servers,
            dns_servers=self._dns() if policy.allow_dns else [],
            dhcp_server=self._dhcp(),
            extra_allow=policy.extra_allow,
            allow_dns=policy.allow_dns,
        )

    def _isolate(self, request: Request) -> None:
        session = str(request.session_id)
        policy = self.policy
        if self.backend is None:
            raise IsolationError("not_supported", "no firewall backend on this platform")
        if policy is None or not policy.enabled:
            raise IsolationError("helper_disabled", "isolation disabled by local policy")
        now = self._now()
        expires = request.expires_at
        if expires is None or expires <= now:
            raise IsolationError("invalid_request", "expires_at is not in the future")
        if expires - now > timedelta(minutes=policy.max_minutes):
            raise IsolationError("duration_exceeds_policy", "duration exceeds max_minutes")
        if self.state.state == STATE_ISOLATED:
            if self.state.session_id == session:
                self._record(session, "isolate", True, None)  # reentrega: ya aplicado
                return
            raise IsolationError("already_isolated", "another isolation session is active")
        allowed = self._allowed(policy)
        self.backend.precheck()
        self.state = HelperState(
            state=STATE_APPLYING,
            session_id=session,
            expires_at=expires.isoformat(),
            method=self.backend.method,
            allowed=[_display(net) for net in allowed],
            last_action=self.state.last_action,
        )
        # Guardado ANTES de tocar el firewall: si el helper muere a medias, al arrancar se
        # revierte en lugar de quedar un aislamiento sin dueño.
        self._save()
        try:
            rules = self.backend.apply(allowed, request.session_id, expires)
            verified = self.backend.verify(allowed)
        except IsolationError as exc:
            self._revert_quietly()
            self.state.state = STATE_FAILED
            self.state.error_code = exc.code
            raise
        if not verified:
            self._revert_quietly()
            self.state.state = STATE_FAILED
            self.state.error_code = "verification_failed"
            raise IsolationError("verification_failed", "rules could not be read back")
        self.state.state = STATE_ISOLATED
        self.state.rules = rules
        self.state.verified = True
        self.state.applied_at = self._now().isoformat()
        self.state.error_code = None
        self._checked_at = self._wall()
        self._record(session, "isolate", True, None)

    def _release(self, request: Request) -> None:
        session = str(request.session_id)
        active = self.state.state != STATE_NONE and self.state.session_id is not None
        if active and self.state.session_id != session:
            raise IsolationError("session_mismatch", "release for another session")
        if self.backend is None:
            raise IsolationError("not_supported", "no firewall backend on this platform")
        self.state.state = STATE_REVERTING
        self._save()
        if not self._revert_quietly():
            self.state.state = STATE_FAILED
            self.state.error_code = "revert_failed"
            raise IsolationError("revert_failed", "isolation rules are still present")
        self._record(session, "release", True, None)
        self._clear(None)

    def run(self, stop: threading.Event) -> None:
        self.startup()
        while not stop.is_set():
            try:
                self.step()
            except Exception:
                logger.exception("isolation helper step failed")
            stop.wait(STEP_SECONDS)

    def revert_now(self) -> bool:
        """Desinstalación o emergencia: quita las reglas propias pase lo que pase."""
        self._load_state()
        ok = self._revert_quietly()
        self._record(self.state.session_id, "recover", ok, "manual_revert")
        self._clear(None if ok else "revert_failed")
        self._save()
        self.write_status(force=True)
        return ok


def _display(network: Network) -> str:
    """Una dirección suelta sin /32 ni /128 (como en el contrato); las redes en CIDR."""
    return str(network.network_address) if network.num_addresses == 1 else str(network)


def _json(data: dict[str, Any]) -> str:
    import json

    return json.dumps(data, indent=2, sort_keys=True)


def build_helper(args: argparse.Namespace) -> IsolationHelper:
    paths = default_paths()
    state_dir = args.state_dir or paths["state_dir"]
    return IsolationHelper(
        args.policy or paths["policy"],
        ExchangeDir(args.exchange_dir or paths["exchange_dir"]),
        state_dir,
        default_backend(sys.platform, state_dir),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentra_agent.isolation_helper")
    parser.add_argument("command", nargs="?", default="run", choices=["run", "revert", "status"])
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--exchange-dir", type=Path)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--service", action="store_true", help="Windows SCM mode")
    args = parser.parse_args(argv)

    from sentra_agent.logs import configure_logging

    paths = default_paths()
    state_dir = args.state_dir or paths["state_dir"]
    configure_logging(
        state_dir,
        "INFO",
        args.log_dir or paths["log_dir"],
        console=not args.service,
        file_name="isolation-helper.log",
    )
    helper = build_helper(args)
    if args.command == "revert":
        return 0 if helper.revert_now() else 1
    if args.command == "status":
        helper.startup()
        print(_json({"helper": helper.helper_status(), **asdict(helper.state)}))
        return 0
    if args.service:
        from sentra_agent.winservice import NotRunningAsServiceError, dispatch

        try:
            return dispatch(helper.run, SERVICE_NAME)
        except NotRunningAsServiceError:
            logger.error("--service is only for the Windows Service Control Manager")
            return 2
    stop = threading.Event()
    import signal

    for name in ("SIGTERM", "SIGINT"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), lambda *_: stop.set())
    helper.run(stop)
    return 0


if __name__ == "__main__":
    sys.exit(main())

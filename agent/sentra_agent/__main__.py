"""Command line entry point: `python -m sentra_agent`."""

import argparse
import logging
import signal
import sys
import threading
from pathlib import Path

from sentra_agent import __version__
from sentra_agent.client import client_for
from sentra_agent.config import AgentConfig, load_config
from sentra_agent.credentials import CredentialStoreUnavailableError, check_store
from sentra_agent.enrollment import (
    EXIT_CREDENTIAL_STORE,
    EXIT_ENROLLED,
    EXIT_NO_CREDENTIAL,
    EXIT_REJECTED,
    EXIT_UNREACHABLE,
    bootstrap_service_enrollment,
    enroll_once,
)
from sentra_agent.identity import IdentityStore
from sentra_agent.logs import configure_logging
from sentra_agent.runner import Agent
from sentra_agent.winservice import NotRunningAsServiceError, dispatch

# Re-exported: the Linux installer tests import the exit codes from here.
__all__ = [
    "EXIT_CREDENTIAL_STORE",
    "EXIT_ENROLLED",
    "EXIT_NO_CREDENTIAL",
    "EXIT_REJECTED",
    "EXIT_UNREACHABLE",
    "main",
]


def _enroll(agent: Agent) -> int:
    # One result line on stdout (read by installers); details are in the log.
    outcome = enroll_once(agent)
    print(outcome.message)
    return outcome.exit_code


def _run_service(config: AgentConfig) -> int:
    """Modo servicio Windows: el SCM arranca el proceso y lo controla con dispatch()."""

    def body(stop: threading.Event) -> None:
        # El agente se crea dentro del ServiceMain: un error al cargar el estado (permisos
        # del directorio, disco lleno) se informa al SCM como fallo del servicio y activa
        # su recuperación, en lugar de terminar el proceso antes de conectar con el SCM.
        agent = Agent(
            config,
            client_for(config),
            IdentityStore(config.state_dir, config.credential_store),
            stop_event=stop,
        )
        bootstrap_service_enrollment(agent, stop)
        agent.run()

    try:
        return dispatch(body)
    except NotRunningAsServiceError:
        logging.getLogger("sentra_agent").error(
            "--service is only for the Windows Service Control Manager"
            " (Start-Service SentraAgent); run without --service in a console"
        )
        return 2


def main(argv: list[str] | None = None) -> int:
    args_list = sys.argv[1:] if argv is None else argv
    if args_list[:1] == ["isolation-helper"]:
        # Fase 6E.7: el lanzador de Linux (/opt/sentra-agent/bin/sentra-agent) sirve también
        # para la unidad sentra-isolation, sin un segundo lanzador con otro intérprete.
        from sentra_agent.isolation_helper import main as helper_main

        return helper_main(args_list[1:])
    parser = argparse.ArgumentParser(prog="sentra-agent", description="Sentra endpoint agent")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", type=Path, help="TOML config file (see agent.example.toml)")
    parser.add_argument("--api-url")
    parser.add_argument("--interval", type=int, dest="interval_seconds")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--log-level")
    # A file, not a value: command lines are visible to other users (ps, Task Manager).
    parser.add_argument(
        "--enrollment-token-file",
        type=Path,
        help="file holding a one-time enrollment token; deleted once the agent is enrolled",
    )
    parser.add_argument("--once", action="store_true", help="run a single cycle and exit")
    parser.add_argument(
        "--rotate-credential",
        action="store_true",
        help="replace this agent's own credential with a new one (needs https), then exit",
    )
    parser.add_argument(
        "--service",
        action="store_true",
        help="run under the Windows Service Control Manager (set by the Windows installer)",
    )
    parser.add_argument(
        "--no-console-log",
        action="store_true",
        help="log only to the rotating file (used by the macOS LaunchDaemon, whose console"
        " output would otherwise grow without rotation)",
    )
    parser.add_argument(
        "--enroll",
        action="store_true",
        help="enroll if not enrolled yet, then exit (exit code tells the result; used by"
        " installers)",
    )
    args = parser.parse_args(args_list)

    try:
        config = load_config(
            args.config,
            {
                "api_url": args.api_url,
                "interval_seconds": args.interval_seconds,
                "state_dir": args.state_dir,
                "log_level": args.log_level,
                "enrollment_token_file": args.enrollment_token_file,
            },
        )
    except (ValueError, OSError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    # Un servicio no tiene consola: solo el archivo de log rotado.
    log_file = configure_logging(
        config.state_dir,
        config.log_level,
        config.log_dir,
        console=not (args.service or args.no_console_log),
    )
    logging.getLogger("sentra_agent").info("logging to file", extra={"path": str(log_file)})
    if args.service:
        return _run_service(config)

    stop = threading.Event()
    # SIGTERM (Linux service managers) and SIGBREAK (Windows console close) stop the loop
    # cleanly between cycles instead of killing it mid-request.
    for name in ("SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), lambda *_: stop.set())

    try:
        # Fase 6C.5: antes de enrolar o cargar el token, el almacén elegido debe funcionar
        # (Keychain en macOS). Si no, se para aquí con un mensaje claro: nunca se enrola
        # para luego perder el token ni se guarda en claro sin que lo pida la configuración.
        check_store(config.credential_store, config.state_dir)
        agent = Agent(
            config,
            client_for(config),
            IdentityStore(config.state_dir, config.credential_store),
            stop_event=stop,
        )
    except CredentialStoreUnavailableError as exc:
        logging.getLogger("sentra_agent").error(
            "credential store unavailable; the agent will not enroll or report",
            extra={"error": str(exc), "credential_store": config.credential_store},
        )
        print(f"credential store unavailable: {exc}")
        return EXIT_CREDENTIAL_STORE
    if args.enroll:
        return _enroll(agent)
    if args.rotate_credential:
        # Fase 7D.1: rotación manual (p. ej. tras migrar a HTTPS una credencial que viajó en
        # claro). Requiere estar enrolado y un api_url https:// (o loopback).
        try:
            rotated = agent.rotate_credential()
        except Exception as exc:  # se informa y se sale con código de error
            print(f"credential rotation failed: {exc}", file=sys.stderr)
            return 1
        print("credential rotated" if rotated else "credential rotation failed; see the log")
        return 0 if rotated else 1
    try:
        agent.run(once=args.once)
    except KeyboardInterrupt:
        stop.set()
        logging.getLogger("sentra_agent").info("agent stopped by user")
    return 0


if __name__ == "__main__":
    sys.exit(main())

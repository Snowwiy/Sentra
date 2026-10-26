"""CLI `sentra-sensor`: enroll, run, status, diagnostics. Sin GUI."""

import argparse
import json
import logging
import signal
import sys
import threading
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TextIO

from sentra_sensor import __version__
from sentra_sensor.client import Transport, TransportError, UrllibTransport
from sentra_sensor.config import ConfigError, LocalConfig, default_config_path, load_config
from sentra_sensor.credentials import CredentialError, CredentialStore
from sentra_sensor.diagnostics import local_status, run_diagnostics
from sentra_sensor.enrollment import EnrollmentError, enroll
from sentra_sensor.fingerprint import SystemFingerprintProber
from sentra_sensor.logs import configure_logging, register_secret
from sentra_sensor.names import SystemIdentityProber
from sentra_sensor.runner import ProberSet, SensorRunner
from sentra_sensor.scanner import AsyncioTcpProber, default_probers

logger = logging.getLogger("sentra_sensor")

TransportFactory = Callable[[LocalConfig], Transport]


def _default_transport(config: LocalConfig) -> Transport:
    return UrllibTransport(config.ca_bundle)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentra-sensor", description="Sentra distributed network sensor"
    )
    parser.add_argument("--version", action="version", version=f"sentra-sensor {__version__}")
    parser.add_argument("--config", type=Path, help="path to sensor.toml")
    parser.add_argument("--data-dir", type=Path, help="override data_dir from the config")
    sub = parser.add_subparsers(dest="command", required=True)

    enroll_p = sub.add_parser("enroll", help="enroll this sensor with a one-time token")
    enroll_p.add_argument("--server", required=True, help="Sentra server URL (https://...)")
    token = enroll_p.add_mutually_exclusive_group(required=True)
    token.add_argument("--token", help="enrollment token (prefer --token-file or --token-stdin)")
    token.add_argument("--token-file", type=Path, help="file containing the enrollment token")
    token.add_argument(
        "--token-stdin", action="store_true", help="read the enrollment token from stdin"
    )
    enroll_p.add_argument(
        "--force", action="store_true", help="replace an existing credential (re-enroll)"
    )

    run_p = sub.add_parser("run", help="run the sensor in the foreground")
    run_p.add_argument(
        "--service", action="store_true", help="run under the Windows Service Control Manager"
    )
    run_p.add_argument(
        "--enroll-token-file",
        type=Path,
        help="if not enrolled yet, enroll first with this token file (deleted afterwards)",
    )
    status_p = sub.add_parser("status", help="show local state (no network)")
    status_p.add_argument("--json", action="store_true")
    diag_p = sub.add_parser("diagnostics", help="check server, TLS, credential and spool")
    diag_p.add_argument("--json", action="store_true")
    return parser


def _load(args: argparse.Namespace) -> LocalConfig:
    path: Path | None = args.config
    if path is None:
        candidate = default_config_path()
        path = candidate if candidate.exists() else None
    elif not path.exists():
        raise ConfigError(f"config file {path} does not exist")
    overrides: dict[str, Any] = {}
    if args.data_dir is not None:
        overrides["data_dir"] = args.data_dir
    return load_config(path, overrides)


def _read_token(args: argparse.Namespace, stdin: TextIO) -> str:
    if args.token is not None:
        return str(args.token)
    if args.token_file is not None:
        return Path(args.token_file).read_text(encoding="utf-8")
    return stdin.readline()


def cmd_enroll(
    args: argparse.Namespace,
    config: LocalConfig,
    transport_factory: TransportFactory,
    out: TextIO,
    stdin: TextIO,
) -> int:
    try:
        raw_token = _read_token(args, stdin)
    except OSError as exc:
        print(f"error: cannot read the token: {exc.strerror}", file=sys.stderr)
        return 2
    register_secret(raw_token.strip())
    try:
        result = enroll(config, args.server, raw_token, transport_factory(config), force=args.force)
    except (EnrollmentError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except TransportError as exc:
        print(f"error: cannot reach the server: {exc}", file=sys.stderr)
        return 3
    identity = result.identity
    # Solo identificadores públicos: ni el token ni la credencial se imprimen jamás.
    print(f"Enrolled sensor {identity.sensor_id}", file=out)
    print(f"Site: {identity.site_name} ({identity.site_id})", file=out)
    print(f"Credential stored at {config.credential_file()}", file=out)
    return 0


def _run_foreground(config: LocalConfig, transport_factory: TransportFactory) -> int:
    configure_logging(config.logs_dir(), config.log_level)
    runner = build_runner(config, transport_factory)

    def on_signal(_signum: int, _frame: object) -> None:
        runner.stop()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    runner.run()
    return 0


def build_runner(config: LocalConfig, transport_factory: TransportFactory) -> SensorRunner:
    def probers() -> ProberSet:
        icmp, neighbors, resolver = default_probers(
            config.allow_system_ping, config.allow_system_arp
        )
        return ProberSet(
            AsyncioTcpProber(),
            icmp,
            neighbors,
            resolver,
            SystemIdentityProber(),
            SystemFingerprintProber(),
        )

    return SensorRunner(config, transport_factory(config), probers=probers)


def _run_service(config: LocalConfig, transport_factory: TransportFactory) -> int:
    from sentra_sensor import winservice

    configure_logging(config.logs_dir(), config.log_level, console=False)

    def body(stop_event: threading.Event) -> None:
        runner = build_runner(config, transport_factory)

        def watch() -> None:
            stop_event.wait()
            runner.stop()

        threading.Thread(target=watch, name="sensor-stop-watch", daemon=True).start()
        runner.run()

    try:
        return winservice.dispatch(body)
    except winservice.NotRunningAsServiceError:
        print("error: --service must be started by the Windows Service Control Manager")
        return 2


def enroll_on_first_run(config: LocalConfig, token_file: Path, factory: TransportFactory) -> None:
    """Enrolla con la cuenta que ejecuta el servicio (necesario para DPAPI en Windows).

    Con DPAPI en ámbito de usuario, una credencial cifrada por el administrador que instala no
    la puede descifrar la cuenta virtual del servicio. Por eso el instalador deja el token en
    un fichero protegido por ACL y es el propio servicio quien enrola en su primer arranque.
    El fichero se borra tras un enrollment correcto: el token es de un solo uso.
    """
    if CredentialStore(config.credential_file()).exists() or not token_file.exists():
        return
    if config.server_url is None:
        raise ConfigError("server_url must be set in the config to enroll on first run")
    token = token_file.read_text(encoding="utf-8")
    enroll(config, config.server_url, token, factory(config))
    token_file.unlink()
    logger.info("enrolled on first run; token file removed")


def cmd_run(args: argparse.Namespace, config: LocalConfig, factory: TransportFactory) -> int:
    try:
        if args.enroll_token_file is not None:
            enroll_on_first_run(config, args.enroll_token_file, factory)
        if args.service:
            return _run_service(config, factory)
        return _run_foreground(config, factory)
    except CredentialError as exc:
        print(f"error: {exc}. Run `sentra-sensor enroll` first.", file=sys.stderr)
        return 2
    except (EnrollmentError, ConfigError, TransportError) as exc:
        print(f"error: first-run enrollment failed: {exc}", file=sys.stderr)
        return 2


def cmd_status(args: argparse.Namespace, config: LocalConfig, out: TextIO) -> int:
    status = local_status(config)
    if args.json:
        print(json.dumps(status, indent=2), file=out)
        return 0
    print(f"Version:        {status['version']}", file=out)
    print(f"Enrolled:       {'yes' if status['enrolled'] else 'no'}", file=out)
    if status["enrolled"]:
        print(f"Sensor ID:      {status['sensor_id']}", file=out)
        print(f"Site:           {status['site_name']} ({status['site_id']})", file=out)
        print(f"Server:         {status['server_url']}", file=out)
    elif status.get("credential_error"):
        print(f"Credential:     {status['credential_error']}", file=out)
    print(f"Mode:           {status['mode']}", file=out)
    print(f"Last heartbeat: {status['last_heartbeat_at'] or '-'}", file=out)
    print(f"Last job OK:    {status['last_successful_job_at'] or '-'}", file=out)
    if "allowed_networks" in status:
        print(f"Networks:       {', '.join(status['allowed_networks']) or '-'}", file=out)
    spool = status["spool"]
    print(
        f"Spool:          {spool['items']} items, {spool['bytes']} bytes,"
        f" {spool['dropped_total']} dropped ({spool['path']})",
        file=out,
    )
    return 0


def cmd_diagnostics(
    args: argparse.Namespace, config: LocalConfig, factory: TransportFactory, out: TextIO
) -> int:
    checks = run_diagnostics(config, factory(config))
    if args.json:
        print(json.dumps([c.__dict__ for c in checks], indent=2), file=out)
    else:
        for check in checks:
            print(f"[{'OK' if check.ok else 'FAIL'}] {check.name}: {check.detail}", file=out)
    return 0 if all(c.ok for c in checks) else 1


def main(
    argv: Sequence[str] | None = None,
    transport_factory: TransportFactory | None = None,
    out: TextIO | None = None,
    stdin: TextIO | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    factory = transport_factory or _default_transport
    out = out or sys.stdout
    try:
        config = _load(args)
    except (ConfigError, OSError, ValueError) as exc:
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        return 2
    if args.command in ("enroll", "run"):
        try:
            config.ensure_data_dir()
        except OSError as exc:
            print(f"error: cannot prepare data_dir: {exc.strerror}", file=sys.stderr)
            return 2
    if args.command == "enroll":
        return cmd_enroll(args, config, factory, out, stdin or sys.stdin)
    if args.command == "run":
        return cmd_run(args, config, factory)
    if args.command == "status":
        return cmd_status(args, config, out)
    return cmd_diagnostics(args, config, factory, out)

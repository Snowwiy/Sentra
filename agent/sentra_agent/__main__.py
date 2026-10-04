"""Command line entry point: `python -m sentra_agent`."""

import argparse
import ipaddress
import logging
import signal
import sys
import threading
from pathlib import Path
from urllib.parse import urlparse

from sentra_agent import __version__
from sentra_agent.client import SentraClient, TransportError
from sentra_agent.config import load_config
from sentra_agent.identity import IdentityStore
from sentra_agent.logs import configure_logging
from sentra_agent.runner import Agent, CredentialsRejectedError, EnrollmentKeyMissingError


def _warn_if_cleartext(api_url: str) -> None:
    # Without TLS the bearer token travels in clear text and anyone on the path can replay
    # it. Loopback is fine (development, agent next to the API); anything else should be
    # https until mTLS or a TLS-terminating proxy is in place.
    parsed = urlparse(api_url)
    if parsed.scheme == "https":
        return
    host = parsed.hostname or ""
    try:
        loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback:
        logging.getLogger("sentra_agent").warning(
            "api_url is not https: the agent token is sent unencrypted over the network",
            extra={"api_url": api_url},
        )


# Exit codes of --enroll, read by the Linux installer.
EXIT_ENROLLED = 0
EXIT_NO_CREDENTIAL = 3
EXIT_REJECTED = 4
EXIT_UNREACHABLE = 5


def _enroll(agent: Agent) -> int:
    already = agent.identity.token is not None
    try:
        asset_id = agent.enroll()
    except EnrollmentKeyMissingError:
        # One result line on stdout (read by installers); details are in the log.
        print("not enrolled and no enrollment token/key configured")
        return EXIT_NO_CREDENTIAL
    except CredentialsRejectedError as exc:
        print(f"enrollment refused by the server: {exc.reason}")
        return EXIT_REJECTED
    except TransportError as exc:
        print(f"server unreachable: {exc}")
        return EXIT_UNREACHABLE
    state = "already enrolled" if already else "enrolled"
    print(f"{state}: agent_id={agent.identity.agent_id} asset_id={asset_id}")
    return EXIT_ENROLLED


def main(argv: list[str] | None = None) -> int:
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
        "--enroll",
        action="store_true",
        help="enroll if not enrolled yet, then exit (exit code tells the result; used by"
        " installers)",
    )
    args = parser.parse_args(argv)

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

    log_file = configure_logging(config.state_dir, config.log_level, config.log_dir)
    logging.getLogger("sentra_agent").info("logging to file", extra={"path": str(log_file)})
    _warn_if_cleartext(config.api_url)

    stop = threading.Event()
    # SIGTERM (Linux service managers) and SIGBREAK (Windows console close) stop the loop
    # cleanly between cycles instead of killing it mid-request.
    for name in ("SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), lambda *_: stop.set())

    agent = Agent(
        config,
        SentraClient(config.api_url, config.request_timeout_seconds),
        IdentityStore(config.state_dir),
        stop_event=stop,
    )
    if args.enroll:
        return _enroll(agent)
    try:
        agent.run(once=args.once)
    except KeyboardInterrupt:
        stop.set()
        logging.getLogger("sentra_agent").info("agent stopped by user")
    return 0


if __name__ == "__main__":
    sys.exit(main())

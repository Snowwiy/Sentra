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
from sentra_agent.client import SentraClient
from sentra_agent.config import load_config
from sentra_agent.identity import IdentityStore
from sentra_agent.logs import configure_logging
from sentra_agent.runner import Agent


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentra-agent", description="Sentra endpoint agent")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", type=Path, help="TOML config file (see agent.example.toml)")
    parser.add_argument("--api-url")
    parser.add_argument("--interval", type=int, dest="interval_seconds")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--log-level")
    parser.add_argument("--once", action="store_true", help="run a single cycle and exit")
    args = parser.parse_args(argv)

    try:
        config = load_config(
            args.config,
            {
                "api_url": args.api_url,
                "interval_seconds": args.interval_seconds,
                "state_dir": args.state_dir,
                "log_level": args.log_level,
            },
        )
    except (ValueError, OSError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    log_file = configure_logging(config.state_dir, config.log_level)
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
    try:
        agent.run(once=args.once)
    except KeyboardInterrupt:
        stop.set()
        logging.getLogger("sentra_agent").info("agent stopped by user")
    return 0


if __name__ == "__main__":
    sys.exit(main())

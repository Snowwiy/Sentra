"""Comprobaciones estáticas: nada de shell, eval/exec ni TLS desactivado en el paquete."""

import re
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "sentra_sensor"
FORBIDDEN = [
    r"shell\s*=\s*True",
    r"\beval\(",
    r"\bexec\(",
    r"os\.system",
    r"os\.popen",
    r"create_subprocess_shell",
    r"CERT_NONE",
    r"check_hostname\s*=\s*False",
    r"_create_unverified_context",
    r"verify\s*=\s*False",
    r"pickle",
]


@pytest.mark.parametrize("source", sorted(PACKAGE.glob("*.py")), ids=lambda p: p.name)
def test_no_dangerous_constructs(source: Path) -> None:
    text = source.read_text(encoding="utf-8")
    for pattern in FORBIDDEN:
        assert not re.search(pattern, text), f"{source.name}: {pattern}"


def test_no_listening_sockets() -> None:
    # El sensor solo hace conexiones salientes: ningún bind/listen/servidor.
    for source in PACKAGE.glob("*.py"):
        text = source.read_text(encoding="utf-8")
        assert not re.search(r"\.(bind|listen)\(|start_server|HTTPServer", text), source.name

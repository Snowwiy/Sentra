"""Comprobación de higiene del repositorio para CI (Fase 7D.2, H08). Solo biblioteca estándar.

Falla (código 1) si algún fichero versionado:
- es de un tipo que nunca debe publicarse (.env real, claves privadas, certificados con clave,
  volcados de base de datos, entornos virtuales, node_modules, dist, cachés), o
- contiene algo con forma de secreto: claves privadas PEM/OpenSSH/PGP, tokens de instalación o
  recuperación de Sentra (sentra_et_, sentra_et_rec_), tokens de GitHub, Slack, AWS u OpenAI.

Qué NO hace (y no debe presentarse como tal): no detecta secretos sin formato reconocible (una
contraseña cualquiera, las credenciales de agente, que son aleatorias sin prefijo), no revisa el
historial de Git ni los ficheros sin versionar. Para eso está el secret scanning de GitHub con
push protection, que se activa en la configuración del repositorio (docs/github-rulesets.md).

Marcadores de ejemplo: un valor de prueba se acepta si contiene "not-a-real" o "EXAMPLE"
(p. ej. "sentra_et_TEST-not-a-real-token_..."). Así un test puede usar el formato real sin que
un token verdadero copiado por error pase desapercibido.

Uso:  python scripts/ci/check_repo_hygiene.py           (ficheros de `git ls-files`)
      python scripts/ci/check_repo_hygiene.py --include-untracked   (antes de un commit)
      python scripts/ci/check_repo_hygiene.py --self-test
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

# Nombres o rutas que nunca se versionan. Se comparan con la ruta POSIX relativa.
FORBIDDEN_PATHS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("env_file", re.compile(r"(^|/)\.env(\.(?!example$)[^/]+)?$")),
    ("private_key_file", re.compile(r"\.(pem|key|p12|pfx|jks|keystore|kdbx|ppk)$", re.I)),
    ("ssh_key", re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$")),
    ("database_dump", re.compile(r"\.(dump|backup|sqlite3?|db)$|\.sql\.(gz|zst|bz2|xz)$", re.I)),
    ("snmp_key_file", re.compile(r"(^|/)snmp\.keys$")),
    ("virtualenv", re.compile(r"(^|/)(\.venv|venv|env)/")),
    ("node_modules", re.compile(r"(^|/)node_modules/")),
    ("build_output", re.compile(r"(^|/)(dist|build|htmlcov)/|\.egg-info/|\.tsbuildinfo$")),
    (
        "cache",
        re.compile(r"(^|/)(__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache)/|\.py[co]$"),
    ),
    ("agent_config", re.compile(r"(^|/)agent/agent\.toml$")),
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----"
        ),
    ),
    ("sentra_enrollment_token", re.compile(r"sentra_et_(rec_)?[A-Za-z0-9_-]{20,}")),
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("openai_key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}")),
)
PLACEHOLDER = re.compile(r"not-a-real|EXAMPLE", re.I)
# Ficheros mayores no se leen (binarios, lockfiles enormes); el tope cubre todo el código.
MAX_SCAN_BYTES = 2 * 1024 * 1024
# Este propio script contiene los patrones como texto.
SELF = PurePosixPath("scripts/ci/check_repo_hygiene.py")


def tracked_files(root: Path, untracked: bool = False) -> list[PurePosixPath]:
    # Con --include-untracked también los ficheros nuevos aún sin añadir (respeta .gitignore):
    # es lo que se quiere revisar ANTES de hacer commit en local.
    extra = ["-c", "-o", "--exclude-standard"] if untracked else []
    output = subprocess.run(  # noqa: S603  (argumentos fijos, sin shell)
        ["git", "ls-files", "-z", *extra],  # noqa: S607
        cwd=root,
        capture_output=True,
        check=True,
    ).stdout
    return [PurePosixPath(name) for name in output.decode("utf-8").split("\0") if name]


def path_findings(path: PurePosixPath) -> list[str]:
    text = path.as_posix()
    return [kind for kind, pattern in FORBIDDEN_PATHS if pattern.search(text)]


def content_findings(text: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                if PLACEHOLDER.search(match.group(0)) or PLACEHOLDER.search(line):
                    continue
                found.append((number, kind))
    return found


def scan(root: Path, files: list[PurePosixPath]) -> list[str]:
    problems: list[str] = []
    for path in files:
        for kind in path_findings(path):
            problems.append(f"{path}: {kind} must not be committed")
        if path == SELF:
            continue
        full = root / path
        try:
            if not full.is_file() or full.stat().st_size > MAX_SCAN_BYTES:
                continue
            data = full.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue  # binario
        for line, kind in content_findings(data.decode("utf-8", "replace")):
            # Nunca se imprime el valor: el log de CI es público en un repositorio abierto.
            problems.append(f"{path}:{line}: possible {kind}")
    return problems


def self_test() -> int:
    bad = [
        ".env",
        "backend/.env.production",
        "certs/server.key",
        "deploy/ca.pem",
        "backup/sentra.dump",
        "sensor/.venv/bin/python",
        "frontend/node_modules/x/index.js",
        "frontend/dist/index.html",
        "backend/app/__pycache__/x.pyc",
        "agent/agent.toml",
    ]
    good = [".env.example", "frontend/.env.example", "backend/app/main.py", "docs/a.md"]
    failures = [p for p in bad if not path_findings(PurePosixPath(p))]
    failures += [p for p in good if path_findings(PurePosixPath(p))]
    fake_key = "-----BEGIN " + "PRIVATE KEY-----"
    leaked = [
        fake_key,
        "token = 'sentra_et_" + "A" * 32 + "'",
        "ghp_" + "a" * 36,
        "AKIA" + "ABCDEFGHIJKLMNOP",
    ]
    placeholders = [
        "sentra_et_TEST-not-a-real-token_0123456789abcdef",
        "sentra_et_rec_EXAMPLE_0123456789abcdefghij",
        "AGENT_ENROLLMENT_KEY=",
    ]
    failures += [s for s in leaked if not content_findings(s)]
    failures += [s for s in placeholders if content_findings(s)]
    if failures:
        print(f"self-test failed for: {len(failures)} sample(s)", file=sys.stderr)
        return 1
    print("self-test passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--include-untracked", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    files = tracked_files(args.root, args.include_untracked)
    problems = scan(args.root, files)
    for problem in problems:
        print(problem)
    print(f"checked {len(files)} tracked files: {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

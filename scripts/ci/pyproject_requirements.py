"""Imprime las dependencias de un pyproject.toml (incluidos todos sus extras) en formato
requirements, para auditarlas con pip-audit sin instalar el paquete (Fase 7D.2, H07/H08).

Uso: python scripts/ci/pyproject_requirements.py agent/pyproject.toml > /tmp/agent-reqs.txt
"""

import sys
import tomllib
from pathlib import Path


def requirements(path: Path) -> list[str]:
    project = tomllib.loads(path.read_text(encoding="utf-8"))["project"]
    found = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        found.extend(extra)
    # Sin duplicados y en orden estable: el SBOM y el diff entre ejecuciones son legibles.
    return sorted(dict.fromkeys(found))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: pyproject_requirements.py <pyproject.toml>", file=sys.stderr)
        sys.exit(2)
    print("\n".join(requirements(Path(sys.argv[1]))))

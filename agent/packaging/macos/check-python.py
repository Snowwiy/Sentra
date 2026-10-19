"""Comprueba que un intérprete de Python es seguro para el daemon root de Sentra (macOS).

Se ejecuta con el propio intérprete candidato, en modo aislado: `python3 -I -S check-python.py`.
El daemon corre como root con `-I -S` (sin variables PYTHON*, sin site-packages, sin el
directorio actual), así que solo cargan código el ejecutable, su biblioteca y la biblioteca
estándar. Si alguno de ellos (o un directorio por encima) lo puede modificar otro usuario, ese
usuario podría ejecutar código como root sin contraseña. Por eso se exige:

- Python >= 3.12;
- propietario root (uid 0) y sin escritura para "otros" en todo ese código y sus directorios
  padre;
- sin escritura de grupo, salvo que el grupo sea `admin` y el administrador lo acepte
  explícitamente (--allow-admin-writable): el instalador de python.org deja su framework
  escribible por el grupo admin. Homebrew (propiedad del usuario) nunca se acepta.

Salida: una línea "ok <versión> <ruta>" (código 0), o "unsafe: <ruta>: <motivo>" (código 1),
o "too-old <versión>" (código 2). Solo biblioteca estándar.
"""

import os
import stat
import sys
import sysconfig

ADMIN_GID = 80  # grupo "admin" de macOS
MIN_VERSION = (3, 12)


def _problem(path: str, owner_uid: int, allow_admin: bool) -> str | None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        return f"cannot inspect ({exc.strerror})"
    if info.st_uid != owner_uid:
        return f"owned by uid {info.st_uid}, not root"
    if stat.S_ISLNK(info.st_mode):
        # Los bits de un enlace no cuentan; lo que importa es su directorio (ya revisado).
        return None
    if info.st_mode & stat.S_IWOTH and not (
        stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX
    ):
        return "writable by any user"
    if info.st_mode & stat.S_IWGRP:
        if info.st_gid == ADMIN_GID and allow_admin:
            return None
        return f"writable by group {info.st_gid}"
    return None


def _parents(path: str) -> list[str]:
    found = []
    current = os.path.dirname(path)
    while current and current not in found:
        found.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return found


def _tree(root: str) -> list[str]:
    paths = [root]
    for folder, dirs, files in os.walk(root):
        # site-packages no se carga (-S): se excluye aunque sea escribible.
        dirs[:] = [d for d in dirs if d not in ("site-packages", "__pycache__")]
        paths.extend(os.path.join(folder, name) for name in dirs + files)
    return paths


def check(owner_uid: int = 0, allow_admin: bool = False) -> list[tuple[str, str]]:
    executable = os.path.realpath(sys.executable)
    targets = [executable, *_parents(executable)]
    stdlib = os.path.realpath(sysconfig.get_paths()["stdlib"])
    targets += [*_parents(stdlib), *_tree(stdlib)]
    library = sysconfig.get_config_var("LDLIBRARY")
    libdir = sysconfig.get_config_var("LIBDIR")
    framework = sysconfig.get_config_var("PYTHONFRAMEWORKPREFIX")
    if framework:
        # Build de framework (python.org): la biblioteca es Versions/X.Y/Python.
        candidate = os.path.join(sys.base_prefix, "Python")
        if os.path.exists(candidate):
            targets.append(os.path.realpath(candidate))
    elif library and libdir and os.path.exists(os.path.join(libdir, library)):
        targets.append(os.path.realpath(os.path.join(libdir, library)))
    problems = []
    seen: set[str] = set()
    for path in targets:
        if path in seen:
            continue
        seen.add(path)
        reason = _problem(path, owner_uid, allow_admin)
        if reason:
            problems.append((path, reason))
    return problems


def main(argv: list[str]) -> int:
    if sys.version_info < MIN_VERSION:
        print(f"too-old {sys.version.split()[0]}")
        return 2
    allow_admin = "--allow-admin-writable" in argv
    owner = 0
    # El guard de plataforma permite que mypy --platform win32 revise el script (no hay getuid).
    if sys.platform != "win32" and "--owner-self" in argv and os.environ.get("SENTRA_ROOT"):
        # Solo para la suite de tests (instalador con SENTRA_ROOT): en un equipo real el
        # propietario exigido es siempre root.
        owner = os.getuid()
    problems = check(owner, allow_admin)
    if problems:
        for path, reason in problems[:20]:
            print(f"unsafe: {path}: {reason}")
        return 1
    print(f"ok {sys.version.split()[0]} {os.path.realpath(sys.executable)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

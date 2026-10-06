"""Parseo y comparación SEGURA de versiones (Fase 5B).

Regla de oro: si dos versiones no se pueden comparar con certeza, el resultado es "no
comparable" (None), nunca una suposición. Un finding con versión no comparable nunca llega a
"confirmed" (ver matcher.py).

Esquemas soportados (los declara cada entrada del catálogo, nunca se adivinan):
- generic: números separados por puntos con un sufijo opcional reconocido ("9.8p1",
  "1.2.3-rc1", "23.01"). Es lo que publica la mayoría del software de Windows;
- semver: Semantic Versioning 2.0 estricto (prerelease incluido, build ignorado);
- windows_build: build de Windows solo numérico ("10.0.19045" o "10.0.19045.4529");
- dpkg: algoritmo de comparación de Debian (epoch, upstream, revision, "~");
- rpm: algoritmo rpmvercmp (epoch, version, release, "~" y "^").

Truncado: "10.0.26100" frente a "10.0.26100.2314" no es comparable (falta el componente que
decide), pero "9.1" frente a "9.1.0" sí (los componentes que faltan son ceros).
"""

import re
from dataclasses import dataclass
from typing import Literal

Scheme = Literal["generic", "semver", "windows_build", "dpkg", "rpm"]
SCHEMES: tuple[Scheme, ...] = ("generic", "semver", "windows_build", "dpkg", "rpm")
MAX_VERSION_LENGTH = 128

_DIGITS = frozenset("0123456789")


class VersionError(ValueError):
    """La cadena no es una versión válida en ese esquema."""


@dataclass(frozen=True)
class ParsedVersion:
    scheme: Scheme
    raw: str
    # Representación ya parseada, propia de cada esquema (tuplas inmutables).
    key: tuple[object, ...]


# --- generic -----------------------------------------------------------------------------------

_GENERIC = re.compile(
    r"^[vV]?(\d{1,9}(?:\.\d{1,9}){0,7})(?:([-.+~_]?)([A-Za-z0-9][A-Za-z0-9.+~_-]{0,40}))?$"
)
# Sufijos reconocidos. Cualquier otro sufijo hace la versión no comparable cuando los números
# coinciden (p. ej. "6.8.0-45-generic" frente a "6.8.0").
_PRE = re.compile(r"^(alpha|beta|preview|pre|rc|dev|a|b)[.-]?(\d{0,9})$", re.IGNORECASE)
_POST = re.compile(r"^(patch|post|pl|p|rev|r)[.-]?(\d{1,9})$", re.IGNORECASE)
_PRE_ORDER = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "preview": 3, "pre": 3, "rc": 4}

# Clases de sufijo: prerelease < sin sufijo < post-release. "unknown" no se compara.
_SUFFIX_PRE, _SUFFIX_NONE, _SUFFIX_POST, _SUFFIX_UNKNOWN = -1, 0, 1, 9


def _parse_generic(raw: str) -> ParsedVersion:
    match = _GENERIC.match(raw)
    if match is None:
        raise VersionError("not a dotted numeric version")
    numbers = tuple(int(part) for part in match.group(1).split("."))
    separator, suffix = match.group(2) or "", match.group(3) or ""
    if not suffix:
        return ParsedVersion("generic", raw, (numbers, _SUFFIX_NONE, 0, 0))
    if separator == "~":
        # "~" es la convención de Debian para "anterior a": 1.0~rc1 < 1.0.
        pre = _PRE.match(suffix)
        rank = _PRE_ORDER.get(pre.group(1).lower(), 0) if pre else 0
        number = int(pre.group(2) or 0) if pre else 0
        return ParsedVersion("generic", raw, (numbers, _SUFFIX_PRE, rank, number))
    pre = _PRE.match(suffix)
    if pre is not None:
        rank = _PRE_ORDER[pre.group(1).lower()]
        return ParsedVersion("generic", raw, (numbers, _SUFFIX_PRE, rank, int(pre.group(2) or 0)))
    post = _POST.match(suffix)
    if post is not None:
        return ParsedVersion("generic", raw, (numbers, _SUFFIX_POST, 0, int(post.group(2))))
    return ParsedVersion("generic", raw, (numbers, _SUFFIX_UNKNOWN, 0, 0))


def _compare_numbers(
    a: tuple[int, ...], b: tuple[int, ...], a_exact: bool = False, b_exact: bool = False
) -> int | None:
    """Compara componentes numéricos; None si decide un componente que falta en uno.

    `exact` marca un límite del catálogo: en un límite los componentes que faltan SÍ son
    ceros ("< 10.0.26200" es "< 10.0.26200.0"). En una versión instalada no: el agente
    pudo no informarlos.
    """
    for x, y in zip(a, b, strict=False):
        if x != y:
            return -1 if x < y else 1
    a_longer = len(a) > len(b)
    extra = a[len(b) :] if a_longer else b[len(a) :]
    if not any(extra):
        return 0
    if not (b_exact if a_longer else a_exact):
        # "10.0.26100" instalada frente a "10.0.26100.2314": el componente que falta decide
        # y no se conoce. Suponer 0 marcaría como vulnerable un equipo quizá parcheado.
        return None
    return 1 if a_longer else -1


def _compare_generic(
    a: ParsedVersion, b: ParsedVersion, a_exact: bool = False, b_exact: bool = False
) -> int | None:
    a_numbers, a_kind, a_rank, a_num = a.key
    b_numbers, b_kind, b_rank, b_num = b.key
    assert isinstance(a_numbers, tuple) and isinstance(b_numbers, tuple)  # noqa: S101
    numbers = _compare_numbers(a_numbers, b_numbers, a_exact, b_exact)
    if numbers is None or numbers != 0:
        return numbers
    if a_kind == _SUFFIX_UNKNOWN or b_kind == _SUFFIX_UNKNOWN:
        # Mismos números con un sufijo no reconocido: no sabemos si es anterior o posterior.
        return 0 if a.raw == b.raw else None
    left = (a_kind, a_rank, a_num)
    right = (b_kind, b_rank, b_num)
    if left == right:
        return 0
    return -1 if left < right else 1


# --- windows_build -------------------------------------------------------------------------------

_WINDOWS_BUILD = re.compile(r"^\d{1,6}(?:\.\d{1,6}){1,3}$")


def _parse_windows_build(raw: str) -> ParsedVersion:
    if not _WINDOWS_BUILD.match(raw):
        raise VersionError("not a numeric Windows build")
    return ParsedVersion("windows_build", raw, tuple(int(p) for p in raw.split(".")))


# --- semver --------------------------------------------------------------------------------------

_SEMVER = re.compile(
    r"^[vV]?(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})\.(0|[1-9]\d{0,8})"
    r"(?:-((?:0|[1-9]\d{0,8}|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d{0,8}|\d*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def _parse_semver(raw: str) -> ParsedVersion:
    match = _SEMVER.match(raw)
    if match is None:
        raise VersionError("not a semantic version")
    core = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    pre = tuple(match.group(4).split(".")) if match.group(4) else ()
    return ParsedVersion("semver", raw, (core, pre))


def _compare_semver(a: ParsedVersion, b: ParsedVersion) -> int:
    a_core, a_pre = a.key
    b_core, b_pre = b.key
    if a_core != b_core:
        return -1 if a_core < b_core else 1  # type: ignore[operator]
    if a_pre == b_pre:
        return 0
    # Una versión con prerelease es anterior a la misma sin él (1.0.0-rc.1 < 1.0.0).
    if not a_pre:
        return 1
    if not b_pre:
        return -1
    assert isinstance(a_pre, tuple) and isinstance(b_pre, tuple)  # noqa: S101
    for x, y in zip(a_pre, b_pre, strict=False):
        if x == y:
            continue
        x_num, y_num = str(x).isdigit(), str(y).isdigit()
        if x_num and y_num:
            return -1 if int(str(x)) < int(str(y)) else 1
        if x_num != y_num:
            # Identificadores numéricos tienen menor precedencia que los alfanuméricos.
            return -1 if x_num else 1
        return -1 if str(x) < str(y) else 1
    return -1 if len(a_pre) < len(b_pre) else 1


# --- dpkg ----------------------------------------------------------------------------------------

_DPKG = re.compile(r"^(?:(\d{1,9}):)?([0-9][A-Za-z0-9.+~:-]*?)(?:-([A-Za-z0-9.+~]+))?$")


def _dpkg_order(char: str | None) -> int:
    # Misma tabla que dpkg (lib/dpkg/version.c): "~" ordena antes que nada, incluso el final.
    if char is None or char in _DIGITS:
        return 0
    if char.isascii() and char.isalpha():
        return ord(char)
    if char == "~":
        return -1
    return ord(char) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and a[i] not in _DIGITS) or (j < len(b) and b[j] not in _DIGITS):
            ac = _dpkg_order(a[i] if i < len(a) else None)
            bc = _dpkg_order(b[j] if j < len(b) else None)
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i] in _DIGITS and j < len(b) and b[j] in _DIGITS:
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i] in _DIGITS:
            return 1
        if j < len(b) and b[j] in _DIGITS:
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def _parse_dpkg(raw: str) -> ParsedVersion:
    match = _DPKG.match(raw)
    if match is None:
        raise VersionError("not a Debian package version")
    epoch = int(match.group(1) or 0)
    return ParsedVersion("dpkg", raw, (epoch, match.group(2), match.group(3) or ""))


def _compare_dpkg(a: ParsedVersion, b: ParsedVersion) -> int:
    a_epoch, a_up, a_rev = a.key
    b_epoch, b_up, b_rev = b.key
    if a_epoch != b_epoch:
        return -1 if a_epoch < b_epoch else 1  # type: ignore[operator]
    result = _verrevcmp(str(a_up), str(b_up))
    if result:
        return result
    return _verrevcmp(str(a_rev), str(b_rev))


# --- rpm -----------------------------------------------------------------------------------------

_RPM = re.compile(r"^(?:(\d{1,9}):)?([A-Za-z0-9._+~^]+)(?:-([A-Za-z0-9._+~^]+))?$")


def _rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0

    def sep(text: str, k: int) -> bool:
        # Separadores: todo lo que no es alfanumérico ASCII, salvo "~" y "^" (con significado).
        if k >= len(text):
            return False
        char = text[k]
        return not (char.isascii() and char.isalnum()) and char not in "~^"

    while i < len(a) or j < len(b):
        while sep(a, i):
            i += 1
        while sep(b, j):
            j += 1
        a_tilde = i < len(a) and a[i] == "~"
        b_tilde = j < len(b) and b[j] == "~"
        if a_tilde or b_tilde:
            if not a_tilde:
                return 1
            if not b_tilde:
                return -1
            i += 1
            j += 1
            continue
        a_caret = i < len(a) and a[i] == "^"
        b_caret = j < len(b) and b[j] == "^"
        if a_caret or b_caret:
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if not a_caret:
                return 1
            if not b_caret:
                return -1
            i += 1
            j += 1
            continue
        if i >= len(a) or j >= len(b):
            break
        start_i, start_j = i, j
        numeric = a[i] in _DIGITS
        if numeric:
            while i < len(a) and a[i] in _DIGITS:
                i += 1
            while j < len(b) and b[j] in _DIGITS:
                j += 1
        else:
            while i < len(a) and a[i].isascii() and a[i].isalpha():
                i += 1
            while j < len(b) and b[j].isascii() and b[j].isalpha():
                j += 1
        seg_a, seg_b = a[start_i:i], b[start_j:j]
        if not seg_b:
            # Un segmento numérico frente a uno alfabético: el numérico es más nuevo.
            return 1 if numeric else -1
        if numeric:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return -1 if len(seg_a) < len(seg_b) else 1
        if seg_a != seg_b:
            return -1 if seg_a < seg_b else 1
    if i >= len(a) and j >= len(b):
        return 0
    return 1 if i < len(a) else -1


def _parse_rpm(raw: str) -> ParsedVersion:
    match = _RPM.match(raw)
    if match is None or not match.group(2)[0].isalnum():
        raise VersionError("not an RPM version")
    epoch = int(match.group(1) or 0)
    return ParsedVersion("rpm", raw, (epoch, match.group(2), match.group(3)))


def _compare_rpm(a: ParsedVersion, b: ParsedVersion) -> int:
    a_epoch, a_ver, a_rel = a.key
    b_epoch, b_ver, b_rel = b.key
    if a_epoch != b_epoch:
        return -1 if a_epoch < b_epoch else 1  # type: ignore[operator]
    result = _rpmvercmp(str(a_ver), str(b_ver))
    if result or a_rel is None or b_rel is None:
        # Como rpm: si un lado no tiene release, solo cuenta la versión.
        return result
    return _rpmvercmp(str(a_rel), str(b_rel))


# --- API pública ---------------------------------------------------------------------------------

_PARSERS = {
    "generic": _parse_generic,
    "semver": _parse_semver,
    "windows_build": _parse_windows_build,
    "dpkg": _parse_dpkg,
    "rpm": _parse_rpm,
}


def parse(raw: str, scheme: Scheme) -> ParsedVersion:
    """Versión parseada o VersionError. Nunca evalúa la cadena: solo expresiones regulares
    acotadas y comparaciones de caracteres."""
    if not isinstance(raw, str):
        raise VersionError("version must be text")
    value = raw.strip()
    if not value or len(value) > MAX_VERSION_LENGTH:
        raise VersionError("empty or too long version")
    parser = _PARSERS.get(scheme)
    if parser is None:
        raise VersionError("unknown version scheme")
    return parser(value)


def compare(
    a: ParsedVersion, b: ParsedVersion, *, a_exact: bool = False, b_exact: bool = False
) -> int | None:
    """-1, 0 o 1; None si no se puede afirmar el orden (nunca se adivina).

    a_exact/b_exact: esa versión es un límite del catálogo (ver _compare_numbers).
    """
    if a.scheme != b.scheme:
        return None
    if a.scheme == "generic":
        return _compare_generic(a, b, a_exact, b_exact)
    if a.scheme == "windows_build":
        return _compare_numbers(a.key, b.key, a_exact, b_exact)  # type: ignore[arg-type]
    if a.scheme == "semver":
        return _compare_semver(a, b)
    if a.scheme == "dpkg":
        return _compare_dpkg(a, b)
    return _compare_rpm(a, b)


# --- Rangos declarativos -------------------------------------------------------------------------

OPERATORS = ("eq", "lt", "lte", "gt", "gte")
_LABEL = {"eq": "=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">="}


def check_range(range_: dict[str, str], scheme: Scheme) -> None:
    """Valida un rango del catálogo. Solo operadores conocidos y como mucho un límite
    inferior y uno superior ("between" = gte + lt). Nunca expresiones arbitrarias."""
    if not isinstance(range_, dict) or not range_:
        raise VersionError("range must be a non-empty object")
    unknown = set(range_) - set(OPERATORS)
    if unknown:
        raise VersionError("unknown range operator")
    if "eq" in range_ and len(range_) > 1:
        raise VersionError("eq cannot be combined with other bounds")
    if {"lt", "lte"} <= set(range_) or {"gt", "gte"} <= set(range_):
        raise VersionError("at most one lower and one upper bound")
    parsed = {op: parse(value, scheme) for op, value in range_.items()}
    lower = parsed.get("gt") or parsed.get("gte")
    upper = parsed.get("lt") or parsed.get("lte")
    if lower is not None and upper is not None:
        order = compare(lower, upper, a_exact=True, b_exact=True)
        if order is None or order > 0:
            raise VersionError("lower bound is greater than upper bound")


def range_label(range_: dict[str, str]) -> str:
    """Texto legible del rango ("< 9.8", ">= 8.5, < 9.8")."""
    ordered = [op for op in ("eq", "gt", "gte", "lt", "lte") if op in range_]
    return ", ".join(f"{_LABEL[op]} {range_[op]}" for op in ordered)


def in_range(installed: ParsedVersion, range_: dict[str, str], scheme: Scheme) -> bool | None:
    """True/False si la versión está o no en el rango; None si no se puede afirmar."""
    unknown = False
    for op, bound_raw in range_.items():
        result = compare(installed, parse(bound_raw, scheme), b_exact=True)
        if result is None:
            unknown = True
            continue
        satisfied = {
            "eq": result == 0,
            "lt": result < 0,
            "lte": result <= 0,
            "gt": result > 0,
            "gte": result >= 0,
        }[op]
        if not satisfied:
            # Un límite incumplido con certeza basta para descartar el rango.
            return False
    return None if unknown else True


def affected(installed: ParsedVersion, ranges: list[dict[str, str]], scheme: Scheme) -> bool | None:
    """Afectada si cae en ALGÚN rango; no afectada solo si se descartan TODOS con certeza."""
    unknown = False
    for range_ in ranges:
        result = in_range(installed, range_, scheme)
        if result is True:
            return True
        if result is None:
            unknown = True
    return None if unknown else False

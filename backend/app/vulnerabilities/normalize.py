"""Normalización conservadora del inventario y del catálogo (Fase 5B).

El objetivo es que "Google Chrome" y "Google Chrome (64-bit)" den la misma clave, sin que
"Chrome" a secas se confunda con nada: Sentra NO hace fuzzy matching. Una variante distinta
("Chrome", "Chromium") solo coincide si el catálogo la declara expresamente en `names`.

Claves de búsqueda (las mismas en el inventario y en vulnerability_affected.match_keys):
- name:<nombre normalizado>       software instalado (DisplayName en Windows)
- pkg:<ecosistema>:<paquete>      paquete de distribución (dpkg -> deb, rpm -> rpm)
- os:windows | os:linux-kernel    sistema operativo del activo

Reglas del nombre: NFKC, minúsculas, sin ®/™/©, sin grupos entre paréntesis que solo
describen arquitectura, bitness, idioma o versión, sin una versión final suelta ("7-Zip
23.01" -> "7-zip") y con espacios colapsados. Nada más: quitar palabras o reordenar
convertiría nombres distintos en el mismo producto.
"""

import re
import unicodedata

MAX_KEY_LENGTH = 200

_SYMBOLS = re.compile(r"[®™©]")
_PAREN = re.compile(r"\s*\(([^()]{0,80})\)")
# Contenido de un paréntesis que no identifica el producto: arquitectura, bitness, idioma,
# "versión x" o una versión suelta.
_NOISE_WORD = (
    r"(?:x64|x86|x86_64|amd64|arm64|aarch64|ia64|64[- ]?bit|32[- ]?bit|bit|"
    r"[a-z]{2}(?:-[a-z]{2,4})?|version\s+[\w.+-]+|v?\d+(?:\.\d+)+[a-z0-9.+-]*)"
)
# Cada token separado por espacio o puntuación: sin separador obligatorio, "(launcher)" se
# leería como cuatro códigos de idioma de dos letras y se borraría.
_PAREN_NOISE = re.compile(rf"^{_NOISE_WORD}(?:[\s,;/]+{_NOISE_WORD})*[\s,;/]*$")
_TRAILING_VERSION = re.compile(r"(?:\s+-)?\s+v?\d+(?:\.\d+)+[a-z0-9.+-]*$")
_SPACES = re.compile(r"\s+")
# Formas jurídicas que no forman parte del nombre de un editor.
_COMPANY_SUFFIXES = frozenset(
    {
        "inc", "incorporated", "llc", "ltd", "limited", "corp", "corporation", "co",
        "company", "gmbh", "ag", "sa", "s.a", "sas", "srl", "bv", "b.v", "oy", "ab",
        "plc", "pty", "kk", "foundation",
    }
)  # fmt: skip
_WORD = re.compile(r"[a-z0-9]+(?:[.+][a-z0-9]+)*")
# Paquetes: nombre técnico tal cual (minúsculas), sin espacios.
_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9.+_:-]{0,127}$")
ECOSYSTEMS = ("deb", "rpm")


def normalize_name(name: str) -> str:
    """Nombre de producto normalizado ("" si no queda nada utilizable)."""
    # Los símbolos se quitan ANTES de NFKC: NFKC convierte "™" en "TM".
    text = unicodedata.normalize("NFKC", _SYMBOLS.sub("", name or "")).lower()
    text = text.replace("_", " ")
    previous = None
    # Varias pasadas: "Notepad++ (64-bit x64) (es-ES)" tiene dos grupos de ruido.
    while previous != text:
        previous = text
        text = _PAREN.sub(
            lambda m: "" if _PAREN_NOISE.match(m.group(1).strip()) else m.group(0), text
        )
    text = _SPACES.sub(" ", text).strip(" -")
    text = _TRAILING_VERSION.sub("", text).strip(" -")
    return text[:MAX_KEY_LENGTH]


def name_key(name: str) -> str | None:
    normalized = normalize_name(name)
    return f"name:{normalized}"[:MAX_KEY_LENGTH] if normalized else None


def package_key(ecosystem: str, package: str) -> str | None:
    value = (package or "").strip().lower()
    if ecosystem not in ECOSYSTEMS or not _PACKAGE.match(value):
        return None
    # dpkg multiarch ("libc6:amd64") identifica el mismo paquete.
    value = value.split(":", 1)[0]
    return f"pkg:{ecosystem}:{value}"


def os_key(family: str) -> str:
    return f"os:{family}"


def publisher_words(value: str | None) -> tuple[str, ...]:
    """Palabras significativas de un editor ("Google LLC" -> ("google",))."""
    if not value:
        return ()
    text = unicodedata.normalize("NFKC", value).lower()
    words = [w for w in _WORD.findall(text) if w not in _COMPANY_SUFFIXES]
    return tuple(words)


def publisher_matches(publisher: str | None, expected: str) -> bool:
    """El editor del inventario coincide con uno declarado por el catálogo.

    Igualdad de palabras significativas, o el nombre declarado como secuencia completa de
    palabras dentro del editor ("Microsoft" en "Microsoft Corporation"). Nunca subcadenas
    sueltas: "Go" no coincide con "Google".
    """
    have = publisher_words(publisher)
    want = publisher_words(expected)
    if not have or not want:
        return False
    if have == want:
        return True
    size = len(want)
    return any(have[i : i + size] == want for i in range(len(have) - size + 1))


# --- Sistema operativo del activo (columnas os_name / os_version del agente) --------------------

# El agente de Windows envía "11 (build 10.0.26200)" (Fase 4F). Si algún día añade la
# revisión de parche (UBR), "build 10.0.26200.6584" también se acepta.
_WINDOWS_BUILD = re.compile(r"build\s+(\d{1,6}\.\d{1,6}\.\d{1,6}(?:\.\d{1,6})?)", re.IGNORECASE)
_KERNEL = re.compile(r"^(\d{1,4}\.\d{1,4}(?:\.\d{1,6})?)(.*)$")


def windows_build(os_version: str | None) -> str | None:
    match = _WINDOWS_BUILD.search(os_version or "")
    return match.group(1) if match else None


def linux_kernel(os_version: str | None) -> tuple[str, bool] | None:
    """(versión del kernel, es de distribución). "6.8.0-45-generic" -> ("6.8.0", True)."""
    match = _KERNEL.match((os_version or "").strip())
    if match is None:
        return None
    return match.group(1), bool(match.group(2).strip())

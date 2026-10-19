"""CPE 2.3 (cadena formateada) para casar registros de NVD con el inventario (Fase 6C.4).

Solo se usa lo que NVD publica en sus `configurations`: `cpe:2.3:part:vendor:product:version:
update:edition:language:sw_edition:target_sw:target_hw:other`. El inventario de los agentes
NO trae CPE (Windows informa DisplayName/Publisher; dpkg/rpm, nombres de paquete), así que un
CPE solo casa con un componente a través de un identificador declarado expresamente (ver
product_map.py) o de la correspondencia determinista build de Windows -> producto NVD. Nunca
se deduce un CPE a partir de un nombre parecido.

Claves de búsqueda: `cpe:<part>:<vendor>:<product>` (en minúsculas y con el escapado de CPE
tal cual, p. ej. `cpe:a:notepad-plus-plus:notepad\\+\\+`). Comparten el índice GIN de
vulnerability_affected.match_keys con las claves name:/pkg:/os: de la Fase 5B.
"""

import re
from dataclasses import dataclass

# Comodines de CPE: ANY ("*") y NA ("-", "no aplica").
ANY = "*"
NA = "-"
PARTS = ("a", "o", "h")
_FIELDS = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)
MAX_CPE_LENGTH = 400
_COMPONENT = re.compile(r"^(?:[^:\s\\]|\\.){1,200}$")


class CpeError(ValueError):
    """La cadena no es un CPE 2.3 formateado válido."""


@dataclass(frozen=True)
class Cpe:
    part: str
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str

    @property
    def key(self) -> str:
        return product_key(self.part, self.vendor, self.product)

    @property
    def base(self) -> str:
        """El CPE del producto sin versión ni calificadores (para mostrar la procedencia)."""
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:*:*:*:*:*:*:*:*"


def _split(text: str) -> list[str]:
    """Separa por ':' sin escapar (el CPE usa '\\:' dentro de un componente)."""
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        raise CpeError("dangling escape in CPE")
    parts.append("".join(current))
    return parts


def parse(value: str) -> Cpe:
    if (
        not isinstance(value, str)
        or len(value) > MAX_CPE_LENGTH
        or not value.startswith("cpe:2.3:")
    ):
        raise CpeError("not a CPE 2.3 formatted string")
    components = _split(value[len("cpe:2.3:") :])
    if len(components) != len(_FIELDS):
        raise CpeError("a CPE 2.3 string has 11 components")
    for component in components:
        if not _COMPONENT.match(component):
            raise CpeError("invalid CPE component")
    data = dict(zip(_FIELDS, (c.lower() for c in components), strict=True))
    if data["part"] not in PARTS:
        raise CpeError("CPE part must be a, o or h")
    if data["vendor"] in (ANY, NA) or data["product"] in (ANY, NA):
        # Sin fabricante y producto concretos no hay identidad que casar.
        raise CpeError("CPE vendor and product must be concrete")
    return Cpe(**data)


def product_key(part: str, vendor: str, product: str) -> str:
    return f"cpe:{part}:{vendor}:{product}".lower()[:200]


def unescape(value: str) -> str:
    """Valor legible de un componente ("notepad\\+\\+" -> "notepad++")."""
    return re.sub(r"\\(.)", r"\1", value)


def is_concrete(value: str) -> bool:
    return value not in (ANY, NA)


# --- Build de Windows -> producto NVD -----------------------------------------------------------

# NVD publica Windows 10/11 y Server con un producto por versión (windows_10_22h2...) y rangos
# sobre la build completa ("versionEndExcluding": "10.0.19045.4780"). La correspondencia build
# -> producto es pública y determinista (no depende de ningún nombre del inventario). Builds
# anteriores a Windows 10 / Server 2016 no se incluyen: NVD las describe con convenciones
# distintas (r2, sp1 en el campo update) que Sentra no puede comparar con certeza.
_WINDOWS_CLIENT = {
    10240: "windows_10_1507",
    10586: "windows_10_1511",
    14393: "windows_10_1607",
    15063: "windows_10_1703",
    16299: "windows_10_1709",
    17134: "windows_10_1803",
    17763: "windows_10_1809",
    18362: "windows_10_1903",
    18363: "windows_10_1909",
    19041: "windows_10_2004",
    19042: "windows_10_20h2",
    19043: "windows_10_21h1",
    19044: "windows_10_21h2",
    19045: "windows_10_22h2",
    22000: "windows_11_21h2",
    22621: "windows_11_22h2",
    22631: "windows_11_23h2",
    26100: "windows_11_24h2",
    26200: "windows_11_25h2",
}
_WINDOWS_SERVER = {
    14393: "windows_server_2016",
    17763: "windows_server_2019",
    20348: "windows_server_2022",
    25398: "windows_server_2022_23h2",
    26100: "windows_server_2025",
}
_BUILD = re.compile(r"^10\.0\.(\d{5})(?:\.\d{1,6})?$")


def windows_products(build: str | None, server: bool) -> tuple[str, ...]:
    """Productos NVD de una build "10.0.NNNNN[.UBR]" (vacío si no se conoce la build)."""
    match = _BUILD.match(build or "")
    if match is None:
        return ()
    table = _WINDOWS_SERVER if server else _WINDOWS_CLIENT
    product = table.get(int(match.group(1)))
    return (product,) if product else ()


# --- Calificadores de plataforma ----------------------------------------------------------------

# target_sw que identifican un sistema operativo: si no es el del activo, el cpeMatch no aplica.
TARGET_SW_PLATFORM = {
    "windows": "windows",
    "linux": "linux",
    "linux_kernel": "linux",
    "macos": "macos",
    "mac_os": "macos",
    "mac_os_x": "macos",
    "macos_x": "macos",
}
# target_hw conocidos (arquitectura). El inventario informa x64/x86/arm64 o amd64/aarch64.
_ARCH = {
    "x64": "x64",
    "x86_64": "x64",
    "amd64": "x64",
    "x86": "x86",
    "i386": "x86",
    "i686": "x86",
    "arm64": "arm64",
    "aarch64": "arm64",
}


def architecture(value: str | None) -> str | None:
    """Arquitectura normalizada (x64, x86, arm64) o None si no se reconoce."""
    if not value:
        return None
    return _ARCH.get(value.strip().lower())

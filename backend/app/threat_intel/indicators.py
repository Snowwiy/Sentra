"""Validación y normalización de indicadores (IOCs). Funciones puras, sin base de datos.

Un IOC es DATO NO CONFIABLE: solo se acepta si encaja exactamente en uno de los tipos
soportados. Nunca se resuelve, visita ni descarga: estas funciones solo trabajan con texto
(ipaddress y el códec IDNA de la stdlib; ninguna consulta DNS).

Normalización (para que el matching exacto sea fiable):
- IPv4/IPv6: forma canónica de `ipaddress` (IPv6 comprimida, sin zona; una IPv6 mapeada
  ::ffff:a.b.c.d pasa a IPv4);
- CIDR: red canónica; demasiado amplia (< /8 en IPv4, < /32 en IPv6) se rechaza porque
  marcaría medio Internet; un /32 o /128 es una IP;
- dominio y hostname: minúsculas, sin punto final, IDNA (punycode). Sin comodines;
- URL: conservadora. Solo se pasa a minúsculas el esquema y el host y se quita el puerto
  por defecto; ruta, query y fragmento se guardan EXACTAMENTE (decodificar %xx o reordenar
  parámetros cambiaría lo que la fuente quiso decir);
- hashes: hexadecimal en minúsculas con la longitud exacta de su algoritmo;
- email: dominio normalizado; la parte local se conserva (puede distinguir mayúsculas).

Los valores "defanged" (hxxp://, ejemplo[.]com) se rechazan en vez de "arreglarlos": la
importación debe traer el valor real que la fuente quiso indicar.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Final, Literal
from urllib.parse import urlsplit, urlunsplit

from app.threat_intel.errors import IntelRecordError

IndicatorType = Literal[
    "ipv4", "ipv6", "cidr", "domain", "hostname", "url", "sha256", "sha1", "md5", "email"
]
INDICATOR_TYPES: Final[tuple[str, ...]] = (
    "ipv4",
    "ipv6",
    "cidr",
    "domain",
    "hostname",
    "url",
    "sha256",
    "sha1",
    "md5",
    "email",
)
CLASSIFICATIONS: Final[tuple[str, ...]] = ("malicious", "suspicious", "benign", "unknown")
CONFIDENCES: Final[tuple[str, ...]] = ("low", "medium", "high")
CONFIDENCE_RANK: Final[dict[str, int]] = {"low": 0, "medium": 1, "high": 2}

# Qué puede casar con la telemetría que Sentra recoge HOY (ver docs/threat-intelligence.md).
# El agente no calcula hashes de ficheros, no hay telemetría DNS ni de URLs ni de correo:
# esos tipos se pueden importar y consultar, pero nunca producen un match (no se finge).
TELEMETRY_SUPPORT: Final[dict[str, str]] = {
    "ipv4": "supported",
    "ipv6": "supported",
    "cidr": "supported",
    # Solo contra el hostname y el DNS inverso de activos conocidos (no hay consultas DNS).
    "domain": "partial",
    "hostname": "partial",
    "url": "unsupported",
    "sha256": "unsupported",
    "sha1": "unsupported",
    "md5": "unsupported",
    "email": "unsupported",
}
SUPPORT_REASONS: Final[dict[str, str]] = {
    "partial": "Solo hostname y DNS inverso de los activos conocidos; Sentra no recoge "
    "consultas DNS.",
    "unsupported": "La telemetría actual de Sentra no contiene este tipo de dato.",
}

MAX_VALUE = 1024
MAX_ORIGINAL = 2048
# Redes más amplias que esto no son un indicador útil: casarían con tráfico legítimo masivo.
MIN_PREFIX = {4: 8, 6: 32}
_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_HEX = re.compile(r"^[0-9a-f]+$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_EMAIL_LOCAL = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$")
_DEFANGED = re.compile(r"\[\.\]|\(\.\)|\[dot\]|^hxxps?://|\[:\]//", re.IGNORECASE)
_PRINTABLE_ASCII = re.compile(r"^[\x21-\x7e]+$")


@dataclass(frozen=True)
class NormalizedIndicator:
    indicator_type: str
    value: str
    original: str
    # Solo cidr: la red en notación canónica (para la columna CIDR y el índice GiST).
    network: str | None = None


def _fail(code: str, message: str) -> IntelRecordError:
    return IntelRecordError(code, message)


def _ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        raise _fail("invalid_indicator", "not a valid IP address") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def _host_labels(value: str, *, single_label: bool) -> str:
    text = value.strip().rstrip(".").lower()
    if not text or "*" in text:
        raise _fail("invalid_indicator", "domain must not be empty or contain wildcards")
    try:
        # Códec IDNA de la stdlib: solo transforma texto (no consulta DNS).
        ascii_name = text.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        raise _fail("invalid_indicator", "domain is not a valid IDNA name") from None
    if len(ascii_name) > 253:
        raise _fail("invalid_indicator", "domain longer than 253 characters")
    labels = ascii_name.split(".")
    if not all(_LABEL.match(label) for label in labels):
        raise _fail("invalid_indicator", "domain has an invalid label")
    if not single_label and len(labels) < 2:
        raise _fail("invalid_indicator", "domain must have at least two labels")
    if labels[-1].isdigit():
        # "1.2.3.4" o "example.123": una IP disfrazada de dominio o un TLD imposible.
        raise _fail("invalid_indicator", "domain must not end in a numeric label")
    return ascii_name


def _url(value: str) -> str:
    text = value.strip()
    if not _PRINTABLE_ASCII.match(text):
        raise _fail("invalid_indicator", "URL must be printable ASCII without spaces")
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise _fail("invalid_indicator", "URL indicators must be http or https")
    if not parts.hostname:
        raise _fail("invalid_indicator", "URL must have a host")
    if parts.username or parts.password:
        raise _fail("invalid_indicator", "URL must not contain credentials")
    host = parts.hostname
    try:
        literal = ipaddress.ip_address(host)
        host_text = f"[{literal.compressed}]" if literal.version == 6 else literal.compressed
    except ValueError:
        host_text = _host_labels(host, single_label=True)
    try:
        port = parts.port
    except ValueError:
        raise _fail("invalid_indicator", "URL has an invalid port") from None
    default = {"http": 80, "https": 443}[scheme]
    netloc = host_text if port in (None, default) else f"{host_text}:{port}"
    # Ruta, query y fragmento tal cual: la semántica de la URL es de la fuente.
    return urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))


def _email(value: str) -> str:
    text = value.strip()
    local, sep, domain = text.rpartition("@")
    if not sep or not _EMAIL_LOCAL.match(local) or local.startswith(".") or ".." in local:
        raise _fail("invalid_indicator", "not a valid email address")
    return f"{local}@{_host_labels(domain, single_label=False)}"


def normalize(indicator_type: str, value: object) -> NormalizedIndicator:
    """Valida y normaliza un indicador. IntelRecordError si no encaja en su tipo."""
    if indicator_type not in INDICATOR_TYPES:
        raise _fail("unsupported_indicator_type", f"unsupported indicator type {indicator_type}")
    if not isinstance(value, str) or not value.strip():
        raise _fail("invalid_indicator", "indicator value must be a non-empty string")
    if "\x00" in value or len(value) > MAX_ORIGINAL:
        raise _fail("invalid_indicator", "indicator value too long or with NUL characters")
    original = value.strip()
    if _DEFANGED.search(original):
        raise _fail("defanged_indicator", "defanged values must be imported in real form")
    kind = indicator_type
    network: str | None = None
    if kind in ("ipv4", "ipv6"):
        address = _ip(original)
        kind = f"ipv{address.version}"
        # Una IPv6 mapeada (::ffff:a.b.c.d) se acepta como IPv4; una IPv4 normal no es ipv6.
        mapped = indicator_type == "ipv6" and kind == "ipv4" and ":" in original
        if indicator_type != kind and not mapped:
            raise _fail("invalid_indicator", f"value is not an {indicator_type} address")
        normalized = address.compressed
    elif kind == "cidr":
        try:
            net = ipaddress.ip_network(original.split("%", 1)[0], strict=False)
        except ValueError:
            raise _fail("invalid_indicator", "not a valid CIDR network") from None
        if net.prefixlen == net.max_prefixlen:
            return normalize(f"ipv{net.version}", str(net.network_address))
        if net.prefixlen < MIN_PREFIX[net.version]:
            raise _fail("indicator_too_broad", "network is too broad to be an indicator")
        normalized = net.compressed
        network = normalized
    elif kind in ("domain", "hostname"):
        normalized = _host_labels(original, single_label=kind == "hostname")
        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            pass
        else:
            raise _fail("invalid_indicator", "IP addresses must use the ipv4/ipv6 types")
    elif kind == "url":
        normalized = _url(original)
    elif kind in _HASH_LENGTHS:
        normalized = original.lower()
        if len(normalized) != _HASH_LENGTHS[kind] or not _HEX.match(normalized):
            raise _fail("invalid_indicator", f"{kind} must be {_HASH_LENGTHS[kind]} hex chars")
    else:  # email
        normalized = _email(original)
    if len(normalized) > MAX_VALUE:
        raise _fail("invalid_indicator", f"normalized value longer than {MAX_VALUE}")
    return NormalizedIndicator(kind, normalized, original[:MAX_ORIGINAL], network)


def confidence_from_score(score: int) -> str:
    """Escala STIX 2.1 (0-100) -> low/medium/high (apéndice "None/Low/Med/High")."""
    if score >= 70:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def lower_confidence(value: str) -> str:
    """Un escalón menos (coincidencias de red o de visibilidad parcial)."""
    return {"high": "medium", "medium": "low"}.get(value, "low")

"""Formato de importación del catálogo local de vulnerabilidades (sentra-vuln-catalog/1).

El fichero es DATO NO CONFIABLE. Defensas, en orden:
1. tamaño máximo en bytes antes de parsear nada;
2. profundidad máxima de anidamiento, medida con un recorrido lineal del texto ANTES de
   json.loads (un JSON muy anidado agotaría la pila del parser);
3. json.loads estricto: sin NaN/Infinity y sin claves duplicadas (ambiguas);
4. estructura y límites con Pydantic (extra="forbid"): número de registros, longitud de
   cada texto, listas acotadas, identificadores con formato, URLs solo http/https;
5. rangos de versión declarativos validados con su esquema (versions.check_range).

Nunca se ejecuta, evalúa ni interpreta nada del contenido: no hay plantillas, expresiones
ni código. Las URLs de referencia son metadatos que Sentra nunca abre.

Errores estructurales (no es JSON, formato desconocido, demasiados registros...) rechazan el
fichero entero. Un registro inválido se rechaza solo, con su índice y un código (sin
devolver el contenido), y la importación exige confirmarlo explícitamente (skip_invalid).
"""

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from app.vulnerabilities import normalize, versions
from app.vulnerabilities.versions import Scheme, VersionError

FORMAT = "sentra-vuln-catalog/1"
MAX_DEPTH = 16
SEVERITIES = ("informational", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

# Sinónimos de severidad de las fuentes habituales (NVD, Microsoft, Red Hat, GHSA).
_SEVERITY_ALIASES = {
    "none": "informational",
    "info": "informational",
    "informational": "informational",
    "low": "low",
    "moderate": "medium",
    "medium": "medium",
    "important": "high",
    "high": "high",
    "critical": "critical",
}

_SOURCE_KEY = r"^[a-z0-9][a-z0-9._-]{1,63}$"
_EXTERNAL_ID = re.compile(r"^[A-Za-z][A-Za-z0-9]{1,15}-[A-Za-z0-9][A-Za-z0-9._:-]{1,60}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_CWE = re.compile(r"^(?:CWE-\d{1,6}|NVD-CWE-Other|NVD-CWE-noinfo)$")
_CVSS_SEGMENT = re.compile(r"^[A-Za-z]{1,3}:[A-Za-z0-9]{1,3}$")
# CPE 2.3 "formatted string" (13 campos) o URI 2.2. Solo se guarda: no se usa para casar.
_CPE23 = re.compile(r"^cpe:2\.3:[aho*\-](?::(?:[^:\s\\]|\\.){1,200}){10}$")
_CPE22 = re.compile(r"^cpe:/[aho](?::[^:\s]{0,200}){1,6}$")
_PURL = re.compile(r"^pkg:[a-z][a-z0-9.+-]{0,30}/[^\s]{1,250}$")
_META_KEY = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
# Caracteres de control (salvo salto de línea y tabulador) fuera de los textos.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

ID_TYPES = (
    ("CVE", "cve"),
    ("GHSA", "ghsa"),
    ("RHSA", "rhsa"),
    ("RHBA", "rhsa"),
    ("RHEA", "rhsa"),
    ("USN", "usn"),
    ("DSA", "vendor"),
    ("MSRC", "msrc"),
    ("ADV", "msrc"),
    ("OSV", "osv"),
    ("PYSEC", "osv"),
    ("RUSTSEC", "osv"),
    ("GO", "osv"),
)


class CatalogFormatError(ValueError):
    """Error estructural: el fichero entero se rechaza."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class CatalogLimits:
    max_bytes: int
    max_records: int
    max_depth: int = MAX_DEPTH


def _clean_text(value: str, limit: int, *, multiline: bool = False) -> str:
    if "\x00" in value:
        raise ValueError("text must not contain NUL characters")
    text = unicodedata.normalize("NFC", value)
    text = _CONTROL.sub("", text)
    if not multiline:
        text = " ".join(text.split())
    text = text.strip()
    if len(text) > limit:
        raise ValueError(f"text longer than {limit} characters")
    return text


def _external_id(value: str) -> str:
    value = value.strip()
    if not _EXTERNAL_ID.match(value) or len(value) > 64:
        raise ValueError("invalid vulnerability identifier")
    if value.upper().startswith("CVE-"):
        value = value.upper()
        if not _CVE.match(value):
            raise ValueError("invalid CVE identifier")
    return value


def id_type(external_id: str) -> str:
    prefix = external_id.split("-", 1)[0].upper()
    for name, kind in ID_TYPES:
        if prefix == name:
            return kind
    return "vendor"


def safe_reference(url: str) -> str:
    """URL de referencia validada: solo http/https, con host, sin credenciales ni espacios.

    javascript:, data:, file:, vbscript: y cualquier otro esquema se rechazan aquí y la UI
    vuelve a comprobarlo antes de pintar un enlace (defensa en profundidad).
    """
    if not isinstance(url, str) or len(url) > 2048 or _CONTROL.search(url) or " " in url:
        raise ValueError("invalid reference URL")
    parts = urlsplit(url.strip())
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError("reference URL must be http or https")
    if parts.username or parts.password:
        raise ValueError("reference URL must not contain credentials")
    return url.strip()


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CvssIn(_Strict):
    version: Literal["2.0", "3.0", "3.1", "4.0"]
    score: float | None = Field(default=None, ge=0, le=10, allow_inf_nan=False)
    vector: str | None = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def _check(self) -> "CvssIn":
        if self.score is None and self.vector is None:
            raise ValueError("cvss needs a score or a vector")
        if self.vector is not None:
            vector = self.vector
            if self.version == "2.0":
                if vector.startswith("CVSS:"):
                    raise ValueError("CVSS v2 vectors have no CVSS: prefix")
                body = vector
            else:
                prefix = f"CVSS:{self.version}/"
                # Un vector 3.1 declarado como 4.0 (o al revés) se rechaza: interpretar un
                # vector con la versión equivocada daría métricas falsas.
                if not vector.startswith(prefix):
                    raise ValueError("CVSS vector does not match its declared version")
                body = vector[len(prefix) :]
            segments = body.split("/")
            if not 1 <= len(segments) <= 40 or not all(_CVSS_SEGMENT.match(s) for s in segments):
                raise ValueError("malformed CVSS vector")
        return self


class PackageIn(_Strict):
    ecosystem: Literal["deb", "rpm"]
    name: str = Field(min_length=1, max_length=128)

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        if normalize.package_key("deb", value) is None:
            raise ValueError("invalid package name")
        return value.lower()


_DEFAULT_SCHEME: dict[str, Scheme] = {
    "deb": "dpkg",
    "rpm": "rpm",
    "windows": "windows_build",
    "linux-kernel": "generic",
}


class AffectedIn(_Strict):
    type: Literal["application", "os", "package"] = "application"
    product: str = Field(min_length=1, max_length=128)
    vendor: str | None = Field(default=None, max_length=128)
    # Nombres EXACTOS (se normalizan con normalize.normalize_name) bajo los que el
    # inventario muestra el producto. Es el único "alias": Sentra no deduce variantes.
    names: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        default_factory=list, max_length=20
    )
    publishers: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        default_factory=list, max_length=20
    )
    packages: list[PackageIn] = Field(default_factory=list, max_length=20)
    os: Literal["windows", "linux-kernel"] | None = None
    version_scheme: Literal["generic", "semver", "windows_build", "dpkg", "rpm"] | None = None
    ranges: list[dict[str, Annotated[str, Field(min_length=1, max_length=128)]]] = Field(
        min_length=1, max_length=20
    )
    fixed_version: str | None = Field(default=None, max_length=128)
    service_ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(
        default_factory=list, max_length=10
    )
    platforms: list[Literal["windows", "linux"]] = Field(default_factory=list, max_length=2)
    cpe: list[Annotated[str, Field(max_length=400)]] = Field(default_factory=list, max_length=20)
    purl: list[Annotated[str, Field(max_length=300)]] = Field(default_factory=list, max_length=20)

    @field_validator("product", "vendor")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return _clean_text(value, 128) if value is not None else None

    @field_validator("names", "publishers")
    @classmethod
    def _clean_list(cls, values: list[str]) -> list[str]:
        return [_clean_text(v, 200) for v in values]

    @field_validator("cpe")
    @classmethod
    def _check_cpe(cls, values: list[str]) -> list[str]:
        for value in values:
            if not (_CPE23.match(value) or _CPE22.match(value)):
                raise ValueError("invalid CPE")
        return values

    @field_validator("purl")
    @classmethod
    def _check_purl(cls, values: list[str]) -> list[str]:
        for value in values:
            if not _PURL.match(value):
                raise ValueError("invalid purl")
        return values

    @model_validator(mode="after")
    def _check(self) -> "AffectedIn":
        if self.type == "os" and self.os is None:
            raise ValueError("os entries need 'os' (windows or linux-kernel)")
        if self.type != "os" and self.os is not None:
            raise ValueError("'os' is only valid for type os")
        if self.type == "package":
            if not self.packages:
                raise ValueError("package entries need 'packages'")
            if len({p.ecosystem for p in self.packages}) > 1:
                # dpkg y rpm comparan versiones de forma distinta: una entrada, un esquema.
                raise ValueError("all packages of an entry must share one ecosystem")
        elif self.packages:
            raise ValueError("'packages' is only valid for type package")
        if self.type == "application" and not (self.names or self.product):
            raise ValueError("application entries need names")
        scheme = self.scheme
        try:
            for range_ in self.ranges:
                versions.check_range(range_, scheme)
            if self.fixed_version is not None:
                versions.parse(self.fixed_version, scheme)
        except VersionError as exc:
            raise ValueError(f"invalid version range: {exc}") from None
        return self

    @property
    def scheme(self) -> Scheme:
        if self.version_scheme is not None:
            return self.version_scheme
        if self.type == "package":
            return _DEFAULT_SCHEME[self.packages[0].ecosystem]
        if self.type == "os" and self.os is not None:
            return _DEFAULT_SCHEME[self.os]
        return "generic"

    def match_keys(self) -> list[str]:
        keys: list[str] = []
        if self.type == "os" and self.os is not None:
            keys.append(normalize.os_key(self.os))
        elif self.type == "package":
            for package in self.packages:
                key = normalize.package_key(package.ecosystem, package.name)
                if key:
                    keys.append(key)
        else:
            # Con nombres explícitos solo esos; sin ellos, el nombre canónico del producto.
            for name in self.names or [self.product]:
                key = normalize.name_key(name)
                if key:
                    keys.append(key)
        return sorted(set(keys))


class VulnerabilityIn(_Strict):
    id: str
    aliases: list[str] = Field(default_factory=list, max_length=20)
    title: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=10_000)
    severity: str | None = Field(default=None, max_length=32)
    cvss: CvssIn | None = None
    published_at: AwareDatetime | None = None
    modified_at: AwareDatetime | None = None
    references: list[str] = Field(default_factory=list, max_length=50)
    cwe: list[str] = Field(default_factory=list, max_length=20)
    remediation: str | None = Field(default=None, max_length=4000)
    affected: list[AffectedIn] = Field(min_length=1, max_length=50)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id")
    @classmethod
    def _check_id(cls, value: str) -> str:
        return _external_id(value)

    @field_validator("aliases")
    @classmethod
    def _check_aliases(cls, values: list[str]) -> list[str]:
        return sorted({_external_id(v) for v in values})

    @field_validator("title")
    @classmethod
    def _check_title(cls, value: str) -> str:
        text = _clean_text(value, 300)
        if not text:
            raise ValueError("title is empty")
        return text

    @field_validator("description", "remediation")
    @classmethod
    def _check_long_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _clean_text(value, 10_000, multiline=True) or None

    @field_validator("references")
    @classmethod
    def _check_references(cls, values: list[str]) -> list[str]:
        return [safe_reference(v) for v in values]

    @field_validator("cwe")
    @classmethod
    def _check_cwe(cls, values: list[str]) -> list[str]:
        for value in values:
            if not _CWE.match(value):
                raise ValueError("invalid CWE identifier")
        return values

    @field_validator("metadata")
    @classmethod
    def _check_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        # Extensible pero acotado: claves simples y valores escalares o listas cortas de
        # escalares. Aquí podrán viajar en el futuro datos como EPSS/KEV (Fase 5C).
        if len(value) > 20:
            raise ValueError("metadata has too many keys")
        clean: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not _META_KEY.match(key):
                raise ValueError("invalid metadata key")
            clean[key] = _scalar_or_list(item)
        return clean

    @model_validator(mode="after")
    def _check(self) -> "VulnerabilityIn":
        if self.severity is not None and self.severity.strip().lower() not in _SEVERITY_ALIASES:
            raise ValueError("unknown severity")
        if self.severity is None and (self.cvss is None or self.cvss.score is None):
            # Sin severidad ni puntuación no se inventa una: el registro se rechaza.
            raise ValueError("severity or cvss.score is required")
        return self

    def normalized_severity(self) -> str:
        if self.severity is not None:
            return _SEVERITY_ALIASES[self.severity.strip().lower()]
        assert self.cvss is not None and self.cvss.score is not None  # noqa: S101
        return severity_from_score(self.cvss.score, self.cvss.version)


def _scalar_or_list(value: Any) -> Any:
    if isinstance(value, list):
        if len(value) > 20:
            raise ValueError("metadata list too long")
        return [_scalar(v) for v in value]
    return _scalar(value)


def _scalar(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("metadata number must be finite")
        return value
    if isinstance(value, str):
        return _clean_text(value, 200)
    raise ValueError("metadata values must be scalars or lists of scalars")


def severity_from_score(score: float, version: str) -> str:
    """Escala cualitativa ESTÁNDAR de la propia especificación CVSS (no un cálculo propio)."""
    if version == "2.0":
        if score < 4.0:
            return "low"
        return "medium" if score < 7.0 else "high"
    if score == 0:
        return "informational"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    return "high" if score < 9.0 else "critical"


class SourceIn(_Strict):
    id: str = Field(pattern=_SOURCE_KEY)
    name: str = Field(min_length=1, max_length=200)
    version: str | None = Field(default=None, max_length=64)
    generated_at: AwareDatetime | None = None

    @field_validator("name", "version")
    @classmethod
    def _clean(cls, value: str | None) -> str | None:
        return _clean_text(value, 200) if value is not None else None


@dataclass(frozen=True)
class InvalidRecord:
    index: int
    external_id: str | None
    code: str
    # Mensaje de validación (de Sentra, nunca el valor recibido).
    message: str


@dataclass(frozen=True)
class ValidRecord:
    index: int
    record: VulnerabilityIn
    severity: str
    content_hash: str

    @property
    def external_id(self) -> str:
        return self.record.id


@dataclass
class ParsedCatalog:
    source: SourceIn
    records: list[ValidRecord]
    invalid: list[InvalidRecord]
    sha256: str
    size_bytes: int
    total: int = 0
    warnings: list[str] = field(default_factory=list)


def check_depth(text: str, limit: int) -> None:
    """Profundidad de anidamiento de un JSON sin parsearlo (recorrido lineal del texto)."""
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > limit:
                raise CatalogFormatError("catalog_too_deep", f"JSON nesting deeper than {limit}")
        elif char in "]}":
            depth -= 1


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CatalogFormatError("catalog_duplicate_key", "Duplicate JSON key in catalog")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise CatalogFormatError("catalog_invalid_json", f"Non-finite number {name} is not allowed")


def _error_message(exc: ValidationError) -> tuple[str, str]:
    first = exc.errors()[0]
    location = ".".join(str(part) for part in first.get("loc", ()))
    message = str(first.get("msg", "invalid value"))
    code = "invalid_reference" if "reference URL" in message else "invalid_record"
    if "version range" in message or "version" in location:
        code = "invalid_version_range"
    return code, f"{location}: {message}"[:300] if location else message[:300]


def parse_catalog(raw: bytes, limits: CatalogLimits) -> ParsedCatalog:
    """Valida un catálogo completo. Errores estructurales -> CatalogFormatError."""
    if len(raw) > limits.max_bytes:
        raise CatalogFormatError("catalog_too_large", f"Catalog exceeds {limits.max_bytes} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CatalogFormatError("catalog_invalid_json", "Catalog must be UTF-8 JSON") from None
    check_depth(text, limits.max_depth)
    try:
        document = json.loads(
            text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant
        )
    except CatalogFormatError:
        raise
    except (ValueError, RecursionError):
        raise CatalogFormatError("catalog_invalid_json", "Catalog is not valid JSON") from None
    if not isinstance(document, dict):
        raise CatalogFormatError("catalog_invalid_format", "Catalog must be a JSON object")
    if document.get("format") != FORMAT:
        raise CatalogFormatError(
            "catalog_invalid_format", f"Unsupported catalog format (expected {FORMAT})"
        )
    unknown = set(document) - {"format", "source", "vulnerabilities"}
    if unknown:
        raise CatalogFormatError("catalog_invalid_format", "Unknown top-level keys in catalog")
    try:
        source = SourceIn.model_validate(document.get("source"))
    except ValidationError:
        raise CatalogFormatError("catalog_invalid_source", "Invalid catalog source") from None
    items = document.get("vulnerabilities")
    if not isinstance(items, list):
        raise CatalogFormatError("catalog_invalid_format", "'vulnerabilities' must be a list")
    if len(items) > limits.max_records:
        raise CatalogFormatError(
            "catalog_too_many_records", f"Catalog has more than {limits.max_records} records"
        )
    records: list[ValidRecord] = []
    invalid: list[InvalidRecord] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        raw_id = item.get("id") if isinstance(item, dict) else None
        shown_id = raw_id if isinstance(raw_id, str) and _EXTERNAL_ID.match(raw_id) else None
        try:
            record = VulnerabilityIn.model_validate(item)
        except ValidationError as exc:
            code, message = _error_message(exc)
            invalid.append(InvalidRecord(index, shown_id, code, message))
            continue
        except (ValueError, TypeError):
            invalid.append(InvalidRecord(index, shown_id, "invalid_record", "invalid record"))
            continue
        if record.id in seen:
            # Mismo source + external_id dos veces en un fichero: ambiguo, no se elige uno.
            invalid.append(
                InvalidRecord(index, record.id, "duplicate_id", "duplicate id in this file")
            )
            continue
        seen.add(record.id)
        records.append(
            ValidRecord(index, record, record.normalized_severity(), content_hash(record))
        )
    return ParsedCatalog(
        source=source,
        records=records,
        invalid=invalid,
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        total=len(items),
    )


def content_hash(record: VulnerabilityIn) -> str:
    """Huella estable del contenido funcional de un registro (orden de claves fijo)."""
    payload = record.model_dump(mode="json")
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def now_utc() -> datetime:
    return datetime.now(UTC)

"""VulnerabilityMatcher: inventario normalizado de un activo + entrada del catálogo -> resultado.

Lógica pura (sin base de datos ni reloj): se prueba sin PostgreSQL y explica cada decisión.

Estados técnicos (match_state), de más a menos evidencia:
- confirmed: identidad fuerte (nombre exacto declarado + editor coincidente, o SO con build
  comparable) y versión comparable DENTRO de un rango afectado;
- probable: versión en rango, pero la identidad tiene una debilidad conocida (el inventario no
  informa el editor, el catálogo no declara editor, paquete de distribución sin saber la
  versión de la distribución, kernel sin configuración conocida);
- potential: hay producto y alguna señal, pero no se puede afirmar (versión no comparable con
  algún límite, versión upstream sobre un paquete de distribución con posibles backports);
- unknown: el producto está, pero sin versión o con una versión que no se puede parsear;
- not_affected: la versión queda fuera de todos los rangos con certeza.

Lo que NUNCA cuenta como evidencia: un puerto abierto, un banner, un nombre parecido. Sin
coincidencia exacta de clave no hay candidato; un editor distinto del declarado descarta la
instancia (otro producto con el mismo nombre).
"""

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, cast

from app.vulnerabilities import normalize, versions
from app.vulnerabilities.versions import Scheme, VersionError

MatchState = Literal["confirmed", "probable", "potential", "unknown", "not_affected"]
Confidence = Literal["high", "medium", "low"]
Platform = Literal["windows", "linux"]
SoftwareSource = Literal["windows_registry", "dpkg", "rpm"]

MATCH_STATES: tuple[MatchState, ...] = (
    "confirmed",
    "probable",
    "potential",
    "unknown",
    "not_affected",
)
# Estados que mantienen un finding activo (not_affected lo resuelve).
ACTIVE_MATCH_STATES = frozenset({"confirmed", "probable", "potential", "unknown"})
STATE_RANK: Mapping[str, int] = {
    "not_affected": 0,
    "unknown": 1,
    "potential": 2,
    "probable": 3,
    "confirmed": 4,
}
STATE_CONFIDENCE: Mapping[str, Confidence] = {
    "confirmed": "high",
    "probable": "medium",
    "potential": "low",
    "unknown": "low",
    "not_affected": "high",
}
STATE_LABELS: Mapping[str, str] = {
    "confirmed": "confirmada",
    "probable": "probable",
    "potential": "potencial",
    "unknown": "evidencia insuficiente",
    "not_affected": "no afectado",
}
SOFTWARE_SOURCES: tuple[SoftwareSource, ...] = ("windows_registry", "dpkg", "rpm")
_ECOSYSTEM: Mapping[str, str] = {"dpkg": "deb", "rpm": "rpm"}

# Cotas defensivas: instancias por componente guardadas como evidencia y componentes por
# activo (el esquema del inventario ya limita el software a 5000 elementos).
MAX_INSTANCES = 20
MAX_COMPONENTS = 12_000
# El agente recorta la lista de software a este tamaño: si llega exactamente así de larga,
# puede faltar software y la captura no se trata como completa.
SOFTWARE_LIST_LIMIT = 5000


# --- Inventario normalizado --------------------------------------------------------------------


@dataclass(frozen=True)
class Instance:
    """Una entrada del inventario tal como la reportó el agente (texto no confiable)."""

    name: str
    version: str | None
    publisher: str | None = None
    architecture: str | None = None


@dataclass(frozen=True)
class Component:
    """Un producto del activo identificado por una clave normalizada.

    Varias entradas con la misma clave (Python 3.11 y 3.12, x64 y x86) son instancias del
    mismo componente: el finding es uno y su evidencia dice qué instancia está afectada.
    """

    key: str
    type: Literal["application", "package", "os"]
    name: str
    vendor: str | None
    instances: tuple[Instance, ...]
    # agent_inventory (lista de software) o agent_host (SO que informa el agente).
    source: str
    # Solo kernel Linux: versión de distribución ("6.8.0-45-generic"), con backports.
    distro_kernel: bool = False


@dataclass(frozen=True)
class AssetSoftware:
    """Entradas de la evaluación de un activo, derivadas del inventario existente.

    No es un segundo inventario: se construye en memoria desde asset_inventories y el SO del
    activo en cada evaluación; solo su huella y sus claves se guardan.
    """

    platform: Platform | None
    software_source: SoftwareSource | None
    # El agente declaró la sección de software completa (True), incompleta (False) o no lo
    # dice (None, agentes anteriores a 5B).
    complete: bool | None
    collected_at: datetime | None
    components: Mapping[str, Component] = field(default_factory=dict)

    @property
    def keys(self) -> list[str]:
        return sorted(self.components)

    def fingerprint(self) -> str:
        """Huella de lo que decide la evaluación (claves, versiones, editores, SO)."""
        payload = [
            [
                key,
                component.type,
                component.distro_kernel,
                sorted(
                    [i.name, i.version or "", i.publisher or "", i.architecture or ""]
                    for i in component.instances
                ),
            ]
            for key, component in sorted(self.components.items())
        ]
        payload.append([self.platform or "", self.software_source or "", str(self.complete)])
        return hashlib.sha256(
            json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()


def platform_of(os_name: str | None) -> Platform | None:
    name = (os_name or "").strip().lower()
    if name.startswith("windows"):
        return "windows"
    if name.startswith("linux"):
        return "linux"
    return None


def _text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text[:limit] if text else None


def build_asset_software(
    *,
    os_name: str | None,
    os_version: str | None,
    inventory: Mapping[str, Any] | None,
    collected_at: datetime | None,
) -> AssetSoftware:
    """Normaliza el inventario del agente (software + SO) en componentes con clave."""
    platform = platform_of(os_name)
    data = inventory or {}
    raw_source = data.get("software_source")
    software_source: SoftwareSource | None = (
        cast(SoftwareSource, raw_source) if raw_source in SOFTWARE_SOURCES else None
    )
    if software_source is None and platform == "windows" and inventory is not None:
        # En Windows la única fuente del agente es el registro (Uninstall).
        software_source = "windows_registry"
    software = data.get("software")
    items = software if isinstance(software, list) else []
    complete: bool | None = None
    incomplete = data.get("incomplete_sections")
    if isinstance(incomplete, list):
        complete = "software" not in incomplete
    if len(items) >= SOFTWARE_LIST_LIMIT:
        complete = False

    grouped: dict[str, tuple[str, str | None, list[Instance]]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = _text(item.get("name"), 512)
        if name is None:
            continue
        instance = Instance(
            name=name,
            version=_text(item.get("version"), 128),
            publisher=_text(item.get("publisher"), 512),
            architecture=_text(item.get("architecture"), 16),
        )
        keys: list[tuple[str, str]] = []
        name_key = normalize.name_key(name)
        if name_key:
            keys.append((name_key, "application"))
        ecosystem = _ECOSYSTEM.get(software_source or "")
        if ecosystem is not None:
            package_key = normalize.package_key(ecosystem, name)
            if package_key:
                keys.append((package_key, "package"))
        for key, kind in keys:
            entry = grouped.setdefault(key, (kind, instance.publisher, []))
            if len(entry[2]) < MAX_INSTANCES and instance not in entry[2]:
                entry[2].append(instance)
        if len(grouped) >= MAX_COMPONENTS:
            break

    components: dict[str, Component] = {}
    for key, (kind, vendor, instances) in grouped.items():
        instances.sort(key=lambda i: (i.version or "", i.architecture or "", i.name))
        components[key] = Component(
            key=key,
            type=cast(Literal["application", "package", "os"], kind),
            name=instances[0].name,
            vendor=vendor,
            instances=tuple(instances),
            source="agent_inventory",
        )

    os_component = _os_component(platform, os_name, os_version)
    if os_component is not None:
        components[os_component.key] = os_component
    return AssetSoftware(
        platform=platform,
        software_source=software_source,
        complete=complete,
        collected_at=collected_at,
        components=components,
    )


def _os_component(
    platform: Platform | None, os_name: str | None, os_version: str | None
) -> Component | None:
    display = " ".join(p for p in ((os_name or "").strip(), (os_version or "").strip()) if p)
    if platform == "windows":
        return Component(
            key=normalize.os_key("windows"),
            type="os",
            name=display[:512] or "Windows",
            vendor="Microsoft",
            instances=(Instance(name="Windows", version=normalize.windows_build(os_version)),),
            source="agent_host",
        )
    if platform == "linux":
        kernel = normalize.linux_kernel(os_version)
        return Component(
            key=normalize.os_key("linux-kernel"),
            type="os",
            name=display[:512] or "Linux",
            vendor=None,
            instances=(Instance(name="Linux kernel", version=kernel[0] if kernel else None),),
            source="agent_host",
            distro_kernel=kernel[1] if kernel else False,
        )
    return None


# --- Entradas del catálogo ---------------------------------------------------------------------


@dataclass(frozen=True)
class AffectedRule:
    """Una entrada de vulnerability_affected ya validada en la importación."""

    type: str
    product: str
    vendor: str | None
    names_declared: bool
    publishers: tuple[str, ...]
    ecosystem: str | None
    os: str | None
    scheme: Scheme
    ranges: tuple[Mapping[str, str], ...]
    fixed_version: str | None
    service_ports: tuple[int, ...]
    platforms: tuple[str, ...]

    @classmethod
    def from_definition(cls, definition: Mapping[str, Any]) -> "AffectedRule":
        packages = definition.get("packages") or []
        ecosystem = packages[0].get("ecosystem") if packages else None
        return cls(
            type=str(definition.get("type", "application")),
            product=str(definition.get("product", "")),
            vendor=definition.get("vendor"),
            names_declared=bool(definition.get("names")),
            publishers=tuple(definition.get("publishers") or ()),
            ecosystem=ecosystem,
            os=definition.get("os"),
            scheme=cast(Scheme, definition.get("scheme") or "generic"),
            ranges=tuple(definition.get("ranges") or ()),
            fixed_version=definition.get("fixed_version"),
            service_ports=tuple(int(p) for p in definition.get("service_ports") or ()),
            platforms=tuple(definition.get("platforms") or ()),
        )

    def range_label(self) -> str:
        return " | ".join(versions.range_label(dict(r)) for r in self.ranges)[:255]


# --- Resultado ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class InstanceResult:
    instance: Instance
    # affected | not_affected | not_comparable | no_version | unparseable
    version_result: str
    state: MatchState
    # Debilidades de identidad que limitan el estado (códigos estables, ver _CAPS).
    limits: tuple[str, ...]


@dataclass(frozen=True)
class MatchResult:
    state: MatchState
    confidence: Confidence
    rationale: str
    component: Component
    rule: AffectedRule
    # Instancia que decide el estado (la de peor estado).
    instance: Instance
    instances: tuple[InstanceResult, ...]
    checks: tuple[dict[str, str], ...]

    @property
    def installed_version(self) -> str | None:
        return self.instance.version

    @property
    def active(self) -> bool:
        return self.state in ACTIVE_MATCH_STATES

    def evidence(self, collected_at: datetime | None) -> dict[str, Any]:
        """Evidencia guardada en el finding: qué se comparó y con qué resultado.

        Solo el componente afectado (nunca el inventario completo) y textos acotados.
        """
        return {
            "source": self.component.source,
            "kind": "reported",
            "collected_at": collected_at.isoformat() if collected_at else None,
            "component": {
                "key": self.component.key,
                "type": self.component.type,
                "name": self.instance.name,
                "version": self.instance.version,
                "publisher": self.instance.publisher,
                "architecture": self.instance.architecture,
            },
            "instances": [
                {
                    "name": r.instance.name,
                    "version": r.instance.version,
                    "architecture": r.instance.architecture,
                    "result": r.version_result,
                }
                for r in self.instances
            ],
            "rule": {
                "type": self.rule.type,
                "product": self.rule.product,
                "vendor": self.rule.vendor,
                "version_scheme": self.rule.scheme,
                "affected": self.rule.range_label(),
                "fixed_version": self.rule.fixed_version,
            },
            "checks": list(self.checks),
        }


# Debilidades de identidad y el estado máximo que permiten.
_CAPS: Mapping[str, MatchState] = {
    # El catálogo declara editor y el inventario no lo informa.
    "publisher_unreported": "probable",
    # El catálogo no declara editor: coincidencia solo por nombre exacto.
    "name_only": "probable",
    # Paquete de distribución: no sabemos qué versión de la distribución es (el agente solo
    # informa el kernel), así que el rango podría ser de otra distribución.
    "distro_release_unknown": "probable",
    # Kernel sin parche de distribución: versión exacta, pero se desconoce su configuración.
    "kernel_config_unknown": "probable",
    # Versión upstream aplicada a un paquete de distribución: los backports la invalidan.
    "distro_backports": "potential",
}

_LIMIT_TEXT: Mapping[str, str] = {
    "publisher_unreported": "el inventario no informa el editor",
    "name_only": "coincidencia por nombre exacto sin editor declarado en el catálogo",
    "distro_release_unknown": (
        "paquete de distribución; el agente no informa la versión de la distribución"
    ),
    "kernel_config_unknown": "kernel exacto, pero se desconoce su configuración",
    "distro_backports": (
        "versión upstream sobre un paquete o kernel de distribución; la distribución puede "
        "haber aplicado el parche (backport)"
    ),
}


def _cap(state: MatchState, limits: Iterable[str]) -> MatchState:
    for limit in limits:
        ceiling = _CAPS[limit]
        if STATE_RANK[state] > STATE_RANK[ceiling]:
            state = ceiling
    return state


class VulnerabilityMatcher:
    """Compara un componente del activo con una entrada del catálogo.

    match() devuelve None cuando no hay candidato (otra plataforma, otro editor, tipo de
    entrada que no corresponde); en otro caso, el estado con su explicación.
    """

    def match(
        self, component: Component, rule: AffectedRule, asset: AssetSoftware
    ) -> MatchResult | None:
        identity = self._identity(component, rule, asset)
        if identity is None:
            return None
        base_limits, publisher_check = identity
        results: list[InstanceResult] = []
        for instance in component.instances:
            limits = list(base_limits)
            if rule.publishers:
                if instance.publisher is None:
                    limits.append("publisher_unreported")
                elif not any(
                    normalize.publisher_matches(instance.publisher, p) for p in rule.publishers
                ):
                    # Mismo nombre, otro editor: otro producto. No es candidato.
                    continue
            results.append(self._version(instance, rule, tuple(limits)))
        if not results:
            return None
        decisive = max(results, key=lambda r: (STATE_RANK[r.state], r.instance.version or ""))
        checks = self._checks(component, rule, decisive, publisher_check)
        return MatchResult(
            state=decisive.state,
            confidence=STATE_CONFIDENCE[decisive.state],
            rationale=self._rationale(component, rule, decisive),
            component=component,
            rule=rule,
            instance=decisive.instance,
            instances=tuple(results),
            checks=checks,
        )

    def _identity(
        self, component: Component, rule: AffectedRule, asset: AssetSoftware
    ) -> tuple[tuple[str, ...], str] | None:
        if rule.platforms and asset.platform not in rule.platforms:
            return None
        if rule.type == "os":
            if component.type != "os":
                return None
            if rule.os == "linux-kernel":
                limit = "distro_backports" if component.distro_kernel else "kernel_config_unknown"
                return (limit,), "not_applicable"
            return (), "not_applicable"
        if rule.type == "package":
            if component.type != "package":
                return None
            return ("distro_release_unknown",), "not_applicable"
        # Aplicación: solo componentes de software (nunca el SO).
        if component.type != "application":
            return None
        limits: list[str] = []
        if asset.platform == "linux":
            # En Linux el software son paquetes de distribución: el número upstream no basta.
            limits.append("distro_backports")
        if not rule.publishers:
            limits.append("name_only")
            return tuple(limits), "not_declared"
        return tuple(limits), "declared"

    def _version(
        self, instance: Instance, rule: AffectedRule, limits: tuple[str, ...]
    ) -> InstanceResult:
        if instance.version is None:
            return InstanceResult(instance, "no_version", "unknown", limits)
        try:
            parsed = versions.parse(instance.version, rule.scheme)
            result = versions.affected(parsed, [dict(r) for r in rule.ranges], rule.scheme)
        except VersionError:
            return InstanceResult(instance, "unparseable", "unknown", limits)
        if result is False:
            return InstanceResult(instance, "not_affected", "not_affected", limits)
        if result is None:
            return InstanceResult(instance, "not_comparable", _cap("potential", limits), limits)
        return InstanceResult(instance, "affected", _cap("confirmed", limits), limits)

    def _checks(
        self,
        component: Component,
        rule: AffectedRule,
        decisive: InstanceResult,
        publisher_check: str,
    ) -> tuple[dict[str, str], ...]:
        checks = [{"check": "identity", "result": f"exact_key:{component.key}"}]
        if publisher_check == "declared":
            publisher = "unreported" if "publisher_unreported" in decisive.limits else "match"
            checks.append({"check": "publisher", "result": publisher})
        elif publisher_check == "not_declared":
            checks.append({"check": "publisher", "result": "not_declared"})
        checks.append({"check": "version", "result": decisive.version_result})
        checks.extend({"check": "limit", "result": limit} for limit in decisive.limits)
        return tuple(checks)

    def _rationale(self, component: Component, rule: AffectedRule, decisive: InstanceResult) -> str:
        version = decisive.instance.version
        label = rule.range_label() or "rango declarado"
        subject = f"{decisive.instance.name} {version}" if version else decisive.instance.name
        if decisive.version_result == "no_version":
            text = f"{subject}: producto presente sin versión informada; no se puede afirmar."
        elif decisive.version_result == "unparseable":
            text = (
                f"{subject}: la versión no es válida en el esquema {rule.scheme} del catálogo; "
                "no se puede afirmar."
            )
        elif decisive.version_result == "not_affected":
            text = f"{subject}: versión fuera del rango afectado ({label})."
        elif decisive.version_result == "not_comparable":
            text = f"{subject}: la versión no se puede comparar con certeza con {label}" + (
                " (la build no incluye la revisión de parche)."
                if component.type == "os" and rule.scheme == "windows_build"
                else "."
            )
        else:
            text = f"{subject} está en el rango afectado ({label})."
        reasons = [_LIMIT_TEXT[limit] for limit in decisive.limits]
        if reasons and decisive.version_result in ("affected", "not_comparable"):
            text += " Limitado por: " + "; ".join(reasons) + "."
        return text[:500]


def candidate_rules(
    asset: AssetSoftware, rows: Sequence[tuple[Any, Sequence[str], Mapping[str, Any]]]
) -> list[tuple[Any, Component, AffectedRule]]:
    """Empareja cada fila candidata (id, match_keys, definition) con los componentes del activo
    que comparten clave. La consulta SQL ya filtró por solapamiento de claves (GIN)."""
    pairs: list[tuple[Any, Component, AffectedRule]] = []
    for row_id, keys, definition in rows:
        rule = AffectedRule.from_definition(definition)
        for key in keys:
            component = asset.components.get(key)
            if component is not None:
                pairs.append((row_id, component, rule))
    return pairs

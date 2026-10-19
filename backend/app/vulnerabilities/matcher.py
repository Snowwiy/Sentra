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

Fase 6C.4: entradas `cpe` (NVD). Un componente solo es candidato de un CPE a través de un
alias declarado (product_map.py: clave del inventario -> CPE, con editor y plataforma) o de
la build de Windows (cpe.windows_products). Cada cpeMatch se evalúa con sus calificadores
(edición, target_sw, target_hw, update): un calificador que no se puede verificar limita el
estado; uno que contradice el inventario descarta ese cpeMatch.
"""

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, cast

from app.vulnerabilities import cpe as cpe_mod
from app.vulnerabilities import normalize, versions
from app.vulnerabilities.product_map import ProductIdentity
from app.vulnerabilities.versions import Scheme, VersionError

# Marcas de versión de la distribución en el número de paquete (Fase 6C.4). El agente no
# informa la versión de la distribución, pero el paquete a menudo la lleva: Debian
# "+deb12u3" / "~deb12u1", RHEL y derivadas ".el9", Ubuntu "~22.04".
_DEB_RELEASE = re.compile(r"[+~]deb(\d{1,2})u\d+")
_EL_RELEASE = re.compile(r"\.el(\d{1,2})(?:[._]|$)")
_UBUNTU_RELEASE = re.compile(r"~(\d{2}\.\d{2})(?:\.\d+)?(?:$|[^0-9])")


def release_compatible(distro: str | None, version: str | None) -> bool:
    """False si la versión instalada lleva la marca de otra versión de la distribución.

    Sin marca no se descarta nada (se mantiene el límite distro_release_unknown): las marcas
    solo sirven para no aplicar a un paquete de Debian 12 el rango corregido en Debian 13.
    """
    if not distro or not version:
        return True
    parts = distro.split(":")
    if len(parts) < 2:
        return True
    family, release = parts[0], parts[-1]
    if family == "debian":
        found = _DEB_RELEASE.search(version)
        return found is None or found.group(1) == release.split(".")[0]
    if family in ("almalinux", "rocky", "rhel"):
        found = _EL_RELEASE.search(version)
        return found is None or found.group(1) == release.split(".")[0]
    if family == "ubuntu":
        found = _UBUNTU_RELEASE.search(version)
        return found is None or found.group(1) == release
    return True


MatchState = Literal["confirmed", "probable", "potential", "unknown", "not_affected"]
Confidence = Literal["high", "medium", "low"]
Platform = Literal["windows", "linux", "macos"]
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
class ComponentAlias:
    """Un identificador adicional (CPE) de un componente del activo, con su procedencia."""

    key: str
    component_key: str
    # windows_build (correspondencia determinista build -> producto NVD) o product_map.
    method: str
    # Solo product_map: la declaración (editores, ediciones, plataformas, fuente).
    identity: ProductIdentity | None = None

    def describe(self) -> dict[str, Any]:
        data: dict[str, Any] = {"method": self.method, "identifier": self.key}
        if self.identity is not None:
            data.update(
                cpe=self.identity.cpe,
                inventory_key=self.identity.inventory_key,
                declared_by=self.identity.source,
                publishers=list(self.identity.publishers),
                editions=list(self.identity.editions),
            )
        return data


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
    # Fase 6C.4: identificadores CPE de los componentes (clave cpe:... -> alias).
    aliases: Mapping[str, tuple[ComponentAlias, ...]] = field(default_factory=dict)
    # Arquitectura del equipo normalizada (x64, x86, arm64) para target_hw de CPE.
    architecture: str | None = None

    @property
    def keys(self) -> list[str]:
        """Claves de búsqueda: componentes y sus identificadores CPE."""
        return sorted(set(self.components) | set(self.aliases))

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
        if self.aliases:
            # Solo si hay alias: la huella de un activo sin identificadores CPE no cambia
            # respecto a la Fase 5B.
            payload.append(
                [
                    [key, a.component_key, a.method, sorted(a.describe().items(), key=str)]
                    for key, values in sorted(self.aliases.items())
                    for a in values
                ]
            )
            payload.append([self.architecture or ""])
        return hashlib.sha256(
            json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()


def platform_of(os_name: str | None) -> Platform | None:
    name = (os_name or "").strip().lower()
    if name.startswith("windows"):
        return "windows"
    if name.startswith("linux"):
        return "linux"
    # Fase 6C.4: el agente de macOS informa "macOS ..." o "Darwin" (platform.system()). Solo
    # se reconoce la plataforma: su versión de SO no se evalúa (ver _os_component).
    if name.startswith(("macos", "mac os", "darwin")):
        return "macos"
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
    architecture: str | None = None,
) -> AssetSoftware:
    """Normaliza el inventario del agente (software + SO) en componentes con clave.

    Los alias CPE de la build de Windows se añaden aquí (no dependen de nada importado); los
    de product_map los añade with_identities() con lo que haya en la base de datos.
    """
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
    aliases: dict[str, tuple[ComponentAlias, ...]] = {}
    if os_component is not None:
        components[os_component.key] = os_component
        if os_component.key == normalize.os_key("windows"):
            server = "server" in f"{os_name or ''} {os_version or ''}".lower()
            for product in cpe_mod.windows_products(os_component.instances[0].version, server):
                key = cpe_mod.product_key("o", "microsoft", product)
                aliases[key] = (ComponentAlias(key, os_component.key, "windows_build"),)
    return AssetSoftware(
        platform=platform,
        software_source=software_source,
        complete=complete,
        collected_at=collected_at,
        components=components,
        aliases=aliases,
        architecture=cpe_mod.architecture(architecture),
    )


def with_identities(
    software: AssetSoftware, identities: Mapping[str, Sequence[ProductIdentity]]
) -> AssetSoftware:
    """Añade los alias CPE declarados (product_map) para los componentes del activo."""
    aliases: dict[str, list[ComponentAlias]] = {k: list(v) for k, v in software.aliases.items()}
    for component_key in software.components:
        for identity in identities.get(component_key, ()):
            if identity.platforms and software.platform not in identity.platforms:
                continue
            aliases.setdefault(identity.cpe_key, []).append(
                ComponentAlias(identity.cpe_key, component_key, "product_map", identity)
            )
    if not aliases:
        return software
    return AssetSoftware(
        platform=software.platform,
        software_source=software.software_source,
        complete=software.complete,
        collected_at=software.collected_at,
        components=software.components,
        aliases={k: tuple(v) for k, v in aliases.items()},
        architecture=software.architecture,
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
    # Fase 6C.4 (type cpe): cpeMatch de NVD y condiciones AND de la configuración.
    cpe_match: tuple[Mapping[str, Any], ...] = ()
    conditions: tuple[str, ...] = ()
    # Fase 6C.4 (type package): distribución de los rangos y si los nombres son fuentes.
    distro: str | None = None
    source_package: bool = False

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
            cpe_match=tuple(definition.get("cpe_match") or ()),
            conditions=tuple(definition.get("conditions") or ()),
            distro=definition.get("distro"),
            source_package=bool(definition.get("source_package")),
        )

    @property
    def cpe_key(self) -> str | None:
        if self.type != "cpe" or not self.cpe_match:
            return None
        return cpe_mod.parse(str(self.cpe_match[0]["criteria"])).key

    def range_label(self) -> str:
        if self.type == "cpe":
            return " | ".join(cpe_range_label(m) for m in self.cpe_match)[:255]
        return " | ".join(versions.range_label(dict(r)) for r in self.ranges)[:255]


def cpe_bounds(match: Mapping[str, Any]) -> dict[str, str] | None:
    """Rango declarativo de un cpeMatch; {} = todas las versiones; None = calificado (update)."""
    parsed = cpe_mod.parse(str(match["criteria"]))
    if cpe_mod.is_concrete(parsed.version):
        return {"eq": cpe_mod.unescape(parsed.version)}
    bounds = {
        op: str(match[name])
        for name, op in (
            ("version_start_including", "gte"),
            ("version_start_excluding", "gt"),
            ("version_end_including", "lte"),
            ("version_end_excluding", "lt"),
        )
        if match.get(name)
    }
    return bounds


def cpe_range_label(match: Mapping[str, Any]) -> str:
    bounds = cpe_bounds(match)
    return versions.range_label(bounds) if bounds else "todas las versiones"


# --- Resultado ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class InstanceResult:
    instance: Instance
    # affected | not_affected | not_comparable | no_version | unparseable
    version_result: str
    state: MatchState
    # Debilidades de identidad que limitan el estado (códigos estables, ver _CAPS).
    limits: tuple[str, ...]
    # Fase 6C.4: cpeMatch que decidió (solo entradas cpe).
    match: Mapping[str, Any] | None = None


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
    # Fase 6C.4: identificador por el que casó (CPE) y cpeMatch que decidió el estado.
    alias: ComponentAlias | None = None
    decisive_match: Mapping[str, Any] | None = None

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
            # Fase 6C.4: por qué identificador casó (CPE o clave exacta) y qué rango decidió.
            "identity": self.alias.describe()
            if self.alias is not None
            else {"method": "exact_key", "identifier": self.component.key},
            **(
                {
                    "cpe_match": {
                        "criteria": self.decisive_match.get("criteria"),
                        "range": cpe_range_label(self.decisive_match),
                    }
                }
                if self.decisive_match is not None
                else {}
            ),
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
    # Fase 6C.4. Plataforma sin validar con agentes reales (macOS).
    "platform_unvalidated": "probable",
    # La configuración de NVD exige además otro producto (AND) que Sentra no puede verificar.
    "configuration_unverified": "probable",
    # El cpeMatch no tiene límites de versión: "todas las versiones" según la fuente.
    "unbounded_version_range": "probable",
    # target_sw/target_hw/other concretos que el inventario no permite comprobar.
    "cpe_target_unverified": "probable",
    # Edición concreta (sw_edition) y el identificador no declara qué edición es.
    "cpe_edition_unverified": "potential",
    # Calificador "update" concreto (sp1, p1...): la versión del inventario no lo incluye.
    "cpe_update_qualifier": "potential",
    # Nombres de paquete FUENTE (Debian en OSV) frente a paquetes binarios del inventario.
    "source_package_unverified": "probable",
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
    "platform_unvalidated": "plataforma macOS sin validar con agentes reales",
    "configuration_unverified": (
        "la fuente exige además otro producto o plataforma que Sentra no puede verificar"
    ),
    "unbounded_version_range": "la fuente declara afectadas todas las versiones, sin rango",
    "cpe_target_unverified": "el CPE limita la plataforma o arquitectura y no se puede verificar",
    "cpe_edition_unverified": "el CPE se refiere a una edición concreta no declarada",
    "cpe_update_qualifier": "el CPE incluye un calificador de actualización no comparable",
    "source_package_unverified": (
        "la fuente describe el paquete fuente; el inventario informa paquetes binarios"
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
        self,
        component: Component,
        rule: AffectedRule,
        asset: AssetSoftware,
        alias: ComponentAlias | None = None,
    ) -> MatchResult | None:
        identity = self._identity(component, rule, asset, alias)
        if identity is None:
            return None
        base_limits, publisher_check = identity
        publishers = rule.publishers
        if rule.type == "cpe" and alias is not None and alias.identity is not None:
            # En una entrada cpe el editor lo declara el identificador, no el registro de NVD.
            publishers = alias.identity.publishers
        results: list[InstanceResult] = []
        for instance in component.instances:
            limits = list(base_limits)
            if publishers:
                if instance.publisher is None:
                    limits.append("publisher_unreported")
                elif not any(
                    normalize.publisher_matches(instance.publisher, p) for p in publishers
                ):
                    # Mismo nombre, otro editor: otro producto. No es candidato.
                    continue
            if rule.type == "cpe":
                result = self._cpe_version(instance, rule, tuple(limits), asset, alias)
                if result is None:
                    continue
                results.append(result)
            else:
                if rule.type == "package" and not release_compatible(rule.distro, instance.version):
                    # La versión instalada lleva la marca de OTRA versión de la distribución
                    # ("+deb12u3" frente a una entrada de Debian 13): ese rango no le aplica.
                    continue
                results.append(self._version(instance, rule, tuple(limits)))
        if not results:
            return None
        decisive = max(results, key=lambda r: (STATE_RANK[r.state], r.instance.version or ""))
        checks = self._checks(component, rule, decisive, publisher_check, alias)
        return MatchResult(
            state=decisive.state,
            confidence=STATE_CONFIDENCE[decisive.state],
            rationale=self._rationale(component, rule, decisive),
            component=component,
            rule=rule,
            instance=decisive.instance,
            instances=tuple(results),
            checks=checks,
            alias=alias,
            decisive_match=decisive.match,
        )

    def _identity(
        self,
        component: Component,
        rule: AffectedRule,
        asset: AssetSoftware,
        alias: ComponentAlias | None = None,
    ) -> tuple[tuple[str, ...], str] | None:
        if rule.platforms and asset.platform not in rule.platforms:
            return None
        platform_limits: tuple[str, ...] = (
            ("platform_unvalidated",) if asset.platform == "macos" else ()
        )
        if rule.type == "cpe":
            # Un CPE solo casa por un alias del propio componente con la misma clave.
            if alias is None or alias.component_key != component.key or alias.key != rule.cpe_key:
                return None
            cpe_limits = list(platform_limits)
            if not _conditions_verified(rule.conditions, asset):
                cpe_limits.append("configuration_unverified")
            if alias.identity is None:
                # Build de Windows: identidad del SO informada por el agente.
                return tuple(cpe_limits), "not_applicable"
            if component.type == "package" or (
                component.type == "application" and asset.platform == "linux"
            ):
                # NVD publica versiones upstream; el paquete es de la distribución.
                cpe_limits.append("distro_backports")
            if not alias.identity.publishers:
                cpe_limits.append("name_only")
                return tuple(cpe_limits), "not_declared"
            return tuple(cpe_limits), "declared"
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
            package_limits = ["distro_release_unknown"]
            if rule.source_package:
                package_limits.append("source_package_unverified")
            return tuple(package_limits), "not_applicable"
        # Aplicación: solo componentes de software (nunca el SO).
        if component.type != "application":
            return None
        limits: list[str] = list(platform_limits)
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

    def _cpe_version(
        self,
        instance: Instance,
        rule: AffectedRule,
        limits: tuple[str, ...],
        asset: AssetSoftware,
        alias: ComponentAlias | None,
    ) -> InstanceResult | None:
        """Evalúa cada cpeMatch con sus calificadores. None: ninguno aplica a esta instancia."""
        if instance.version is None:
            return InstanceResult(instance, "no_version", "unknown", limits)
        editions = alias.identity.editions if alias and alias.identity else ()
        architecture = cpe_mod.architecture(instance.architecture) or asset.architecture
        try:
            installed = versions.parse(instance.version, rule.scheme)
        except VersionError:
            installed = None
        applicable = False
        unknown: list[tuple[Mapping[str, Any], tuple[str, ...]]] = []
        outside: Mapping[str, Any] | None = None
        best: InstanceResult | None = None
        for match in rule.cpe_match:
            qualifiers = _qualifiers(match, asset.platform, architecture, editions)
            if qualifiers is None:
                continue
            applicable = True
            match_limits = tuple(dict.fromkeys((*limits, *qualifiers)))
            if installed is None:
                unknown.append((match, match_limits))
                continue
            bounds = cpe_bounds(match)
            if "cpe_update_qualifier" in qualifiers:
                unknown.append((match, match_limits))
                continue
            if not bounds:
                match_limits = tuple(dict.fromkeys((*match_limits, "unbounded_version_range")))
                result: bool | None = True
            else:
                try:
                    result = versions.in_range(installed, bounds, rule.scheme)
                except VersionError:
                    # Límite de la fuente no parseable en el esquema: no se puede afirmar.
                    result = None
            if result is None:
                unknown.append((match, match_limits))
            elif result:
                candidate = InstanceResult(
                    instance, "affected", _cap("confirmed", match_limits), match_limits, match
                )
                if best is None or STATE_RANK[candidate.state] > STATE_RANK[best.state]:
                    best = candidate
            else:
                outside = outside or match
        if not applicable:
            return None
        if best is not None:
            return best
        if installed is None:
            match, match_limits = unknown[0]
            return InstanceResult(instance, "unparseable", "unknown", match_limits, match)
        if unknown:
            match, match_limits = unknown[0]
            return InstanceResult(
                instance, "not_comparable", _cap("potential", match_limits), match_limits, match
            )
        return InstanceResult(instance, "not_affected", "not_affected", limits, outside)

    def _checks(
        self,
        component: Component,
        rule: AffectedRule,
        decisive: InstanceResult,
        publisher_check: str,
        alias: ComponentAlias | None = None,
    ) -> tuple[dict[str, str], ...]:
        checks = [{"check": "identity", "result": f"exact_key:{component.key}"}]
        if alias is not None:
            checks.append({"check": "identifier", "result": f"{alias.method}:{alias.key}"})
            if alias.identity is not None:
                checks.append({"check": "identifier_source", "result": alias.identity.source})
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
        if decisive.match is not None:
            # Entrada cpe: el rango que cuenta es el del cpeMatch que decidió.
            label = f"{cpe_mod.unescape(rule.product)} {cpe_range_label(decisive.match)}"
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


def _qualifiers(
    match: Mapping[str, Any],
    platform: str | None,
    architecture: str | None,
    editions: Sequence[str],
) -> tuple[str, ...] | None:
    """Limitaciones que añaden los calificadores de un cpeMatch; None si no aplica."""
    parsed = cpe_mod.parse(str(match["criteria"]))
    limits: list[str] = []
    if cpe_mod.is_concrete(parsed.target_sw):
        expected = cpe_mod.TARGET_SW_PLATFORM.get(parsed.target_sw)
        if expected is not None:
            if platform is not None and expected != platform:
                return None
        else:
            limits.append("cpe_target_unverified")
    if cpe_mod.is_concrete(parsed.target_hw):
        wanted = cpe_mod.architecture(parsed.target_hw)
        if wanted is not None and architecture is not None:
            if wanted != architecture:
                return None
        else:
            limits.append("cpe_target_unverified")
    if cpe_mod.is_concrete(parsed.other):
        limits.append("cpe_target_unverified")
    if parsed.sw_edition != cpe_mod.ANY:
        if editions:
            if parsed.sw_edition not in editions:
                return None
        elif parsed.sw_edition != cpe_mod.NA:
            limits.append("cpe_edition_unverified")
    if parsed.edition not in (cpe_mod.ANY, cpe_mod.NA):
        limits.append("cpe_edition_unverified")
    if parsed.update not in (cpe_mod.ANY, cpe_mod.NA):
        limits.append("cpe_update_qualifier")
    return tuple(limits)


# Condiciones (AND) que el agente sí permite verificar: el SO del propio activo.
_OS_CONDITIONS = {
    "windows": ("cpe:o:microsoft:windows",),
    "linux": ("cpe:o:linux:linux_kernel",),
    "macos": ("cpe:o:apple:macos", "cpe:o:apple:mac_os_x", "cpe:o:apple:mac_os"),
}


def _conditions_verified(conditions: Sequence[str], asset: AssetSoftware) -> bool:
    """¿Todas las condiciones AND son el SO del activo? (p. ej. "app ... running on Windows")."""
    if not conditions:
        return True
    prefixes = _OS_CONDITIONS.get(asset.platform or "", ())
    for condition in conditions:
        try:
            key = cpe_mod.parse(condition).key
        except cpe_mod.CpeError:
            return False
        if not prefixes or not key.startswith(prefixes):
            return False
    return True


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

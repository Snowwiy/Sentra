"""Identificadores de producto: inventario -> CPE, declarados expresamente (Fase 6C.4).

NVD describe lo afectado con CPE (`cpe:2.3:a:google:chrome:...`); el inventario de los agentes
no trae CPE. Para no casar "por nombre parecido", la relación entre una clave del inventario
(`name:google chrome`, `pkg:deb:openssh-server`) y un producto CPE debe estar DECLARADA:

- en la semilla integrada (BUILTIN, abajo): pocos productos muy comunes cuya correspondencia
  con NVD es pública y estable, cada uno con el editor que debe informar el inventario;
- en la sección opcional `products` de un catálogo local sentra-vuln-catalog/1, que importa un
  administrador (ver docs/vulnerability-sources.md).

El editor declarado se comprueba en cada instancia (un "Chrome" de otro editor no es Google
Chrome) y la plataforma limita dónde aplica. Una correspondencia nunca hace "confirmed" por sí
sola: el matcher sigue exigiendo versión comparable dentro de un rango.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.vulnerabilities import cpe as cpe_mod
from app.vulnerabilities import normalize

BUILTIN_SOURCE = "builtin"
MAX_PRODUCTS = 20_000


@dataclass(frozen=True)
class ProductIdentity:
    """Una clave del inventario identifica un producto CPE (con sus condiciones)."""

    inventory_key: str
    cpe_key: str
    cpe: str
    vendor: str
    product: str
    publishers: tuple[str, ...]
    # Valores de sw_edition aceptados ("-" = sin edición, p. ej. Firefox no ESR). Vacío: no
    # declarado; un cpeMatch con edición concreta no se puede verificar.
    editions: tuple[str, ...]
    platforms: tuple[str, ...]
    # builtin o la clave de la fuente del catálogo que lo declaró (procedencia).
    source: str


class _PackageRef(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    ecosystem: Literal["deb", "rpm"]
    name: str = Field(min_length=1, max_length=128)


class ProductIn(BaseModel):
    """Entrada de la sección `products` de un catálogo local."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    cpe: str = Field(max_length=cpe_mod.MAX_CPE_LENGTH)
    names: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        default_factory=list, max_length=20
    )
    packages: list[_PackageRef] = Field(default_factory=list, max_length=20)
    publishers: list[Annotated[str, Field(min_length=1, max_length=200)]] = Field(
        default_factory=list, max_length=20
    )
    editions: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(
        default_factory=list, max_length=10
    )
    platforms: list[Literal["windows", "linux", "macos"]] = Field(
        default_factory=list, max_length=3
    )

    @field_validator("cpe")
    @classmethod
    def _check_cpe(cls, value: str) -> str:
        try:
            parsed = cpe_mod.parse(value)
        except cpe_mod.CpeError as exc:
            raise ValueError(str(exc)) from None
        if parsed.part == "h":
            raise ValueError("hardware CPEs cannot identify inventory software")
        return value

    @model_validator(mode="after")
    def _check(self) -> "ProductIn":
        if not self.names and not self.packages:
            raise ValueError("a product needs names or packages")
        for package in self.packages:
            if normalize.package_key(package.ecosystem, package.name) is None:
                raise ValueError("invalid package name")
        return self

    def identities(self, source: str) -> list[ProductIdentity]:
        parsed = cpe_mod.parse(self.cpe)
        keys: list[str] = []
        for name in self.names:
            key = normalize.name_key(name)
            if key:
                keys.append(key)
        for package in self.packages:
            key = normalize.package_key(package.ecosystem, package.name)
            if key:
                keys.append(key)
        return [
            ProductIdentity(
                inventory_key=key,
                cpe_key=parsed.key,
                cpe=parsed.base,
                vendor=parsed.vendor,
                product=parsed.product,
                publishers=tuple(self.publishers),
                editions=tuple(e.lower() for e in self.editions),
                platforms=tuple(self.platforms),
                source=source,
            )
            for key in sorted(set(keys))
        ]


def _app(cpe: str, names: Sequence[str], publishers: Sequence[str], **extra: object) -> ProductIn:
    return ProductIn.model_validate(
        {"cpe": cpe, "names": list(names), "publishers": list(publishers), **extra}
    )


def _pkg(cpe: str, deb: Sequence[str] = (), rpm: Sequence[str] = ()) -> ProductIn:
    packages = [{"ecosystem": "deb", "name": n} for n in deb]
    packages += [{"ecosystem": "rpm", "name": n} for n in rpm]
    return ProductIn.model_validate({"cpe": cpe, "packages": packages, "platforms": ["linux"]})


# Semilla integrada. Criterios: producto muy común en el parque Windows/Linux, nombre de
# inventario (DisplayName o paquete) estable, editor estable y versión del inventario en el
# mismo esquema que NVD. Quedan fuera a propósito productos cuyo DisplayVersion no es la
# versión pública (Python en Windows informa 3.12.1150.0 para 3.12.1) o cuyo nombre incluye
# texto variable (PuTTY "release 0.81", Wireshark "4.2.5 x64").
_ANY = "*:*:*:*:*:*:*:*"
BUILTIN_PRODUCTS: tuple[ProductIn, ...] = (
    _app(f"cpe:2.3:a:google:chrome:{_ANY}", ["Google Chrome"], ["Google"], platforms=["windows"]),
    _app(
        f"cpe:2.3:a:mozilla:firefox:{_ANY}",
        ["Mozilla Firefox"],
        ["Mozilla"],
        editions=["-"],
        platforms=["windows"],
    ),
    _app(
        f"cpe:2.3:a:mozilla:firefox:{_ANY}",
        ["Mozilla Firefox ESR"],
        ["Mozilla"],
        editions=["esr"],
        platforms=["windows"],
    ),
    _app(
        f"cpe:2.3:a:mozilla:firefox_esr:{_ANY}",
        ["Mozilla Firefox ESR"],
        ["Mozilla"],
        platforms=["windows"],
    ),
    _app(
        f"cpe:2.3:a:mozilla:thunderbird:{_ANY}",
        ["Mozilla Thunderbird"],
        ["Mozilla"],
        platforms=["windows"],
    ),
    _app(
        f"cpe:2.3:a:microsoft:edge_chromium:{_ANY}",
        ["Microsoft Edge"],
        ["Microsoft"],
        platforms=["windows"],
    ),
    _app(f"cpe:2.3:a:7-zip:7-zip:{_ANY}", ["7-Zip"], ["Igor Pavlov"], platforms=["windows"]),
    _app(
        f"cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:{_ANY}",
        ["Notepad++"],
        ["Notepad++ Team"],
        platforms=["windows"],
    ),
    _app(
        f"cpe:2.3:a:videolan:vlc_media_player:{_ANY}",
        ["VLC media player"],
        ["VideoLAN"],
        platforms=["windows"],
    ),
    _app(f"cpe:2.3:a:winscp:winscp:{_ANY}", ["WinSCP"], ["Martin Prikryl"], platforms=["windows"]),
    _app(
        f"cpe:2.3:a:git-scm:git:{_ANY}",
        ["Git"],
        ["The Git Development Community"],
        platforms=["windows"],
    ),
    # Paquetes de distribución: NVD publica versiones upstream; el matcher lo limita a
    # "potential" (backports). Sirven para ver el CVE y su KEV/EPSS junto al paquete.
    _pkg(f"cpe:2.3:a:openssl:openssl:{_ANY}", deb=["openssl"], rpm=["openssl"]),
    _pkg(
        f"cpe:2.3:a:openbsd:openssh:{_ANY}",
        deb=["openssh-server", "openssh-client"],
        rpm=["openssh", "openssh-server", "openssh-clients"],
    ),
    _pkg(f"cpe:2.3:a:sudo_project:sudo:{_ANY}", deb=["sudo"], rpm=["sudo"]),
    _pkg(f"cpe:2.3:a:haxx:curl:{_ANY}", deb=["curl"], rpm=["curl"]),
    _pkg(f"cpe:2.3:a:haxx:libcurl:{_ANY}", deb=["libcurl4"], rpm=["libcurl"]),
    _pkg(f"cpe:2.3:a:gnu:bash:{_ANY}", deb=["bash"], rpm=["bash"]),
    _pkg(f"cpe:2.3:a:tukaani:xz:{_ANY}", deb=["xz-utils"], rpm=["xz"]),
)


def builtin_identities() -> dict[str, tuple[ProductIdentity, ...]]:
    """Semilla integrada indexada por clave del inventario."""
    index: dict[str, list[ProductIdentity]] = {}
    for product in BUILTIN_PRODUCTS:
        for identity in product.identities(BUILTIN_SOURCE):
            index.setdefault(identity.inventory_key, []).append(identity)
    return {key: tuple(values) for key, values in index.items()}


BUILTIN_INDEX: Mapping[str, tuple[ProductIdentity, ...]] = builtin_identities()


def merge(
    builtin: Mapping[str, Iterable[ProductIdentity]],
    imported: Iterable[ProductIdentity],
) -> dict[str, tuple[ProductIdentity, ...]]:
    """Une semilla e importados. Para la misma (clave, CPE) gana lo importado por un admin."""
    merged: dict[tuple[str, str], ProductIdentity] = {}
    for values in builtin.values():
        for identity in values:
            merged[
                (identity.inventory_key, identity.cpe_key + "|" + ",".join(identity.editions))
            ] = identity
    for identity in imported:
        # Una entrada importada sustituye a la integrada con la misma clave y producto.
        for existing in [k for k in merged if k[0] == identity.inventory_key]:
            if merged[existing].cpe_key == identity.cpe_key and merged[existing].source == (
                BUILTIN_SOURCE
            ):
                del merged[existing]
        merged[(identity.inventory_key, identity.cpe_key + "|" + ",".join(identity.editions))] = (
            identity
        )
    index: dict[str, list[ProductIdentity]] = {}
    for identity in merged.values():
        index.setdefault(identity.inventory_key, []).append(identity)
    return {
        key: tuple(sorted(values, key=lambda i: (i.cpe_key, i.editions, i.source)))
        for key, values in index.items()
    }

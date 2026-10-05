"""Aplica la identificación (app/discovery/classify.py) a los activos guardados.

Un único punto de entrada, refresh_identity, que se llama siempre que llega información
nueva sobre un activo: un scan de discovery, el registro/heartbeat de su agente, su
inventario (MACs) o la fusión DISCOVERED → MANAGED. Así todas las vías producen la misma
conclusión con las mismas reglas, y los datos del agente siempre ganan a las inferencias
de red porque classify.identify los trata como autoritativos.

Es barato (sin red ni consultas): la base OUI está en memoria y cacheada (oui.py) y las
sondas lentas (DNS, mDNS, NetBIOS, UPnP) solo ocurren durante el scan; aquí se trabaja con
lo que el scan ya guardó en identity_observations.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from app.core.config import get_settings
from app.discovery import oui
from app.discovery.classify import IdentityInput, identify
from app.discovery.device_types import ClassificationConfidence
from app.discovery.scanner import HostObservation
from app.discovery.vendors import display_vendor
from app.models.asset import Asset


@dataclass(frozen=True)
class IdentityChange:
    previous_type: str | None
    previous_confidence: ClassificationConfidence | None
    device_type: str | None

    @property
    def reclassified(self) -> bool:
        """Cambio de tipo que merece una entrada en el historial del activo.

        Solo si la clasificación anterior la hizo este mismo motor (confianza no nula): la
        primera pasada tras la migración 0015 no es un cambio del dispositivo, sino de las
        reglas, y registrarla llenaría el historial de ruido.
        """
        return self.previous_confidence is not None and self.previous_type != self.device_type


def oui_database() -> oui.OuiDatabase:
    return oui.load_database(oui.parse_paths(get_settings().discovery_oui_file))


def network_adapter_vendor(asset: Asset) -> str | None:
    """Marca corta de la NIC para la API ("Realtek"), a partir del nombre OUI guardado."""
    return display_vendor(asset.vendor)


def record_observation(asset: Asset, obs: HostObservation, is_gateway: bool | None) -> None:
    """Guarda lo que el scan vio de la identidad del host, sin perder lo visto antes.

    Un dispositivo no responde a mDNS/NetBIOS/SSDP en todos los scans (Wi-Fi dormido,
    pérdida de un paquete UDP): un valor ausente no borra el anterior; uno nuevo lo
    sustituye. `is_gateway` es None cuando no se pudo leer la tabla de rutas del servidor:
    en ese caso tampoco se cambia lo que se sabía.
    """
    current: dict[str, Any] = dict(asset.identity_observations or {})
    updates: dict[str, Any] = {
        "mdns_name": obs.mdns_name,
        "netbios_name": obs.netbios_name,
        "ssdp_server": obs.ssdp.server if obs.ssdp else None,
    }
    if obs.upnp is not None:
        updates["upnp"] = {k: v for k, v in vars(obs.upnp).items() if v}
    for key, value in updates.items():
        if value:
            current[key] = value
    if is_gateway is not None:
        current["gateway"] = is_gateway
    # Asignar un dict nuevo (no mutar el existente) para que SQLAlchemy detecte el cambio.
    asset.identity_observations = current or None


def identity_input(asset: Asset, open_ports: Iterable[int]) -> IdentityInput:
    seen: dict[str, Any] = asset.identity_observations or {}
    upnp: dict[str, Any] = seen.get("upnp") or {}
    return IdentityInput(
        managed=asset.is_managed,
        hostname=asset.hostname,
        os_name=asset.os_name,
        os_version=asset.os_version,
        reverse_dns=asset.reverse_dns,
        mdns_name=_text(seen.get("mdns_name")),
        netbios_name=_text(seen.get("netbios_name")),
        upnp_friendly_name=_text(upnp.get("friendly_name")),
        upnp_manufacturer=_text(upnp.get("manufacturer")),
        upnp_model_name=_text(upnp.get("model_name")),
        upnp_model_number=_text(upnp.get("model_number")),
        upnp_device_type=_text(upnp.get("device_type")),
        ssdp_server=_text(seen.get("ssdp_server")),
        mac=asset.mac_address,
        mac_vendor=asset.vendor,
        mac_random=oui.is_locally_administered(asset.mac_address),
        open_ports=frozenset(open_ports),
        is_gateway=seen.get("gateway") is True,
    )


def refresh_identity(
    asset: Asset,
    open_ports: Iterable[int] = (),
    database: oui.OuiDatabase | None = None,
) -> IdentityChange:
    """Recalcula y guarda la identificación del activo. No hace commit.

    Las asignaciones solo generan UPDATE si el valor cambia (SQLAlchemy compara), así que
    llamarlo en cada heartbeat del agente no escribe nada mientras no cambie la conclusión.
    """
    database = database if database is not None else oui_database()
    if asset.mac_address:
        if oui.is_locally_administered(asset.mac_address):
            # MAC aleatoria: cualquier fabricante anterior pertenecía a otra MAC.
            asset.vendor = None
        else:
            found = database.lookup(asset.mac_address)
            # Sin base OUI configurada no se borra un fabricante ya conocido.
            if found:
                asset.vendor = found
    change = IdentityChange(
        previous_type=asset.device_type,
        previous_confidence=asset.classification_confidence,
        device_type=None,
    )
    result = identify(identity_input(asset, open_ports))
    asset.device_name = result.name
    asset.name_source = result.name_source
    asset.device_type = result.device_type.value if result.device_type else None
    asset.device_type_reason = result.reason
    asset.device_vendor = result.device_vendor
    asset.device_model = result.device_model
    asset.probable_os = None if asset.is_managed else result.probable_os
    asset.classification_confidence = result.confidence
    asset.classification_evidence = result.evidence or None
    return IdentityChange(change.previous_type, change.previous_confidence, asset.device_type)


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None

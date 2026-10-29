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
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.config import get_settings
from app.discovery import oui
from app.discovery.classify import (
    DHCP_LEASE,
    MDNS,
    MDNS_SERVICE,
    NETBIOS,
    REVERSE_DNS,
    UPNP,
    WEB,
    IdentityInput,
    WebEvidence,
    identify,
    is_default_name,
)
from app.discovery.device_types import ClassificationConfidence, DeviceType
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


# Corrección 6C: un nombre que ninguna fuente repite en este plazo se considera antiguo. Se
# conserva como evidencia, pero no gana a un nombre reciente de otra fuente ni impide que un
# dato nuevo (aunque sea más débil) lo sustituya: un equipo renombrado o una IP reasignada
# dejan de anunciar el nombre viejo.
NAME_STALE_DAYS = 30
# Clave de identity_observations -> fuente de nombre de classify (para la vigencia).
_SEEN_KEYS = {
    "dhcp_lease": DHCP_LEASE,
    "reverse_dns": REVERSE_DNS,
    "mdns_name": MDNS,
    "netbios_name": NETBIOS,
    "upnp": UPNP,
    # Fase 7A.4: las huellas también caducan (un firmware nuevo, una IP reasignada).
    "mdns_services": MDNS_SERVICE,
    "mdns_model": MDNS_SERVICE,
    "web": WEB,
}


def oui_database() -> oui.OuiDatabase:
    return oui.load_database(oui.parse_paths(get_settings().discovery_oui_file))


def network_adapter_vendor(asset: Asset) -> str | None:
    """Marca corta de la NIC para la API ("Realtek"), a partir del nombre OUI guardado."""
    return display_vendor(asset.vendor)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _is_stale(seen: dict[str, Any], key: str, now: datetime) -> bool:
    # Sin fecha (datos anteriores a la Corrección 6C) no se sabe su edad: no se tratan como
    # antiguos, para no degradar de golpe todos los nombres al actualizar.
    when = _parse_time(seen.get(key))
    return when is not None and now - when > timedelta(days=NAME_STALE_DAYS)


def source_seen_times(asset: Asset) -> dict[str, datetime]:
    """Fuente de identidad de classify -> última vez que el discovery la vio (Fase 7B.2).

    Para la ficha de identidad: la vigencia de cada nivel sale de la misma marca que usa la
    selección de nombres, así la UI y el motor nunca discrepan sobre qué es antiguo.
    """
    seen = (asset.identity_observations or {}).get("seen_at")
    found: dict[str, datetime] = {}
    if not isinstance(seen, dict):
        return found
    for key, source in _SEEN_KEYS.items():
        when = _parse_time(seen.get(key))
        if when is not None and (source not in found or when > found[source]):
            found[source] = when
    return found


def _weaker_name(new: str, old: Any) -> bool:
    """¿El nombre nuevo es un valor por defecto que vendría a tapar uno que sí identifica?"""
    return isinstance(old, str) and bool(old) and is_default_name(new) and not is_default_name(old)


def record_observation(
    asset: Asset, obs: HostObservation, is_gateway: bool | None, now: datetime | None = None
) -> None:
    """Guarda lo que el scan vio de la identidad del host, sin perder lo visto antes.

    Un dispositivo no responde a mDNS/NetBIOS/SSDP en todos los scans (Wi-Fi dormido,
    pérdida de un paquete UDP): un valor ausente no borra el anterior; uno nuevo lo
    sustituye. `is_gateway` es None cuando no se pudo leer la tabla de rutas del servidor:
    en ese caso tampoco se cambia lo que se sabía.

    Corrección 6C: cada dato lleva la hora en que se vio (`seen_at`) y un nombre genérico
    ("linux") no sustituye a uno que identifica al equipo mientras este siga vigente: una
    respuesta más pobre de la misma fuente no borra una identificación mejor.
    """
    now = now or datetime.now(UTC)
    current: dict[str, Any] = dict(asset.identity_observations or {})
    seen: dict[str, Any] = dict(current.get("seen_at") or {})
    updates: dict[str, Any] = {
        "mdns_name": obs.mdns_name,
        "netbios_name": obs.netbios_name,
        "ssdp_server": obs.ssdp.server if obs.ssdp else None,
    }
    if obs.upnp is not None:
        updates["upnp"] = {k: v for k, v in vars(obs.upnp).items() if v}
    # Fase 7A.4: huellas de servicio. Igual que los nombres, una ausencia no borra lo visto.
    if obs.services is not None:
        updates["mdns_services"] = list(obs.services.services) or None
        updates["mdns_model"] = obs.services.model
    if obs.web:
        updates["web"] = [item.as_dict() for item in obs.web[:2]]
    for key, value in updates.items():
        if not value:
            continue
        old = current.get(key)
        if isinstance(value, str) and _weaker_name(value, old) and not _is_stale(seen, key, now):
            continue
        current[key] = value
        if key in _SEEN_KEYS:
            seen[key] = now.isoformat()
    if seen:
        current["seen_at"] = seen
    if is_gateway is not None:
        current["gateway"] = is_gateway
    # Asignar un dict nuevo (no mutar el existente) para que SQLAlchemy detecte el cambio.
    asset.identity_observations = current or None


def record_reverse_dns(
    asset: Asset, name: str | None, confirmed: bool | None, now: datetime | None = None
) -> None:
    """Actualiza el DNS inverso sin que una respuesta más débil tape una más fiable.

    `confirmed` es el resultado de la confirmación directa (FCrDNS) del nombre NUEVO: True
    si resuelve a esta IP, False si resuelve a otra, None si no se comprobó. Se conserva el
    nombre anterior cuando, estando vigente, el nuevo es un valor por defecto ("linux") y el
    anterior no, o cuando el anterior estaba confirmado y el nuevo queda desmentido.
    """
    if not name:
        return
    now = now or datetime.now(UTC)
    current: dict[str, Any] = dict(asset.identity_observations or {})
    seen: dict[str, Any] = dict(current.get("seen_at") or {})
    old = asset.reverse_dns
    if old and old != name and not _is_stale(seen, "reverse_dns", now):
        old_confirmed = current.get("reverse_dns_confirmed")
        if _weaker_name(_bare(name), _bare(old)) or (old_confirmed is True and confirmed is False):
            return
    if old != name:
        # Otro nombre: la confirmación anterior era del nombre viejo.
        current.pop("reverse_dns_confirmed", None)
    asset.reverse_dns = name
    if confirmed is not None:
        current["reverse_dns_confirmed"] = confirmed
    seen["reverse_dns"] = now.isoformat()
    current["seen_at"] = seen
    asset.identity_observations = current


def _bare(name: str | None) -> str:
    """Primera etiqueta del nombre, para comparar "linux.local" con "linux"."""
    return (name or "").strip().rstrip(".").split(".", 1)[0]


def identity_input(
    asset: Asset, open_ports: Iterable[int], now: datetime | None = None
) -> IdentityInput:
    seen: dict[str, Any] = asset.identity_observations or {}
    upnp: dict[str, Any] = seen.get("upnp") or {}
    seen_at = seen.get("seen_at")
    seen_at = seen_at if isinstance(seen_at, dict) else {}
    now = now or datetime.now(UTC)
    confirmed = seen.get("reverse_dns_confirmed")
    return IdentityInput(
        managed=asset.is_managed,
        hostname=asset.hostname,
        os_name=asset.os_name,
        os_version=asset.os_version,
        reverse_dns=asset.reverse_dns,
        dhcp_hostname=_dhcp_hostname(seen.get("dhcp_lease")),
        mdns_name=_text(seen.get("mdns_name")),
        netbios_name=_text(seen.get("netbios_name")),
        upnp_friendly_name=_text(upnp.get("friendly_name")),
        upnp_manufacturer=_text(upnp.get("manufacturer")),
        upnp_model_name=_text(upnp.get("model_name")),
        upnp_model_number=_text(upnp.get("model_number")),
        upnp_device_type=_text(upnp.get("device_type")),
        ssdp_server=_text(seen.get("ssdp_server")),
        mdns_services=frozenset(
            item for item in seen.get("mdns_services") or [] if isinstance(item, str)
        ),
        mdns_model=_text(seen.get("mdns_model")),
        web=tuple(_web_items(seen.get("web"))),
        mac=asset.mac_address,
        mac_vendor=asset.vendor,
        mac_random=oui.is_locally_administered(asset.mac_address),
        open_ports=frozenset(open_ports),
        is_gateway=seen.get("gateway") is True,
        reverse_dns_confirmed=confirmed if isinstance(confirmed, bool) else None,
        stale_sources=frozenset(
            source for key, source in _SEEN_KEYS.items() if _is_stale(seen_at, key, now)
        ),
        manual_type=_manual_type(asset.manual_device_type),
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
    asset.observed_names = result.names or None
    return IdentityChange(change.previous_type, change.previous_confidence, asset.device_type)


def _dhcp_hostname(value: Any) -> str | None:
    """Hostname del lease guardado por app/dhcp/service.py ({"hostname", "source", ...})."""
    return _text(value.get("hostname")) if isinstance(value, dict) else None


def _manual_type(value: str | None) -> DeviceType | None:
    # Un valor que ya no existe en el enum (BD manipulada) se ignora: vuelve el automático.
    try:
        return DeviceType(value) if value else None
    except ValueError:
        return None


def _web_items(value: Any) -> Iterable[WebEvidence]:
    if not isinstance(value, list):
        return
    for item in value[:2]:
        if isinstance(item, dict):
            yield WebEvidence(
                server=_text(item.get("server")),
                title=_text(item.get("title")),
                cert_cn=_text(item.get("cert_cn")),
                cert_org=_text(item.get("cert_org")),
            )


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None

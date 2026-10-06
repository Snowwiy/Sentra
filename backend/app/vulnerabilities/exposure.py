"""Contexto de exposición de un finding (Fase 5B), reutilizando Discovery (4D) y Contexto (4L).

Exposición NO es vulnerabilidad: aquí solo se responde "¿el servicio que declara el catálogo
para esta vulnerabilidad es alcanzable?" con lo que Sentra ya sabe:
- asset_ports: puertos TCP observados abiertos desde el servidor/sensor de Sentra;
- inventario del agente: sockets en escucha en el propio equipo (no implica alcanzable);
- contexto de negocio (4L): internet_exposed confirmado por un administrador.

Sin escaneos nuevos, sin banner grabbing, sin conexiones a los activos. Si el catálogo no
declara puertos de servicio, la exposición de la vulnerabilidad es "unknown" (no se deduce
del producto).

Estados (de más a menos expuesto):
- internet_exposed: un puerto declarado se observa abierto y el activo tiene la exposición a
  Internet CONFIRMADA en su contexto;
- observed: un puerto declarado se observa abierto desde el sensor de Sentra (alcanzable en la
  red interna que ve Sentra);
- listening: el agente ve el puerto en escucha, pero Sentra no lo ha observado abierto;
- not_observed: puertos declarados, escaneados por discovery y no abiertos, ni en escucha;
- unknown: sin puertos declarados o sin datos suficientes.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

ExposureState = Literal["internet_exposed", "observed", "listening", "not_observed", "unknown"]
EXPOSURE_STATES: tuple[ExposureState, ...] = (
    "internet_exposed",
    "observed",
    "listening",
    "not_observed",
    "unknown",
)
EXPOSURE_RANK: Mapping[str, int] = {
    "unknown": 0,
    "not_observed": 0,
    "listening": 1,
    "observed": 2,
    "internet_exposed": 3,
}

# Etiquetas de alcanzabilidad (códigos estables; la UI los traduce).
OBSERVED_FROM_SENSOR = "observed_from_sentra_sensor"
LAN_REACHABLE = "lan_reachable"
AGENT_LISTENING = "agent_listening"
NOT_OBSERVED = "not_observed_from_sensor"
INTERNET_CONFIRMED = "internet_exposure_confirmed"
INTERNET_NOT_EXPOSED = "internet_not_exposed"
INTERNET_UNKNOWN = "internet_exposure_unknown"
NO_SERVICE_DECLARED = "no_service_port_declared"


@dataclass(frozen=True)
class AssetExposure:
    """Lo que Sentra sabe de la red de un activo (una vez por activo y evaluación)."""

    # Puertos TCP abiertos según discovery (asset_ports.state = open).
    observed_open: frozenset[int] = frozenset()
    # Puertos en escucha según el último inventario del agente.
    listening: frozenset[int] = frozenset()
    # Discovery ya estableció la línea base de puertos de este activo.
    scanned: bool = False
    # Puertos que discovery prueba (DISCOVERY_PORTS): solo esos pueden estar "no observados".
    probed: frozenset[int] = frozenset()
    # Contexto 4L: True/False confirmado por un administrador; None = desconocido.
    internet_exposed: bool | None = None


@dataclass(frozen=True)
class ExposureAssessment:
    state: ExposureState
    labels: tuple[str, ...]
    ports: tuple[int, ...]
    observed_open: tuple[int, ...]
    listening: tuple[int, ...]

    def to_json(self, internet_exposed: bool | None) -> dict[str, Any]:
        return {
            "state": self.state,
            "labels": list(self.labels),
            "service_ports": list(self.ports),
            "observed_open": list(self.observed_open),
            "listening": list(self.listening),
            "internet_exposed": internet_exposed,
        }


def assess(service_ports: Iterable[int], exposure: AssetExposure) -> ExposureAssessment:
    ports = tuple(sorted(set(service_ports)))
    if not ports:
        return ExposureAssessment("unknown", (NO_SERVICE_DECLARED,), (), (), ())
    observed = tuple(p for p in ports if p in exposure.observed_open)
    listening = tuple(p for p in ports if p in exposure.listening)
    labels: list[str] = []
    if observed:
        labels += [OBSERVED_FROM_SENSOR, LAN_REACHABLE]
    if listening:
        labels.append(AGENT_LISTENING)
    internet = {
        True: INTERNET_CONFIRMED,
        False: INTERNET_NOT_EXPOSED,
        None: INTERNET_UNKNOWN,
    }[exposure.internet_exposed]
    if observed and exposure.internet_exposed is True:
        state: ExposureState = "internet_exposed"
    elif observed:
        state = "observed"
    elif listening:
        state = "listening"
    elif exposure.scanned and all(p in exposure.probed for p in ports):
        state = "not_observed"
        labels.append(NOT_OBSERVED)
    else:
        state = "unknown"
    labels.append(internet)
    return ExposureAssessment(state, tuple(labels), ports, observed, listening)

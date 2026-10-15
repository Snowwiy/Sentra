"""Evidencia de Advanced Network Discovery (Fase 6A): una fila por job y dirección.

ResultApplier ya decide la identidad (qué activo es cada host) y actualiza activos, puertos,
cambios y alertas con la semántica de siempre. Este módulo solo deja constancia auditable de
QUÉ se vio, CÓMO y DESDE DÓNDE (site, servidor o sensor, job), y de las diferencias con la
observación anterior del mismo activo. Reglas:

- Observed = evidencia directa de esta ejecución (respuesta ICMP, TCP open/RST, entrada ARP,
  registro DNS). Inferred = deducción parcial (pista de servicio por número de puerto, puerto
  que dejó de responder sin un RST). Unknown = sin evidencia suficiente.
- Nunca se inventa SO, fabricante, modelo, versión ni servicio real: un puerto abierto es
  "puerto abierto", y su nombre IANA se marca como pista inferida al leer.
- Un host sin respuesta solo se registra tras un scan COMPLETO y para activos ya vistos en
  esa red; es "no respondió en esta ejecución", nunca "desaparecido" ni "comprometido".
- Las comparaciones solo usan lo que ambas ejecuciones sondearon de verdad: un puerto que el
  job anterior no sondeó no es "nuevo", y uno que este job no sondeó no "dejó de responder".
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.orm import Session

from app.discovery.probes import PortState
from app.discovery.scanner import HostObservation
from app.models.asset import Asset
from app.models.discovery import DiscoveryJob, DiscoveryObservation

# Métodos de liveness: cada uno es una prueba independiente de que hay un host.
LIVENESS_METHODS = ("icmp", "tcp", "arp")
MAX_EVIDENCE = 40


@dataclass(frozen=True)
class _Previous:
    address: str
    hostname: str | None
    open_ports: frozenset[int]
    probed_ports: frozenset[int]


def confidence(methods: Iterable[str], responded: bool) -> str:
    """high: dos o más pruebas de vida independientes; medium: una; low: sin respuesta."""
    if not responded:
        return "low"
    live = sum(1 for method in set(methods) if method in LIVENESS_METHODS)
    return "high" if live >= 2 else "medium"


def _item(field: str, value: Any, method: str, state: str = "observed") -> dict[str, Any]:
    return {"field": field, "value": value, "method": method, "state": state}


class ObservationRecorder:
    def __init__(
        self,
        session: Session,
        job: DiscoveryJob,
        site_id: int,
        executor: str,
        sensor_id: int | None,
    ) -> None:
        self._session = session
        self._job = job
        self._site_id = site_id
        self._executor = executor
        self._sensor_id = sensor_id
        self._addresses: set[str] = set()
        self._previous: dict[int, _Previous] = {}
        self.unresponsive = 0

    def load_previous(self, asset_ids: Sequence[int]) -> None:
        """Última observación (de otro job) de cada activo, en lotes y sin N+1."""
        unique = sorted(set(asset_ids))
        for start in range(0, len(unique), 5000):
            rows = self._session.execute(
                select(
                    DiscoveryObservation.asset_id,
                    DiscoveryObservation.address,
                    DiscoveryObservation.hostname,
                    DiscoveryObservation.open_ports,
                    DiscoveryObservation.reachability,
                    DiscoveryJob.parameters,
                )
                .join(DiscoveryJob, DiscoveryJob.id == DiscoveryObservation.job_id)
                .where(
                    DiscoveryObservation.asset_id.in_(unique[start : start + 5000]),
                    DiscoveryObservation.job_id != self._job.id,
                    DiscoveryObservation.reachability == "responded",
                )
                .ext(distinct_on(DiscoveryObservation.asset_id))
                .order_by(
                    DiscoveryObservation.asset_id,
                    DiscoveryObservation.observed_at.desc(),
                    DiscoveryObservation.id.desc(),
                )
            ).all()
            for row in rows:
                params = row.parameters or {}
                self._previous[int(row.asset_id)] = _Previous(
                    address=row.address,
                    hostname=row.hostname,
                    open_ports=frozenset(int(p) for p in row.open_ports or ()),
                    probed_ports=frozenset(int(p) for p in params.get("ports", [])),
                )

    def observed(
        self,
        obs: HostObservation,
        asset: Asset,
        created: bool,
        matched_by_mac: bool,
        now: datetime,
    ) -> None:
        if obs.address in self._addresses:
            return
        self._addresses.add(obs.address)
        methods = set(obs.sources) & set(LIVENESS_METHODS)
        if obs.reverse_dns:
            methods.add("dns")
        open_ports = obs.open_ports
        hostname = obs.reverse_dns or obs.mdns_name or obs.netbios_name
        evidence: list[dict[str, Any]] = [
            _item("reachability", "responded", method) for method in sorted(set(obs.sources))
        ]
        if obs.mac:
            evidence.append(_item("mac", obs.mac, "arp"))
        if obs.reverse_dns:
            evidence.append(_item("hostname", obs.reverse_dns, "reverse_dns"))
        if obs.forward_dns_match is not None:
            evidence.append(_item("forward_dns_match", obs.forward_dns_match, "dns"))
        if obs.mdns_name:
            evidence.append(_item("hostname", obs.mdns_name, "mdns"))
        if obs.netbios_name:
            evidence.append(_item("hostname", obs.netbios_name, "netbios"))
        if obs.rtt_ms is not None:
            evidence.append(_item("rtt_ms", obs.rtt_ms, "tcp"))
        self._add(
            asset=asset,
            address=obs.address,
            mac=obs.mac,
            hostname=hostname,
            reverse_dns=obs.reverse_dns,
            forward_dns_match=obs.forward_dns_match,
            open_ports=open_ports,
            methods=sorted(methods),
            reachability="responded",
            rtt_ms=obs.rtt_ms,
            confidence=confidence(methods, True),
            evidence=evidence,
            changes=self._changes(obs, asset, created, matched_by_mac),
            now=now,
        )

    def unanswered(self, asset: Asset, now: datetime) -> None:
        """Activo conocido de la red que no respondió en un scan completo."""
        address = asset.primary_ip
        if address in self._addresses:
            return
        self._addresses.add(address)
        self.unresponsive += 1
        self._add(
            asset=asset,
            address=address,
            mac=None,
            hostname=None,
            reverse_dns=None,
            forward_dns_match=None,
            open_ports=[],
            methods=[],
            reachability="no_response",
            rtt_ms=None,
            confidence="low",
            evidence=[_item("reachability", "no_response", "scan")],
            # Observado: sondeado y sin respuesta. Que el equipo ya no exista sería una
            # inferencia que aquí NO se hace (la decide la política de ciclo de vida).
            changes=[
                {
                    "kind": "host_unresponsive",
                    "previous": "responded",
                    "current": "no_response",
                    "state": "observed",
                }
            ],
            now=now,
        )

    # --- internos --------------------------------------------------------------------------

    def _changes(
        self, obs: HostObservation, asset: Asset, created: bool, matched_by_mac: bool
    ) -> list[dict[str, Any]]:
        if created:
            return [
                {"kind": "new_host", "previous": None, "current": obs.address, "state": "observed"}
            ]
        previous = self._previous.get(asset.id)
        if previous is None:
            return []
        changes: list[dict[str, Any]] = []
        if previous.address != obs.address and matched_by_mac:
            # Misma MAC en otra IP del mismo site: evidencia consistente de cambio de dirección
            # (DHCP). Sin MAC no se afirma: podría ser otro equipo en la IP antigua.
            changes.append(
                {
                    "kind": "address_changed",
                    "previous": previous.address,
                    "current": obs.address,
                    "state": "observed",
                }
            )
        name = obs.reverse_dns
        if name and previous.hostname and name.lower() != previous.hostname.lower():
            changes.append(
                {
                    "kind": "hostname_changed",
                    "previous": previous.hostname,
                    "current": name,
                    "state": "observed",
                }
            )
        for port in obs.open_ports:
            if port not in previous.open_ports and port in previous.probed_ports:
                changes.append(
                    {
                        "kind": "port_new",
                        "previous": None,
                        "current": str(port),
                        "state": "observed",
                    }
                )
        for port in sorted(previous.open_ports):
            state = obs.ports.get(port)
            if state is None or state == PortState.OPEN:
                continue
            # Un RST es una negativa observada; un timeout solo permite inferir (firewall,
            # pérdida de paquetes): la semántica de PORT_CLOSE_AFTER no cambia.
            changes.append(
                {
                    "kind": "port_unresponsive",
                    "previous": str(port),
                    "current": state.value,
                    "state": "observed" if state == PortState.CLOSED else "inferred",
                }
            )
        return changes

    def _add(
        self, *, asset: Asset, now: datetime, evidence: list[dict[str, Any]], **values: Any
    ) -> None:
        self._session.add(
            DiscoveryObservation(
                job_id=self._job.id,
                site_id=self._site_id,
                executor=self._executor,
                sensor_id=self._sensor_id,
                asset_id=asset.id,
                profile=self._job.profile,
                observed_at=now,
                evidence=evidence[:MAX_EVIDENCE],
                **values,
            )
        )

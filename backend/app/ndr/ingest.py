"""Ingesta de lotes NDR de los sensores (Fase 7E.1, POST /api/v1/sensor/ndr/batches).

Garantías:
- Autorización por lote: el sensor debe declarar la capacidad, tener una captura aprobada y
  habilitada que incluya ESA interfaz, estar activo y su site también. Si no, 403
  ndr_not_authorized y el sensor descarta el lote (no se guarda lo no autorizado).
- At-least-once sin duplicar: el recibo (sensor, batch_id) es único; un reenvío devuelve
  duplicate=true sin tocar nada. Los contadores de un flujo llegan acumulados por segmento y
  se fusionan con máximo, así que tampoco un segmento repetido o desordenado suma dos veces.
- Concurrencia: authenticate() bloquea la fila del sensor hasta el commit, así que los lotes
  de un mismo sensor se procesan de uno en uno y la fusión en Python no compite consigo misma.
- Reloj: las marcas del sensor se recortan a "ahora + desfase tolerado": un reloj adelantado
  no puede dejar flujos "en el futuro" que nunca caducarían.
"""

import hashlib
import json
import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import NdrNotAuthorizedError
from app.models.ndr import NdrBatch, NdrFlow, NdrProtocolObservation
from app.models.site import Sensor, Site
from app.ndr.config import capture_config, is_capable
from app.schemas.ndr import (
    NdrArpIn,
    NdrBatchAccepted,
    NdrBatchIn,
    NdrDhcpIn,
    NdrDnsIn,
    NdrFlowIn,
    NdrTlsIn,
)
from app.sensors.catalog import version_status

logger = logging.getLogger(__name__)

MAX_DNS_ANSWERS = 8
MAX_ARP_FRAME_MACS = 4
# Lo que se guarda de las estadísticas de la ventana (todas numéricas o enumeradas).
_STATS_KEYS = (
    "packets_seen",
    "packets_processed",
    "bytes_seen",
    "malformed",
    "truncated",
    "unsupported",
    "budget_dropped",
    "kernel_dropped",
    "interface_dropped",
    "flows_active",
    "flows_evicted",
    "flows_exported",
    "observations_overflow",
    "cpu_percent",
    "pps_budget",
    "capture_state",
    "degraded_reasons",
)


@dataclass
class IngestedBatch:
    """Lo que entró en este lote, ya validado y normalizado. Lo consumen los analizadores de
    7E.2+ dentro de la misma transacción (nunca vuelven a leer el cuerpo crudo)."""

    sensor: Sensor
    site: Site
    interface: str
    received_at: datetime
    flows: list[NdrFlowIn] = field(default_factory=list)
    arp: list[NdrArpIn] = field(default_factory=list)
    dns: list[NdrDnsIn] = field(default_factory=list)
    dhcp: list[NdrDhcpIn] = field(default_factory=list)
    tls: list[NdrTlsIn] = field(default_factory=list)


Analyzer = Callable[[Session, Settings, IngestedBatch], None]


def _key_hash(*parts: object) -> str:
    raw = json.dumps(parts, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def _union(first: Iterable[str], second: Iterable[str], limit: int) -> list[str]:
    out: list[str] = []
    for item in [*first, *second]:
        if item not in out:
            out.append(item)
        if len(out) >= limit:
            break
    return out


class NdrIngest:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        analyzers: Sequence[Analyzer] = (),
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._session = session
        self._settings = settings
        self._analyzers = analyzers
        self._now = now

    # --- autorización -----------------------------------------------------------------------

    def _authorize(self, sensor: Sensor, interface: str) -> Site:
        site = self._session.get(Site, sensor.site_id)
        config = capture_config(self._session, sensor.id)
        settings = self._settings
        reasons = []
        if not is_capable(sensor):
            reasons.append("capability")
        if config is None or not config.enabled or interface not in (config.interfaces or []):
            reasons.append("interface")
        if sensor.status != "active" or site is None or site.status != "active":
            reasons.append("status")
        if (
            version_status(
                sensor.sensor_version,
                settings.sensor_min_version,
                settings.sensor_recommended_version,
            )
            == "unsupported"
        ):
            reasons.append("version")
        if reasons or site is None:
            logger.info(
                "ndr batch rejected",
                extra={"sensor": str(sensor.public_id), "reasons": reasons},
            )
            raise NdrNotAuthorizedError("NDR capture is not authorized for this interface")
        return site

    # --- entrada ----------------------------------------------------------------------------

    def process(self, sensor: Sensor, body: NdrBatchIn) -> NdrBatchAccepted:
        site = self._authorize(sensor, body.interface)
        now = self._now()
        limit = now + timedelta(seconds=self._settings.sensor_max_clock_skew_seconds)
        observations = len(body.arp) + len(body.dns) + len(body.dhcp) + len(body.tls)
        receipt = self._session.execute(
            pg_insert(NdrBatch)
            .values(
                batch_id=body.batch_id,
                sensor_id=sensor.id,
                site_id=site.id,
                interface=body.interface,
                config_revision=body.config_revision,
                backend=body.backend,
                window_start=min(body.window_start, limit),
                window_end=min(body.window_end, limit),
                received_at=now,
                part=body.part,
                parts=body.parts,
                flows=len(body.flows),
                observations=observations,
                stats=self._stats(body),
            )
            .on_conflict_do_nothing(constraint="uq_ndr_batches_sensor_batch")
            .returning(NdrBatch.id)
        ).scalar_one_or_none()
        if receipt is None:
            # Reenvío de un lote ya guardado (el sensor no recibió la respuesta): nada que hacer.
            self._session.commit()
            return NdrBatchAccepted(batch_id=body.batch_id, duplicate=True, flows=0, observations=0)
        batch = IngestedBatch(sensor, site, body.interface, now)
        batch.flows = [self._clamp(f, limit) for f in body.flows]
        batch.arp = [self._clamp(o, limit) for o in body.arp]
        batch.dns = [self._clamp(o, limit) for o in body.dns]
        batch.dhcp = [self._clamp(o, limit) for o in body.dhcp]
        batch.tls = [self._clamp(o, limit) for o in body.tls]
        self._store_flows(batch)
        self._store_observations(batch)
        for analyzer in self._analyzers:
            analyzer(self._session, self._settings, batch)
        self._session.commit()
        return NdrBatchAccepted(
            batch_id=body.batch_id,
            duplicate=False,
            flows=len(body.flows),
            observations=observations,
        )

    @staticmethod
    def _clamp[T: (NdrFlowIn, NdrArpIn, NdrDnsIn, NdrDhcpIn, NdrTlsIn)](
        item: T, limit: datetime
    ) -> T:
        if item.last_seen <= limit and item.first_seen <= limit:
            return item
        return item.model_copy(
            update={
                "first_seen": min(item.first_seen, limit),
                "last_seen": min(item.last_seen, limit),
            }
        )

    @staticmethod
    def _stats(body: NdrBatchIn) -> dict[str, Any] | None:
        if body.stats is None:
            return None
        raw = body.stats.model_dump(mode="json")
        return {key: raw[key] for key in _STATS_KEYS if key in raw}

    # --- flujos -----------------------------------------------------------------------------

    def _store_flows(self, batch: IngestedBatch) -> None:
        if not batch.flows:
            return
        merged: dict[str, NdrFlowIn] = {}
        for flow in batch.flows:
            current = merged.get(flow.uid)
            merged[flow.uid] = flow if current is None else _newer_flow(current, flow)
        existing = {
            row.uid: row
            for row in self._session.scalars(
                select(NdrFlow).where(
                    NdrFlow.sensor_id == batch.sensor.id, NdrFlow.uid.in_(list(merged))
                )
            )
        }
        new_rows: list[dict[str, Any]] = []
        for uid, flow in merged.items():
            row = existing.get(uid)
            if row is None:
                new_rows.append(self._flow_values(batch, flow))
            else:
                _merge_flow(row, flow, batch.received_at)
        if new_rows:
            self._session.execute(insert(NdrFlow), new_rows)

    @staticmethod
    def _flow_values(batch: IngestedBatch, flow: NdrFlowIn) -> dict[str, Any]:
        return {
            "sensor_id": batch.sensor.id,
            "site_id": batch.site.id,
            "interface": batch.interface,
            "uid": flow.uid,
            "ip_version": flow.ip_version,
            "transport": flow.transport,
            "src_ip": flow.src_ip,
            "src_port": flow.src_port,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "vlan": flow.vlan,
            "src_mac": flow.src_mac,
            "dst_mac": flow.dst_mac,
            "first_seen": flow.first_seen,
            "last_seen": flow.last_seen,
            "packets_out": flow.packets_out,
            "packets_in": flow.packets_in,
            "bytes_out": flow.bytes_out,
            "bytes_in": flow.bytes_in,
            "tcp_flags_out": flow.tcp_flags_out,
            "tcp_flags_in": flow.tcp_flags_in,
            "state": flow.state,
            "final": flow.final,
            "segments": flow.segment + 1,
            "flags": sorted(set(flow.flags)),
            "retransmissions": flow.retransmissions,
            "fragments": flow.fragments,
            "icmp_type": flow.icmp_type,
            "app_hints": sorted(set(flow.app_hints)),
            "updated_at": batch.received_at,
        }

    # --- metadatos de protocolo -------------------------------------------------------------

    def _store_observations(self, batch: IngestedBatch) -> None:
        entries: dict[tuple[str, str], dict[str, Any]] = {}
        for kind, values in (
            ("arp", (_arp_values(o) for o in batch.arp)),
            ("dns", (_dns_values(o) for o in batch.dns)),
            ("dhcp", (_dhcp_values(o) for o in batch.dhcp)),
            ("tls", (_tls_values(o) for o in batch.tls)),
        ):
            for value in values:
                key = (kind, value["key_hash"])
                current = entries.get(key)
                entries[key] = value if current is None else _merge_values(kind, current, value)
        if not entries:
            return
        existing = {
            (row.kind, row.key_hash): row
            for row in self._session.scalars(
                select(NdrProtocolObservation).where(
                    NdrProtocolObservation.sensor_id == batch.sensor.id,
                    NdrProtocolObservation.key_hash.in_([k[1] for k in entries]),
                )
            )
        }
        new_rows: list[dict[str, Any]] = []
        for (kind, key_hash), value in entries.items():
            row = existing.get((kind, key_hash))
            if row is None:
                new_rows.append(
                    {
                        **value,
                        "kind": kind,
                        "sensor_id": batch.sensor.id,
                        "site_id": batch.site.id,
                        "interface": batch.interface,
                    }
                )
                continue
            merged = _merge_values(
                kind,
                {
                    "count": row.count,
                    "first_seen": row.first_seen,
                    "last_seen": row.last_seen,
                    "data": dict(row.data or {}),
                },
                value,
            )
            row.count = merged["count"]
            row.first_seen = merged["first_seen"]
            row.last_seen = merged["last_seen"]
            row.data = merged["data"]
        if new_rows:
            self._session.execute(insert(NdrProtocolObservation), new_rows)


# --- fusión -----------------------------------------------------------------------------------


def _newer_flow(first: NdrFlowIn, second: NdrFlowIn) -> NdrFlowIn:
    """Dos segmentos del mismo flujo en un lote: el de contadores mayores manda; las banderas
    y pistas se unen."""
    newer, older = (second, first) if second.segment >= first.segment else (first, second)
    return newer.model_copy(
        update={
            "flags": sorted(set(newer.flags) | set(older.flags)),
            "app_hints": sorted(set(newer.app_hints) | set(older.app_hints)),
            "first_seen": min(newer.first_seen, older.first_seen),
            "final": newer.final or older.final,
        }
    )


def _merge_flow(row: NdrFlow, flow: NdrFlowIn, now: datetime) -> None:
    newer = flow.last_seen >= row.last_seen
    row.first_seen = min(row.first_seen, flow.first_seen)
    row.last_seen = max(row.last_seen, flow.last_seen)
    row.packets_out = max(row.packets_out, flow.packets_out)
    row.packets_in = max(row.packets_in, flow.packets_in)
    row.bytes_out = max(row.bytes_out, flow.bytes_out)
    row.bytes_in = max(row.bytes_in, flow.bytes_in)
    row.tcp_flags_out |= flow.tcp_flags_out
    row.tcp_flags_in |= flow.tcp_flags_in
    row.retransmissions = max(row.retransmissions, flow.retransmissions)
    row.fragments = max(row.fragments, flow.fragments)
    row.segments = max(row.segments, flow.segment + 1)
    row.flags = sorted(set(row.flags or []) | set(flow.flags))
    row.app_hints = sorted(set(row.app_hints or []) | set(flow.app_hints))
    row.final = row.final or flow.final
    if newer:
        row.state = flow.state
    row.src_mac = row.src_mac or flow.src_mac
    row.dst_mac = row.dst_mac or flow.dst_mac
    row.updated_at = now


def _base(item: NdrArpIn | NdrDnsIn | NdrDhcpIn | NdrTlsIn) -> dict[str, Any]:
    return {"count": item.count, "first_seen": item.first_seen, "last_seen": item.last_seen}


def _arp_values(item: NdrArpIn) -> dict[str, Any]:
    frame_macs = [item.eth_src_mac] if item.eth_src_mac else []
    return {
        **_base(item),
        "key_hash": _key_hash(
            item.operation, item.sender_ip, item.sender_mac, item.target_ip, item.vlan
        ),
        "ip": item.sender_ip,
        "peer_ip": item.target_ip,
        "mac": item.sender_mac,
        "name": None,
        "vlan": item.vlan,
        "data": {
            "operation": item.operation,
            "gratuitous": item.gratuitous,
            "unsolicited": item.unsolicited,
            "frame_macs": frame_macs,
        },
    }


def _dns_values(item: NdrDnsIn) -> dict[str, Any]:
    return {
        **_base(item),
        "key_hash": _key_hash(item.client_ip, item.resolver_ip, item.qname, item.qtype),
        "ip": item.client_ip,
        "peer_ip": item.resolver_ip,
        "mac": None,
        "name": item.qname,
        "vlan": item.vlan,
        "data": {
            "qtype": item.qtype,
            "queries": item.queries,
            "responses": item.responses,
            "rcodes": dict(item.rcodes),
            "answers": list(item.answers)[:MAX_DNS_ANSWERS],
            "min_ttl": item.min_ttl,
            "transport": item.transport,
        },
    }


def _dhcp_values(item: NdrDhcpIn) -> dict[str, Any]:
    return {
        **_base(item),
        "key_hash": _key_hash(
            item.message_type,
            item.client_mac,
            item.server_ip,
            item.your_ip,
            item.routers,
            item.dns_servers,
        ),
        "ip": item.your_ip,
        "peer_ip": item.server_ip,
        "mac": item.client_mac,
        "name": None,
        "vlan": item.vlan,
        "data": {
            "message_type": item.message_type,
            "server_mac": item.server_mac,
            "routers": list(item.routers),
            "dns_servers": list(item.dns_servers),
        },
    }


def _tls_values(item: NdrTlsIn) -> dict[str, Any]:
    return {
        **_base(item),
        "key_hash": _key_hash(item.client_ip, item.server_ip, item.server_port, item.sni),
        "ip": item.client_ip,
        "peer_ip": item.server_ip,
        "mac": None,
        "name": item.sni,
        "vlan": None,
        "data": {"server_port": item.server_port},
    }


def _merge_values(kind: str, current: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    out = dict(current)
    out["count"] = int(current["count"]) + int(new["count"])
    out["first_seen"] = min(current["first_seen"], new["first_seen"])
    out["last_seen"] = max(current["last_seen"], new["last_seen"])
    data = dict(current["data"])
    extra = new["data"]
    if kind == "arp":
        data["unsolicited"] = int(data.get("unsolicited", 0)) + int(extra.get("unsolicited", 0))
        data["gratuitous"] = bool(data.get("gratuitous")) or bool(extra.get("gratuitous"))
        data["frame_macs"] = _union(
            data.get("frame_macs", []), extra.get("frame_macs", []), MAX_ARP_FRAME_MACS
        )
    elif kind == "dns":
        data["queries"] = int(data.get("queries", 0)) + int(extra.get("queries", 0))
        data["responses"] = int(data.get("responses", 0)) + int(extra.get("responses", 0))
        rcodes = dict(data.get("rcodes", {}))
        for code, value in extra.get("rcodes", {}).items():
            rcodes[code] = int(rcodes.get(code, 0)) + int(value)
        data["rcodes"] = rcodes
        data["answers"] = _union(data.get("answers", []), extra.get("answers", []), MAX_DNS_ANSWERS)
        ttls = [t for t in (data.get("min_ttl"), extra.get("min_ttl")) if t is not None]
        data["min_ttl"] = min(ttls) if ttls else None
    elif kind == "dhcp":
        data["server_mac"] = data.get("server_mac") or extra.get("server_mac")
    out["data"] = data
    return out

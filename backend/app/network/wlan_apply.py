"""Aplicación del módulo SNMP `wlan` al inventario Wi-Fi (Fase 6C.3).

Se llama desde PollApplier (app/network/apply.py) al cerrar un job snmp_inventory, con los
registros ya validados por el esquema. Invariantes:

- Todo queda en el site del equipo consultado; las vinculaciones solo miran ese site.
- Un módulo wlan `partial` (o una fuente `partial`, o una consulta no completa: cancelada,
  con lotes perdidos o plazo agotado) solo aporta evidencia positiva. Únicamente una consulta
  completa con el módulo y la fuente `complete` marca como ausente lo que esa fuente de ese
  equipo dejó de informar. Un fallo nunca hace "desaparecer" un AP.
- Un dato que la fuente no da queda en None: no se rellena con suposiciones.
- Los BSS se comparten con lo que observan los agentes: el SNMP fija la identidad
  (`reported_by_device`) y no pisa la señal que solo da un agente.
"""

from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models.network import NetworkDevice, NetworkDevicePoll
from app.models.wlan import WlanAccessPoint, WlanBss, WlanClient, WlanConfiguredNetwork
from app.network import wlan_catalog as wc
from app.network.wlan_store import (
    Observations,
    add_source,
    assign,
    auto_link,
    correlate_client,
    ensure_rows,
)

MAX_RADIOS = 8


class WlanApplier:
    def __init__(
        self, session: Session, device: NetworkDevice, poll: NetworkDevicePoll, now: datetime
    ) -> None:
        self._session = session
        self._device = device
        self._poll = poll
        self._now = now
        self._observations: dict[str, Observations] = {}

    def _obs(self, source: str) -> Observations:
        if source not in self._observations:
            self._observations[source] = Observations(
                self._session,
                self._device.site_id,
                source,
                wc.REPORTED,
                self._now,
                self._now,
                poll_id=self._poll.id,
                sensor_id=self._poll.sensor_id,
                source_device_id=self._device.id,
            )
        return self._observations[source]

    def apply(
        self, by_kind: dict[str, list[dict[str, Any]]], module_status: str | None, full: bool
    ) -> dict[str, int]:
        if module_status not in ("complete", "partial"):
            return {}
        statuses = {r["source"]: r["status"] for r in by_kind.get("wlan_source", [])}

        def authoritative(adapter: str) -> bool:
            return full and module_status == "complete" and statuses.get(adapter) == "complete"

        if "ieee802dot11" in statuses:
            self._standalone(
                wc.SOURCE_DOT11, self._dot11_bss(by_kind.get("wlan_dot11_radio", [])), {}
            )
        if "unifi" in statuses:
            system = (by_kind.get("wlan_unifi_system") or [{}])[-1]
            self._standalone(wc.SOURCE_UNIFI, self._vap_bss(by_kind.get("wlan_vap", [])), system)
        if "airespace" in statuses:
            self._airespace(by_kind)
        for adapter, source in wc.SNMP_SOURCES.items():
            if authoritative(adapter):
                self._mark_absent(source)
        for recorder in self._observations.values():
            recorder.flush()
        return self._counts()

    # --- APs autónomos (IEEE802dot11-MIB, UniFi) -------------------------------------------

    def _dot11_bss(self, rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for row in rows:
            bssid = row.get("mac_address") or row.get("station_id")
            if row.get("bss_type") == 2:
                continue  # IBSS (ad hoc): no es un AP.
            channel = row.get("dsss_channel") or row.get("ofdm_channel")
            band = wc.dot11_band(row.get("phy_type"), channel)
            if row.get("dsss_channel") and band is None:
                band = "2.4"  # DSSS solo existe en 2,4 GHz.
            out.append(
                {
                    "bssid": bssid,
                    "slot": row["if_index"],
                    "ssid": row.get("ssid"),
                    "band": band,
                    "channel": channel,
                    "protection": wc.dot11_protection(
                        row.get("privacy_invoked"), row.get("rsna_enabled")
                    ),
                    "standard": wc.DOT11_PHY_STANDARD.get(row.get("phy_type") or 0),
                    "clients": None,
                }
            )
        return out

    def _vap_bss(self, rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for row in rows:
            band = wc.UNIFI_RADIO_BAND.get(str(row.get("radio") or "").lower())
            out.append(
                {
                    "bssid": row.get("bssid"),
                    "slot": row["vap_index"],
                    "ssid": row.get("ssid"),
                    "band": band,
                    "channel": row.get("channel"),
                    "protection": None,
                    "standard": None,
                    "clients": row.get("clients"),
                }
            )
        return out

    def _standalone(
        self, source: str, radios: list[dict[str, Any]], system: dict[str, Any]
    ) -> None:
        """El equipo consultado ES el AP: una fila con clave device:<uuid> y un BSS por radio
        o VAP con BSSID."""
        device = self._device
        bssids = sorted(r["bssid"] for r in radios if r.get("bssid"))
        values = {
            "name": device.name or device.sys_name,
            "vendor": wc.SOURCE_VENDOR.get(source) or device.vendor,
            "model": system.get("model") or device.model,
            "serial_number": device.serial_number,
            "firmware": system.get("firmware") or device.firmware,
            "location": device.sys_location,
            "management_ip": system.get("ip_address") or device.management_address,
            "ethernet_mac": device.base_bridge_address,
            "radio_mac": bssids[0] if bssids else None,
            # El AP respondió a SNMP en esta consulta: está operativo.
            "reported_status": "up",
            "radios": [
                {
                    "slot": r["slot"],
                    "band": r["band"],
                    "channel": r["channel"],
                    "ssid": r["ssid"],
                    "standard": r["standard"],
                    "clients": r["clients"],
                }
                for r in radios[:MAX_RADIOS]
            ]
            or None,
        }
        aps = self._upsert_aps(source, {f"device:{device.public_id}": values})
        ap = next(iter(aps.values()))
        self._upsert_bss(source, ap, [r for r in radios if r.get("bssid")])

    # --- controladora Cisco (AIRESPACE-WIRELESS-MIB) ----------------------------------------

    def _airespace(self, by_kind: dict[str, list[dict[str, Any]]]) -> None:
        source = wc.SOURCE_AIRESPACE
        radios: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in by_kind.get("wlan_controller_radio", []):
            if len(radios[row["ap_mac"]]) >= MAX_RADIOS:
                continue
            radios[row["ap_mac"]].append(
                {
                    "slot": row["slot"],
                    "band": wc.AIRESPACE_RADIO_BAND.get(row.get("radio_type") or 0),
                    "channel": row.get("channel"),
                    "status": wc.AIRESPACE_RADIO_STATUS.get(row.get("oper_status") or 0),
                    "clients": row.get("clients"),
                }
            )
        values: dict[str, dict[str, Any]] = {}
        for row in by_kind.get("wlan_controller_ap", []):
            ap_mac = row["ap_mac"]
            values[f"mac:{ap_mac}"] = {
                "name": row.get("name"),
                "vendor": wc.SOURCE_VENDOR[source],
                "model": row.get("model"),
                "serial_number": row.get("serial"),
                "firmware": row.get("software_version"),
                "location": row.get("location"),
                "management_ip": row.get("ip_address"),
                "ethernet_mac": row.get("ethernet_mac"),
                "radio_mac": ap_mac,
                "reported_status": wc.AIRESPACE_AP_STATUS.get(
                    row.get("operation_status") or 0, "unknown"
                ),
                "radios": sorted(radios.get(ap_mac, []), key=lambda r: r["slot"]) or None,
            }
        aps = self._upsert_aps(source, values)
        self._configured_networks(source, by_kind.get("wlan_ess", []))
        self._stations(source, by_kind.get("wlan_station", []), aps, radios)

    def _configured_networks(self, source: str, rows: Sequence[dict[str, Any]]) -> None:
        session, device = self._session, self._device
        existing = {
            row.network_key: row
            for row in session.scalars(
                select(WlanConfiguredNetwork).where(
                    WlanConfiguredNetwork.device_id == device.id,
                    WlanConfiguredNetwork.source == source,
                )
            )
        }
        for row in rows:
            key = str(row["ess_index"])
            network = existing.get(key)
            if network is None:
                network = WlanConfiguredNetwork(
                    site_id=device.site_id,
                    device_id=device.id,
                    source=source,
                    network_key=key,
                    first_seen_at=self._now,
                )
                session.add(network)
                existing[key] = network
            network.ssid = row.get("ssid")
            network.client_count = row.get("clients")
            network.present = True
            network.last_seen_at = self._now
            network.last_poll_id = self._poll.id
        session.flush()

    def _stations(
        self,
        source: str,
        rows: Sequence[dict[str, Any]],
        aps: dict[str, WlanAccessPoint],
        radios: dict[str, list[dict[str, Any]]],
    ) -> None:
        session, device = self._session, self._device
        defaults = {
            f"mac:{row['mac']}": {
                "mac": row["mac"],
                "mac_randomized": wc.mac_randomized(row["mac"]),
                "source": source,
                "identity_confidence": "observation_only",
                "first_seen_at": self._now,
                "last_seen_at": self._now,
            }
            for row in rows
        }
        clients, created = ensure_rows(
            session, WlanClient, "uq_wlan_clients_site_key", device.site_id, "client_key", defaults
        )
        cache: dict[str, int | None] = {}
        obs = self._obs(source)
        for row in rows:
            key = f"mac:{row['mac']}"
            client = clients[key]
            ap = aps.get(f"mac:{row['ap_mac']}") if row.get("ap_mac") else None
            standard, band = wc.AIRESPACE_STATION_PROTOCOL.get(
                row.get("protocol") or 0, (None, None)
            )
            if band is None and ap is not None and row.get("slot") is not None:
                radio = next(
                    (r for r in radios.get(row["ap_mac"], []) if r["slot"] == row["slot"]), None
                )
                band = radio["band"] if radio is not None else None
            values: dict[str, Any] = {
                "mac": row["mac"],
                "mac_randomized": wc.mac_randomized(row["mac"]),
                "ssid": row.get("ssid"),
                "access_point_id": ap.id if ap is not None else None,
                "radio_slot": row.get("slot"),
                "band": band,
                "standard": standard,
                "state": wc.AIRESPACE_STATION_STATE.get(row["status"], "unknown")
                if row.get("status") is not None
                else "unknown",
                "present": True,
            }
            # La controladora no da el BSSID del cliente: se conserva el que haya informado
            # un agente, si lo hay, en lugar de inventar uno a partir del AP.
            if client.identity_confidence != "confirmed":
                asset_id = correlate_client(session, device.site_id, row["mac"], cache)
                values["asset_id"] = asset_id
                values["identity_confidence"] = "probable" if asset_id else "observation_only"
                values["correlation_basis"] = "mac_match" if asset_id else None
            changed = assign(client, values) or key in created
            client.source = source
            client.source_device_id = device.id
            client.sensor_id = self._poll.sensor_id
            client.last_seen_at = self._now
            client.last_poll_id = self._poll.id
            obs.add(
                "client",
                client.id,
                {
                    "state": client.state,
                    "ssid": client.ssid,
                    "band": client.band,
                    "access_point": str(ap.public_id) if ap is not None else None,
                    "radio_slot": client.radio_slot,
                },
                changed,
            )
        session.flush()

    # --- comunes ---------------------------------------------------------------------------

    def _upsert_aps(
        self, source: str, values: dict[str, dict[str, Any]]
    ) -> dict[str, WlanAccessPoint]:
        session, device = self._session, self._device
        defaults = {
            key: {
                "source": source,
                "first_seen_at": self._now,
                "last_seen_at": self._now,
            }
            for key in values
        }
        aps, created = ensure_rows(
            session,
            WlanAccessPoint,
            "uq_wlan_access_points_site_key",
            device.site_id,
            "ap_key",
            defaults,
        )
        obs = self._obs(source)
        for key, data in values.items():
            ap = aps[key]
            changed = assign(ap, {**data, "present": True}) or key in created
            ap.source = source
            ap.confidence = wc.REPORTED
            ap.source_device_id = device.id
            ap.sensor_id = self._poll.sensor_id
            ap.last_seen_at = self._now
            ap.last_poll_id = self._poll.id
            auto_link(session, ap, self._now)
            obs.add(
                "access_point",
                ap.id,
                {
                    "name": ap.name,
                    "status": ap.reported_status,
                    "management_ip": ap.management_ip,
                    "firmware": ap.firmware,
                    "radios": len(ap.radios or []),
                },
                changed,
            )
        session.flush()
        return aps

    def _upsert_bss(
        self, source: str, ap: WlanAccessPoint, radios: Sequence[dict[str, Any]]
    ) -> None:
        session, device = self._session, self._device
        defaults = {
            r["bssid"]: {
                "source": source,
                "confidence": wc.REPORTED,
                "first_seen_at": self._now,
                "last_seen_at": self._now,
            }
            for r in radios
        }
        rows, created = ensure_rows(
            session, WlanBss, "uq_wlan_bss_site_bssid", device.site_id, "bssid", defaults
        )
        obs = self._obs(source)
        for radio in radios:
            bss = rows[radio["bssid"]]
            values: dict[str, Any] = {
                "ssid": radio["ssid"],
                "band": radio["band"],
                "channel": radio["channel"],
                "frequency_mhz": wc.frequency_from_channel(radio["band"], radio["channel"]),
                "standard": radio["standard"],
                "client_count": radio["clients"],
                "access_point_id": ap.id,
                "present": True,
            }
            # La protección que da la MIB estándar es gruesa (rsn/legacy): si un agente ya la
            # precisó (wpa2, wpa3...) no se degrada; UniFi no la da (None no pisa nada).
            protection = radio["protection"]
            if protection is not None and (
                bss.protection is None
                or bss.protection in ("rsn", "legacy", "unknown")
                or protection == "open"
            ):
                values["protection"] = protection
            changed = assign(bss, values) or radio["bssid"] in created
            add_source(bss, source)
            bss.source = source
            bss.confidence = wc.REPORTED
            bss.source_device_id = device.id
            bss.sensor_id = self._poll.sensor_id
            bss.last_snmp_seen_at = self._now
            bss.last_seen_at = max(bss.last_seen_at, self._now)
            bss.last_poll_id = self._poll.id
            obs.add(
                "bss",
                bss.id,
                {
                    "ssid": bss.ssid,
                    "band": bss.band,
                    "channel": bss.channel,
                    "protection": bss.protection,
                    "clients": bss.client_count,
                },
                changed,
            )
        session.flush()

    def _mark_absent(self, source: str) -> None:
        """present=false para lo que ESTA fuente de ESTE equipo ya no informa (consulta
        completa). No borra historial ni toca lo informado por otros equipos o agentes."""
        session, device, poll_id = self._session, self._device, self._poll.id

        def stale(model: Any) -> Any:
            return (
                (model.source_device_id == device.id)
                & model.present.is_(True)
                & ((model.last_poll_id.is_(None)) | (model.last_poll_id != poll_id))
            )

        statements = [
            update(WlanAccessPoint).where(stale(WlanAccessPoint), WlanAccessPoint.source == source),
            # Un agente puede haber sido la última fuente del BSS: se mira el conjunto de
            # fuentes, no solo la última.
            update(WlanBss).where(stale(WlanBss), WlanBss.sources.contains([source])),
        ]
        if source == wc.SOURCE_AIRESPACE:
            statements.append(update(WlanClient).where(stale(WlanClient)))
            statements.append(
                update(WlanConfiguredNetwork).where(
                    WlanConfiguredNetwork.device_id == device.id,
                    WlanConfiguredNetwork.source == source,
                    WlanConfiguredNetwork.present.is_(True),
                    (WlanConfiguredNetwork.last_poll_id.is_(None))
                    | (WlanConfiguredNetwork.last_poll_id != poll_id),
                )
            )
        for stmt in statements:
            session.execute(stmt.values(present=False).execution_options(synchronize_session=False))

    def _counts(self) -> dict[str, int]:
        session, device = self._session, self._device

        def count(model: Any) -> int:
            return int(
                session.scalar(
                    select(func.count())
                    .select_from(model)
                    .where(model.source_device_id == device.id, model.present)
                )
                or 0
            )

        return {
            "wlan_access_points": count(WlanAccessPoint),
            "wlan_bss": count(WlanBss),
            "wlan_clients": count(WlanClient),
        }

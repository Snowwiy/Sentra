"""Ingesta del campo `wireless` del inventario de un agente (Fase 6C.3).

Lo que ve un agente es una observación pasiva de su sistema operativo (system_profiler,
netsh, nmcli): redes cercanas y la conexión propia. Reglas:

- Todo queda en el site del activo del agente; nunca se cruza con otro site.
- Confianza `observed`: un agente que ve un BSSID no prueba que el AP sea de la organización,
  así que nunca crea APs ni los marca como autorizados. Solo crea o actualiza BSS (si hay
  BSSID) y no pisa los datos de identidad que da la infraestructura SNMP.
- Nunca marca ausencias de redes: una exploración de radio siempre es parcial. La frescura
  se deriva al leer de `last_agent_seen_at`. Lo único que el agente sabe con autoridad es su
  propia conexión: con `status=ok`, una conexión propia que ya no informa deja de estar
  presente.
- Con un estado distinto de ok (sin adaptador, permisos limitados, error...) se registra el
  estado para los indicadores de disponibilidad y se aceptan como evidencia positiva las
  redes que vengan, sin deducir nada de las que falten.
- Un BSS duplicado en el mismo informe se cuenta una vez (gana el conectado o el de más señal).
"""

from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.wlan import WlanAgentReport, WlanBss, WlanClient
from app.network import wlan_catalog as wc
from app.network.wlan_store import Observations, add_source, assign, ensure_rows
from app.schemas.wlan import WirelessNetwork, WirelessReport


def _better(a: WirelessNetwork, b: WirelessNetwork) -> WirelessNetwork:
    if a.connected != b.connected:
        return a if a.connected else b
    return a if (a.signal_dbm or -999) >= (b.signal_dbm or -999) else b


def _band(network: WirelessNetwork) -> str | None:
    return network.band or wc.band_from_frequency(network.frequency_mhz)


def ingest_agent_wireless(
    session: Session, asset: Asset, report: WirelessReport, now: datetime
) -> None:
    observed_at = min(report.collected_at, now)
    previous = session.get(WlanAgentReport, asset.id)
    if previous is not None and previous.collected_at > observed_at:
        # Informe retrasado (p. ej. reenviado tras un corte): más antiguo que lo que ya se
        # tiene, no sustituye el estado ni el "visto por última vez" de nada.
        return
    networks: dict[str, WirelessNetwork] = {}
    without_bssid = 0
    for network in report.networks:
        if network.bssid is None:
            without_bssid += 1
            continue
        current = networks.get(network.bssid)
        networks[network.bssid] = network if current is None else _better(current, network)
    _store_report(session, asset, report, observed_at, now, len(report.networks), without_bssid)
    obs = Observations(
        session,
        asset.site_id,
        wc.SOURCE_AGENT,
        wc.OBSERVED,
        observed_at,
        now,
        agent_asset_id=asset.id,
    )
    bss_rows = _upsert_bss(session, asset, networks, observed_at, obs)
    _own_connections(session, asset, report, bss_rows, observed_at, obs)
    obs.flush()


def _store_report(
    session: Session,
    asset: Asset,
    report: WirelessReport,
    observed_at: datetime,
    now: datetime,
    total: int,
    without_bssid: int,
) -> None:
    interfaces = [
        {
            "name": item.name,
            "mac": item.mac,
            "mac_randomized": wc.mac_randomized(item.mac),
            "connected_ssid": item.connected_ssid,
            "connected_bssid": item.connected_bssid,
        }
        for item in report.interfaces
    ]
    values = {
        "asset_id": asset.id,
        "site_id": asset.site_id,
        "status": report.status,
        "source": report.source,
        "collected_at": observed_at,
        "received_at": now,
        "interfaces": interfaces,
        "networks_reported": total,
        "networks_without_bssid": without_bssid,
    }
    stmt = insert(WlanAgentReport).values(values)
    session.execute(
        stmt.on_conflict_do_update(
            index_elements=[WlanAgentReport.asset_id],
            set_={k: stmt.excluded[k] for k in values if k != "asset_id"},
            where=stmt.excluded.collected_at >= WlanAgentReport.collected_at,
        )
    )


def _upsert_bss(
    session: Session,
    asset: Asset,
    networks: dict[str, WirelessNetwork],
    observed_at: datetime,
    obs: Observations,
) -> dict[str, WlanBss]:
    defaults = {
        bssid: {
            "source": wc.SOURCE_AGENT,
            "confidence": wc.OBSERVED,
            "first_seen_at": observed_at,
            "last_seen_at": observed_at,
        }
        for bssid in networks
    }
    rows, created = ensure_rows(
        session, WlanBss, "uq_wlan_bss_site_bssid", asset.site_id, "bssid", defaults
    )
    for bssid, network in networks.items():
        bss = rows[bssid]
        band = _band(network)
        protection = wc.normalize_security(network.security)
        frequency = network.frequency_mhz or wc.frequency_from_channel(band, network.channel)
        infra = bss.last_snmp_seen_at is not None
        values: dict[str, Any] = {
            "signal_dbm": network.signal_dbm,
            "signal_quality": network.signal_quality,
        }
        # Identidad y radio: si la infraestructura ya lo informa, el agente solo rellena lo
        # que falte; si no, su observación es la única evidencia y se actualiza.
        candidates = {
            "ssid": network.ssid,
            "band": band,
            "channel": network.channel,
            "frequency_mhz": frequency,
            "standard": wc.normalize_standard(network.phy_mode),
        }
        for name, value in candidates.items():
            if value is not None and (not infra or getattr(bss, name) is None):
                values[name] = value
        if network.security is not None:
            values["protection_reported"] = network.security
            if protection is not None and (
                not infra or bss.protection in (None, "rsn", "legacy", "unknown")
            ):
                values["protection"] = protection
        changed = assign(bss, {k: v for k, v in values.items() if not k.startswith("signal")})
        assign(bss, {k: v for k, v in values.items() if k.startswith("signal")})
        add_source(bss, wc.SOURCE_AGENT)
        if not infra:
            bss.confidence = wc.OBSERVED
        bss.source = wc.SOURCE_AGENT
        bss.last_agent_asset_id = asset.id
        bss.last_agent_seen_at = observed_at
        bss.last_seen_at = max(bss.last_seen_at, observed_at)
        obs.add(
            "bss",
            bss.id,
            {
                "ssid": bss.ssid,
                "band": bss.band,
                "channel": bss.channel,
                "protection": bss.protection,
                "signal_dbm": network.signal_dbm,
                "signal_quality": network.signal_quality,
                "connected": network.connected,
            },
            changed or bssid in created,
        )
    session.flush()
    return rows


def _own_connections(
    session: Session,
    asset: Asset,
    report: WirelessReport,
    bss_rows: dict[str, WlanBss],
    observed_at: datetime,
    obs: Observations,
) -> None:
    """La conexión propia del agente: el activo es un cliente CONFIRMADO de ese BSS."""
    connected = [i for i in report.interfaces if i.connected_bssid or i.connected_ssid]
    defaults: dict[str, dict[str, Any]] = {}
    keyed: list[tuple[str, Any]] = []
    for interface in connected:
        if interface.mac is not None and not wc.mac_randomized(interface.mac):
            key = f"mac:{interface.mac}"
        else:
            # Con MAC aleatoria (por red) la identidad es el activo, no la MAC.
            key = f"asset:{asset.public_id}:{interface.name}"
        keyed.append((key, interface))
        defaults[key] = {
            "mac": interface.mac,
            "mac_randomized": wc.mac_randomized(interface.mac),
            "source": wc.SOURCE_AGENT,
            "identity_confidence": "confirmed",
            "first_seen_at": observed_at,
            "last_seen_at": observed_at,
        }
    clients, created = ensure_rows(
        session, WlanClient, "uq_wlan_clients_site_key", asset.site_id, "client_key", defaults
    )
    missing = [i.connected_bssid for i in connected if i.connected_bssid not in bss_rows]
    if missing:
        bss_rows = {
            **bss_rows,
            **{
                row.bssid: row
                for row in session.scalars(
                    select(WlanBss).where(
                        WlanBss.site_id == asset.site_id,
                        WlanBss.bssid.in_([m for m in missing if m]),
                    )
                )
            },
        }
    seen_ids: list[int] = []
    for key, interface in keyed:
        client = clients[key]
        bss = bss_rows.get(interface.connected_bssid or "")
        values = {
            "mac": interface.mac,
            "mac_randomized": wc.mac_randomized(interface.mac),
            "bssid": interface.connected_bssid,
            "ssid": interface.connected_ssid,
            "access_point_id": bss.access_point_id if bss is not None else None,
            "band": bss.band if bss is not None else None,
            "state": "connected",
            "identity_confidence": "confirmed",
            "asset_id": asset.id,
            "correlation_basis": "agent_self",
            "present": True,
        }
        changed = assign(client, values) or key in created
        client.source = wc.SOURCE_AGENT
        client.last_seen_at = max(client.last_seen_at, observed_at)
        seen_ids.append(client.id)
        obs.add(
            "client",
            client.id,
            {"state": "connected", "ssid": client.ssid, "bssid": client.bssid},
            changed,
        )
        if interface.mac is not None and wc.mac_randomized(interface.mac):
            _attribute_random_mac(session, asset, interface.mac)
    if report.status == "ok":
        # Autoridad sobre sí mismo: una conexión propia que ya no aparece deja de estar
        # presente (no se borra; su historial se conserva).
        session.execute(
            update(WlanClient)
            .where(
                WlanClient.site_id == asset.site_id,
                WlanClient.asset_id == asset.id,
                WlanClient.correlation_basis == "agent_self",
                WlanClient.present.is_(True),
                WlanClient.id.not_in(seen_ids or [-1]),
            )
            .values(present=False, state="disassociated")
            .execution_options(synchronize_session=False)
        )
    session.flush()


def _attribute_random_mac(session: Session, asset: Asset, mac: str) -> None:
    """La controladora ve el cliente con la MAC aleatoria que el agente dice usar: esa
    coincidencia, dentro del mismo site, es evidencia probable (no confirmada: otra máquina
    podría usar la misma MAC aleatoria) de que esa fila es este activo."""
    session.execute(
        update(WlanClient)
        .where(
            WlanClient.site_id == asset.site_id,
            WlanClient.client_key == f"mac:{mac}",
            WlanClient.identity_confidence == "observation_only",
        )
        .values(
            asset_id=asset.id,
            identity_confidence="probable",
            correlation_basis="agent_reported_mac",
        )
        .execution_options(synchronize_session=False)
    )

"""Módulo SNMP `wlan` (Fase 6C.3): puntos de acceso, BSS, WLANs y clientes inalámbricos.

Adaptadores desacoplados, uno por MIB, que declaran lo que de verdad saben leer:
- `ieee802dot11`: IEEE802dot11-MIB (estándar). Un AP autónomo que la implementa informa de
  cada radio (ifIndex): BSSID, SSID, cifrado (privacy/RSNA), tipo de PHY y canal.
- `airespace`: AIRESPACE-WIRELESS-MIB de las controladoras Cisco (AireOS): APs asociados a la
  controladora, sus radios, las WLANs (SSID y clientes) y los clientes asociados.
- `unifi`: UBNT-UniFi-MIB de los APs UniFi: modelo y firmware del AP y sus VAPs (BSSID, SSID,
  canal, banda y clientes).

Cada adaptador comprueba primero una columna clave y, si el equipo no la tiene (no implementa
la MIB o la vista SNMP del usuario no la incluye), es `unsupported`: no es un error y no se
pide nada más. Solo GET/GETBULK de lectura sobre columnas del catálogo cerrado.

El sensor no interpreta: entrega los valores normalizados de la MIB (enteros de la MIB, MAC e
IP canónicas, texto saneado). Banda, protección o estándar los decide el servidor, que conoce
el significado de cada valor por fuente. Un dato que el equipo no da se omite (None), nunca
se inventa. Minimización: de los clientes no se leen ni el nombre de usuario ni la IP.
"""

from collections.abc import Callable

from sentra_sensor.snmp import catalog, values
from sentra_sensor.snmp.mibs import MAX_INDEX, ModuleResult, Record
from sentra_sensor.snmp.transport import Value
from sentra_sensor.snmp.walker import Column, Walker, rows_by_index

# Topes por adaptador además del de filas por tabla del job: un AP o una controladora con
# valores absurdos no puede convertir el módulo en un volcado masivo.
MAX_DOT11_RADIOS = 64
MAX_CONTROLLER_APS = 4096
MAX_RADIOS_PER_AP = 8
MAX_ESS = 512
MAX_VAPS = 128
_SSID_LIMIT = 64

AdapterResult = tuple[str, list[Record]]


def _clean(record: Record) -> Record:
    return {k: v for k, v in record.items() if v is not None}


def _status(columns: list[Column]) -> str:
    if any(c.truncated or c.malformed for c in columns):
        return "partial"
    return "complete"


def _mac_index(index: tuple[int, ...]) -> str | None:
    return values.mac_from_index(index[:6]) if len(index) >= 6 else None


def _truth(value: Value) -> int | None:
    # TruthValue: true(1), false(2).
    return values.integer(value, 1, 2)


# --- IEEE802dot11-MIB ------------------------------------------------------------------------


def dot11(walker: Walker) -> AdapterResult:
    station = walker.table(catalog.DOT11_STATION_CONFIG, catalog.DOT11_STATION_COLUMNS)
    if not any(c.exists for c in station.values()):
        return "unsupported", []
    privacy = walker.table(catalog.DOT11_PRIVACY, catalog.DOT11_PRIVACY_COLUMNS)
    operation = walker.table(catalog.DOT11_OPERATION, catalog.DOT11_OPERATION_COLUMNS)
    phy = walker.table(catalog.DOT11_PHY_OPERATION, catalog.DOT11_PHY_OPERATION_COLUMNS)
    dsss = walker.column((*catalog.DOT11_PHY_DSSS, 1))
    ofdm = walker.column((*catalog.DOT11_PHY_OFDM, 1))
    merged: dict[tuple[int, ...], dict[str, Value]] = {}
    for table in (station, privacy, operation, phy):
        for index, row in rows_by_index(table).items():
            merged.setdefault(index, {}).update(row)
    for name, column in (("dsss_channel", dsss), ("ofdm_channel", ofdm)):
        for index, value in column.rows.items():
            merged.setdefault(index, {})[name] = value
    records: list[Record] = []
    for index, row in sorted(merged.items())[:MAX_DOT11_RADIOS]:
        if len(index) != 1 or not 1 <= index[0] <= MAX_INDEX:
            continue
        records.append(
            _clean(
                {
                    "kind": "wlan_dot11_radio",
                    "if_index": index[0],
                    "station_id": values.mac(row.get("station_id")),
                    "mac_address": values.mac(row.get("mac_address")),
                    "ssid": values.text(row.get("desired_ssid"), _SSID_LIMIT),
                    "bss_type": values.integer(row.get("bss_type"), 1, 3),
                    "privacy_invoked": _truth(row.get("privacy_invoked")),
                    "exclude_unencrypted": _truth(row.get("exclude_unencrypted")),
                    "rsna_enabled": _truth(row.get("rsna_enabled")),
                    "phy_type": values.integer(row.get("phy_type"), 1, 255),
                    "dsss_channel": values.integer(row.get("dsss_channel"), 1, 14),
                    "ofdm_channel": values.integer(row.get("ofdm_channel"), 1, 255),
                }
            )
        )
    columns = [*station.values(), *privacy.values(), *operation.values(), *phy.values()]
    truncated = len(merged) > MAX_DOT11_RADIOS
    status = "partial" if truncated else _status([*columns, dsss, ofdm])
    return status, records


# --- AIRESPACE-WIRELESS-MIB ------------------------------------------------------------------


def airespace(walker: Walker) -> AdapterResult:
    names = walker.column((*catalog.BSN_AP, catalog.BSN_AP_COLUMNS["name"]))
    if not names.exists:
        return "unsupported", []
    aps = {"name": names}
    for column, number in catalog.BSN_AP_COLUMNS.items():
        if column != "name":
            aps[column] = walker.column((*catalog.BSN_AP, number))
    radios = walker.table(catalog.BSN_AP_IF, catalog.BSN_AP_IF_COLUMNS)
    ess = walker.table(catalog.BSN_ESS, catalog.BSN_ESS_COLUMNS)
    stations = walker.table(catalog.BSN_STATION, catalog.BSN_STATION_COLUMNS)
    records: list[Record] = []
    truncated = False
    ap_rows = sorted(rows_by_index(aps).items())
    if len(ap_rows) > MAX_CONTROLLER_APS:
        truncated = True
    for index, row in ap_rows[:MAX_CONTROLLER_APS]:
        ap_mac = _mac_index(index) if len(index) == 6 else None
        if ap_mac is None:
            continue
        raw_ip = row.get("ip_address")
        ip = values.ip_address(raw_ip) if isinstance(raw_ip, bytes) and len(raw_ip) == 4 else None
        records.append(
            _clean(
                {
                    "kind": "wlan_controller_ap",
                    "ap_mac": ap_mac,
                    "name": values.text(row.get("name"), 255),
                    "location": values.text(row.get("location"), 255),
                    "operation_status": values.integer(row.get("operation_status"), 1, 255),
                    "software_version": values.text(row.get("software_version"), 128),
                    "model": values.text(row.get("model"), 128),
                    "serial": values.text(row.get("serial"), 128),
                    "ip_address": ip if ip != "0.0.0.0" else None,  # noqa: S104
                    "ethernet_mac": values.mac(row.get("ethernet_mac")),
                }
            )
        )
    per_ap: dict[str, int] = {}
    for index, row in sorted(rows_by_index(radios).items()):
        ap_mac = _mac_index(index) if len(index) == 7 else None
        if ap_mac is None or not 0 <= index[6] <= 255:
            continue
        per_ap[ap_mac] = per_ap.get(ap_mac, 0) + 1
        if per_ap[ap_mac] > MAX_RADIOS_PER_AP:
            truncated = True
            continue
        records.append(
            _clean(
                {
                    "kind": "wlan_controller_radio",
                    "ap_mac": ap_mac,
                    "slot": index[6],
                    "radio_type": values.integer(row.get("radio_type"), 1, 255),
                    "channel": values.integer(row.get("channel"), 1, 255),
                    "oper_status": values.integer(row.get("oper_status"), 1, 2),
                    "clients": values.integer(row.get("clients"), 0, 100_000),
                }
            )
        )
    ess_rows = sorted(rows_by_index(ess).items())
    if len(ess_rows) > MAX_ESS:
        truncated = True
    for index, row in ess_rows[:MAX_ESS]:
        if len(index) != 1 or not 1 <= index[0] <= MAX_INDEX:
            continue
        records.append(
            _clean(
                {
                    "kind": "wlan_ess",
                    "ess_index": index[0],
                    "ssid": values.text(row.get("ssid"), _SSID_LIMIT),
                    "clients": values.integer(row.get("clients"), 0, 1_000_000),
                }
            )
        )
    for index, row in sorted(rows_by_index(stations).items()):
        mac = _mac_index(index) if len(index) == 6 else None
        if mac is None:
            continue
        raw_ap = row.get("ap_mac")
        records.append(
            _clean(
                {
                    "kind": "wlan_station",
                    "mac": mac,
                    "ap_mac": values.mac(raw_ap) if isinstance(raw_ap, bytes) else None,
                    "slot": values.integer(row.get("slot"), 0, 255),
                    "ess_index": values.integer(row.get("ess_index"), 1, MAX_INDEX),
                    "ssid": values.text(row.get("ssid"), _SSID_LIMIT),
                    "status": values.integer(row.get("status"), 0, 255),
                    "protocol": values.integer(row.get("protocol"), 1, 255),
                }
            )
        )
    columns = [*aps.values(), *radios.values(), *ess.values(), *stations.values()]
    status = "partial" if truncated else _status(columns)
    return status, records


# --- UBNT-UniFi-MIB --------------------------------------------------------------------------


def unifi(walker: Walker) -> AdapterResult:
    vaps = walker.table(catalog.UNIFI_VAP, catalog.UNIFI_VAP_COLUMNS)
    system = walker.get(list(catalog.UNIFI_SYSTEM_SCALARS))
    has_system = any(system.get(o) is not None for o in catalog.UNIFI_SYSTEM_SCALARS)
    if not has_system and not any(c.exists for c in vaps.values()):
        return "unsupported", []
    records: list[Record] = []
    if has_system:
        raw_ip = system.get(catalog.UNIFI_SYSTEM_IP)
        ip = None
        if isinstance(raw_ip, bytes) and len(raw_ip) == 4:
            ip = values.ip_address(raw_ip)
        records.append(
            _clean(
                {
                    "kind": "wlan_unifi_system",
                    "ip_address": ip if ip != "0.0.0.0" else None,  # noqa: S104
                    "model": values.text(system.get(catalog.UNIFI_SYSTEM_MODEL), 128),
                    "firmware": values.text(system.get(catalog.UNIFI_SYSTEM_VERSION), 128),
                }
            )
        )
    rows = sorted(rows_by_index(vaps).items())
    for index, row in rows[:MAX_VAPS]:
        if len(index) != 1 or not 1 <= index[0] <= MAX_INDEX:
            continue
        bssid = row.get("bssid")
        records.append(
            _clean(
                {
                    "kind": "wlan_vap",
                    "vap_index": index[0],
                    # unifiVapBssId es un DisplayString "xx:xx:..." en unos firmwares y
                    # 6 octetos en otros: se aceptan las dos formas y nada más.
                    "bssid": values.mac(bssid) or _mac_text(bssid),
                    "ssid": values.text(row.get("essid"), _SSID_LIMIT),
                    "name": values.text(row.get("name"), 64),
                    "channel": values.integer(row.get("channel"), 1, 255),
                    "radio": values.text(row.get("radio"), 8),
                    "clients": values.integer(row.get("clients"), 0, 100_000),
                }
            )
        )
    status = "partial" if len(rows) > MAX_VAPS else _status(list(vaps.values()))
    return status, records


def _mac_text(value: Value) -> str | None:
    text = values.text(value, 17)
    if text is None or len(text) != 17:
        return None
    parts = text.lower().split(":")
    if len(parts) != 6 or any(len(p) != 2 for p in parts):
        return None
    try:
        return values.mac(bytes(int(p, 16) for p in parts))
    except ValueError:
        return None


ADAPTERS: tuple[tuple[str, Callable[[Walker], AdapterResult]], ...] = (
    ("ieee802dot11", dot11),
    ("airespace", airespace),
    ("unifi", unifi),
)


def wlan(walker: Walker) -> ModuleResult:
    """Ejecuta todos los adaptadores; cada uno con evidencia añade un registro wlan_source
    con su estado, que el servidor usa para decidir si puede marcar ausencias de esa fuente."""
    records: list[Record] = []
    statuses: list[str] = []
    for name, adapter in ADAPTERS:
        status, found = adapter(walker)
        if status == "unsupported":
            continue
        statuses.append(status)
        records.append({"kind": "wlan_source", "source": name, "status": status})
        records.extend(found)
    if not statuses:
        return ModuleResult("unsupported")
    return ModuleResult("partial" if "partial" in statuses else "complete", records)

"""Contratos de NDR (Fase 7E): protocolo del sensor y API del dashboard.

Lo que llega del sensor se valida con modelos cerrados (extra=forbid) y límites explícitos:
un sensor comprometido no puede colar claves libres, nombres sin acotar ni contadores
negativos. Las direcciones IP se normalizan (forma comprimida) y las MAC a aa:bb:cc:dd:ee:ff.
"""

import ipaddress
import re
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, AwareDatetime, Field, field_validator

from app.schemas.common import RequestModel, ResponseModel

ALIAS_PATTERN = r"^[a-z0-9_-]{1,32}$"
MAX_RECORDS_HARD = 10_000
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
# Nombres DNS/SNI ya saneados por el sensor; aquí se revalida con la misma regla: nada que
# pueda interpretarse como marcado o control al mostrarlo en la UI o en un informe.
_NAME = re.compile(r"^[A-Za-z0-9._*?-]{0,253}$")


def _ip(value: str) -> str:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc


def _mac(value: str) -> str:
    text = value.lower()
    if not _MAC.fullmatch(text):
        raise ValueError("invalid MAC address")
    return text


def _name(value: str) -> str:
    if not _NAME.fullmatch(value):
        raise ValueError("invalid DNS name")
    return value.lower()


Ip = Annotated[str, Field(max_length=45), AfterValidator(_ip)]
Mac = Annotated[str, Field(max_length=17), AfterValidator(_mac)]
DnsName = Annotated[str, Field(max_length=253), AfterValidator(_name)]
Alias = Annotated[str, Field(pattern=ALIAS_PATTERN)]
Port = Annotated[int, Field(ge=0, le=65_535)]
Vlan = Annotated[int, Field(ge=0, le=4095)]
Counter = Annotated[int, Field(ge=0, le=2**62)]
Count = Annotated[int, Field(ge=0, le=2**31)]
Code = Annotated[str, Field(pattern=r"^[a-z0-9_]{1,32}$")]

FlowState = Literal["open", "closed", "reset", "timeout", "evicted"]
FlowFlag = Literal["midstream", "asymmetric", "fragmented", "retransmissions", "no_handshake_reply"]
AppHint = Literal["dns", "dhcp", "tls"]
CaptureState = Literal["disabled", "not_configured", "starting", "running", "degraded", "error"]
ObservationKind = Literal["arp", "dns", "dhcp", "tls"]


# --- Protocolo del sensor ---------------------------------------------------------------------


class NdrFlowIn(RequestModel):
    uid: str = Field(pattern=r"^[0-9a-f]{32}$")
    segment: int = Field(ge=0, le=1_000_000)
    ip_version: Literal[4, 6]
    transport: str = Field(pattern=r"^[a-z0-9]{1,8}$")
    src_ip: Ip
    src_port: Port | None = None
    dst_ip: Ip
    dst_port: Port | None = None
    vlan: Vlan | None = None
    src_mac: Mac | None = None
    dst_mac: Mac | None = None
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    packets_out: Counter
    packets_in: Counter
    bytes_out: Counter
    bytes_in: Counter
    tcp_flags_out: int = Field(ge=0, le=255)
    tcp_flags_in: int = Field(ge=0, le=255)
    state: FlowState
    final: bool
    flags: list[FlowFlag] = Field(default_factory=list, max_length=5)
    retransmissions: Count = 0
    fragments: Count = 0
    icmp_type: int | None = Field(default=None, ge=0, le=255)
    app_hints: list[AppHint] = Field(default_factory=list, max_length=4)


class _ObservationIn(RequestModel):
    count: Count = 0
    first_seen: AwareDatetime
    last_seen: AwareDatetime


class NdrArpIn(_ObservationIn):
    operation: Literal["request", "reply"]
    sender_ip: Ip
    sender_mac: Mac
    target_ip: Ip
    gratuitous: bool
    vlan: Vlan | None = None
    unsolicited: Count = 0
    eth_src_mac: Mac | None = None


class NdrDnsIn(_ObservationIn):
    client_ip: Ip
    resolver_ip: Ip
    qname: DnsName
    qtype: str = Field(pattern=r"^[A-Z0-9]{1,10}$")
    queries: Count = 0
    responses: Count = 0
    rcodes: dict[Code, Count] = Field(default_factory=dict, max_length=8)
    answers: list[Ip] = Field(default_factory=list, max_length=8)
    min_ttl: int | None = Field(default=None, ge=0, le=2**31)
    transport: Literal["udp", "tcp"] = "udp"
    vlan: Vlan | None = None


class NdrDhcpIn(_ObservationIn):
    message_type: Code
    client_mac: Mac
    server_ip: Ip | None = None
    server_mac: Mac | None = None
    your_ip: Ip | None = None
    routers: list[Ip] = Field(default_factory=list, max_length=8)
    dns_servers: list[Ip] = Field(default_factory=list, max_length=8)
    vlan: Vlan | None = None


class NdrTlsIn(_ObservationIn):
    client_ip: Ip
    server_ip: Ip
    server_port: Port | None = None
    sni: DnsName


class NdrBatchStatsIn(RequestModel):
    """Estadísticas de la ventana (solo el primer sobre de un lote las lleva)."""

    packets_seen: Counter = 0
    packets_processed: Counter = 0
    bytes_seen: Counter = 0
    malformed: Counter = 0
    truncated: Counter = 0
    unsupported: Counter = 0
    budget_dropped: Counter = 0
    export_failures: Counter = 0
    kernel_dropped: Counter = 0
    interface_dropped: Counter = 0
    flows_active: Counter = 0
    flows_evicted: Counter = 0
    flows_exported: Counter = 0
    unattributed_fragments: Counter = 0
    observations_overflow: Counter = 0
    cpu_percent: float = Field(default=0.0, ge=0, le=10_000)
    pps_budget: Counter = 0
    est_memory_kb: Counter = 0
    capture_state: CaptureState | None = None
    degraded_reasons: list[Code] = Field(default_factory=list, max_length=8)


class NdrBatchIn(RequestModel):
    batch_id: UUID
    interface: Alias
    config_revision: int = Field(ge=0, le=2**31)
    window_start: AwareDatetime
    window_end: AwareDatetime
    backend: str | None = Field(default=None, pattern=r"^[a-z_]{1,16}$")
    part: int = Field(ge=0, le=MAX_RECORDS_HARD)
    parts: int = Field(ge=1, le=MAX_RECORDS_HARD)
    flows: list[NdrFlowIn] = Field(default_factory=list, max_length=MAX_RECORDS_HARD)
    arp: list[NdrArpIn] = Field(default_factory=list, max_length=MAX_RECORDS_HARD)
    dns: list[NdrDnsIn] = Field(default_factory=list, max_length=MAX_RECORDS_HARD)
    dhcp: list[NdrDhcpIn] = Field(default_factory=list, max_length=MAX_RECORDS_HARD)
    tls: list[NdrTlsIn] = Field(default_factory=list, max_length=MAX_RECORDS_HARD)
    stats: NdrBatchStatsIn | None = None

    def record_count(self) -> int:
        return len(self.flows) + len(self.arp) + len(self.dns) + len(self.dhcp) + len(self.tls)


class NdrBatchAccepted(ResponseModel):
    batch_id: UUID
    duplicate: bool
    flows: int
    observations: int


class NdrInterfaceHealthIn(RequestModel):
    name: Alias
    state: CaptureState
    error_code: Code | None = None
    backend: str | None = Field(default=None, pattern=r"^[a-z_]{1,16}$")
    packets_seen: Counter | None = None
    packets_processed: Counter | None = None
    budget_dropped: Counter | None = None
    malformed: Counter | None = None
    cpu_percent: float | None = Field(default=None, ge=0, le=10_000)
    pps_budget: Counter | None = None
    last_packet_at: AwareDatetime | None = None
    last_export_at: AwareDatetime | None = None
    degraded_reasons: list[Code] = Field(default_factory=list, max_length=8)


class NdrHealthIn(RequestModel):
    """Estado de NDR en el heartbeat. Nunca trae nombres de dispositivo, solo alias."""

    state: CaptureState
    config_revision: int | None = Field(default=None, ge=0, le=2**31)
    interfaces: list[NdrInterfaceHealthIn] = Field(default_factory=list, max_length=8)
    spool_items: Counter | None = None
    spool_bytes: Counter | None = None
    spool_dropped: Counter | None = None


class SensorNdrConfig(ResponseModel):
    """Bloque `config.ndr` del heartbeat. Solo para sensores que declaran la capacidad."""

    enabled: bool
    revision: int
    interfaces: list[str]
    promiscuous: bool
    snaplen: int
    max_flows: int
    max_packets_per_second: int
    max_cpu_percent: int
    export_interval_seconds: int
    flow_idle_timeout_seconds: int
    flow_active_timeout_seconds: int
    max_records_per_batch: int
    max_batch_bytes: int
    spool_max_mb: int
    spool_max_age_hours: int
    arp_metadata: bool
    dns_metadata: bool
    dhcp_metadata: bool
    tls_metadata: bool


# --- API del dashboard ------------------------------------------------------------------------


class NdrCaptureConfigUpdate(RequestModel):
    """Aprobación de captura. Habilitar exige el punto de observación y la confirmación
    expresa de que la captura es pasiva y está autorizada en ese segmento."""

    enabled: bool
    interfaces: list[Alias] = Field(default_factory=list, max_length=4)
    observation_point: str | None = Field(
        default=None, min_length=3, max_length=200, pattern=r"^[^\x00-\x1f\x7f<>]+$"
    )
    confirm_passive_authorized: bool = False
    promiscuous: bool = False
    snaplen: int = Field(default=512, ge=96, le=2048)
    max_flows: int = Field(default=20_000, ge=1000, le=500_000)
    max_packets_per_second: int = Field(default=20_000, ge=100, le=500_000)
    max_cpu_percent: int = Field(default=40, ge=5, le=90)
    export_interval_seconds: int = Field(default=60, ge=10, le=600)
    flow_idle_timeout_seconds: int = Field(default=120, ge=10, le=3600)
    flow_active_timeout_seconds: int = Field(default=300, ge=30, le=7200)
    arp_metadata: bool = True
    dhcp_metadata: bool = True
    dns_metadata: bool = False
    tls_metadata: bool = False
    # Concurrencia optimista: la revisión que el admin vio (0 = aún no hay configuración).
    expected_revision: int = Field(ge=0, le=2**31)

    @field_validator("interfaces")
    @classmethod
    def _unique(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("duplicated interface alias")
        return value


class NdrCaptureConfigRead(ResponseModel):
    enabled: bool
    revision: int
    interfaces: list[str]
    observation_point: str | None
    promiscuous: bool
    snaplen: int
    max_flows: int
    max_packets_per_second: int
    max_cpu_percent: int
    export_interval_seconds: int
    flow_idle_timeout_seconds: int
    flow_active_timeout_seconds: int
    arp_metadata: bool
    dhcp_metadata: bool
    dns_metadata: bool
    tls_metadata: bool
    updated_by: str | None
    updated_at: datetime


class NdrInterfaceHealth(ResponseModel):
    name: str
    state: CaptureState
    error_code: str | None
    backend: str | None
    packets_seen: int | None
    packets_processed: int | None
    budget_dropped: int | None
    malformed: int | None
    cpu_percent: float | None
    pps_budget: int | None
    last_packet_at: datetime | None
    last_export_at: datetime | None
    degraded_reasons: list[str]


class NdrSensorRead(ResponseModel):
    sensor_id: UUID
    name: str
    site_id: UUID
    site_name: str
    status: str
    sensor_version: str | None
    last_seen_at: datetime | None
    # El sensor declara la capacidad network.ndr.passive (sensor 0.8.0+ con [ndr] local).
    capable: bool
    # Estado informado por el sensor en su último heartbeat (None = nunca informó).
    capture_state: CaptureState | None
    reported_revision: int | None
    interfaces: list[NdrInterfaceHealth]
    spool_items: int | None
    spool_dropped: int | None
    config: NdrCaptureConfigRead | None
    last_batch_at: datetime | None
    # Ventana de 24 h según los recibos: paquetes vistos y descartes de kernel/presupuesto.
    packets_24h: int
    dropped_24h: int


class NdrSensorList(ResponseModel):
    items: list[NdrSensorRead]


class NdrProtocolCount(ResponseModel):
    key: str
    flows: int
    bytes: int


class NdrTalker(ResponseModel):
    ip: str
    flows: int
    bytes: int


class NdrOverview(ResponseModel):
    window_hours: int
    sensors_capable: int
    sensors_enabled: int
    sensors_capturing: int
    sensors_degraded: int
    flows: int
    bytes: int
    packets_seen: int
    packets_dropped: int
    observations: dict[str, int]
    transports: list[NdrProtocolCount]
    services: list[NdrProtocolCount]
    top_talkers: list[NdrTalker]
    last_batch_at: datetime | None


class NdrFlowRead(ResponseModel):
    id: int
    sensor_id: UUID
    sensor_name: str
    site_id: UUID
    interface: str
    uid: str
    ip_version: int
    transport: str
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    vlan: int | None
    src_mac: str | None
    dst_mac: str | None
    first_seen: datetime
    last_seen: datetime
    packets_out: int
    packets_in: int
    bytes_out: int
    bytes_in: int
    tcp_flags_out: int
    tcp_flags_in: int
    state: str
    final: bool
    segments: int
    flags: list[str]
    retransmissions: int
    fragments: int
    icmp_type: int | None
    app_hints: list[str]


class NdrFlowList(ResponseModel):
    items: list[NdrFlowRead]
    total: int


class NdrObservationRead(ResponseModel):
    id: int
    sensor_id: UUID
    sensor_name: str
    site_id: UUID
    interface: str
    kind: ObservationKind
    ip: str | None
    peer_ip: str | None
    mac: str | None
    name: str | None
    vlan: int | None
    count: int
    first_seen: datetime
    last_seen: datetime
    data: dict[str, object]


class NdrObservationList(ResponseModel):
    items: list[NdrObservationRead]
    total: int


# --- Fase 7E.2: anomalías, asociaciones IP-MAC y catálogo de reglas ---------------------------

AnomalyVerdict = Literal["observed", "suspicious", "probable", "confirmed"]
AnomalyStatus = Literal["open", "acknowledged", "resolved", "false_positive"]
AnomalySeverity = Literal["informational", "low", "medium", "high", "critical"]


class NdrMitreRead(ResponseModel):
    tactic: str
    technique: str
    subtechnique: str | None


class NdrRuleRead(ResponseModel):
    id: str
    version: int
    category: str
    title: str
    description: str
    why: str
    recommendations: list[str]
    verdicts: dict[str, str]
    # Fase 7E.5: mapeo MITRE ATT&CK de la regla (null si no describe una técnica).
    mitre: NdrMitreRead | None = None


class NdrRuleList(ResponseModel):
    items: list[NdrRuleRead]


class NdrAssetRef(ResponseModel):
    asset_id: UUID
    name: str
    primary_ip: str
    mac_address: str | None


class NdrSwitchLocation(ResponseModel):
    """Dónde reenvía un switch la MAC del sujeto (tabla FDB por SNMP, Fase 6B). Un uplink
    o un trunk ven muchas MAC: `location` dice si parece el puerto de acceso del equipo."""

    device_id: UUID
    device_name: str | None
    interface: str | None
    vlan: int | None
    location: str
    last_seen: datetime


class NdrDetectionRef(ResponseModel):
    detection_id: UUID
    rule_id: str
    severity: str
    confidence: str
    status: str


class NdrIncidentRef(ResponseModel):
    incident_id: UUID
    number: int
    title: str
    status: str


class NdrAnomalyContext(ResponseModel):
    """Correlación de la anomalía (Fase 7E.4), solo en el detalle."""

    asset: NdrAssetRef | None
    switch_locations: list[NdrSwitchLocation]
    detections: list[NdrDetectionRef]
    incidents: list[NdrIncidentRef]


class NdrAnomalyRead(ResponseModel):
    anomaly_id: UUID
    site_id: UUID
    site_name: str
    sensor_id: UUID | None
    sensor_name: str | None
    rule_id: str
    rule_version: int
    category: str
    title: str
    verdict: AnomalyVerdict
    severity: AnomalySeverity
    status: AnomalyStatus
    subject_ip: str | None
    subject_mac: str | None
    summary: str
    evidence: dict[str, object]
    occurrences: int
    first_seen: datetime
    last_seen: datetime
    status_by: str | None
    status_at: datetime | None
    status_note: str | None
    # Fase 7E.4: activo atribuido (también en el listado) y correlación (solo en el detalle).
    asset_id: UUID | None = None
    asset_name: str | None = None
    context: NdrAnomalyContext | None = None
    # Fase 7E.5: mapeo MITRE de la regla que la generó.
    mitre: NdrMitreRead | None = None


class NdrAnomalyList(ResponseModel):
    items: list[NdrAnomalyRead]
    total: int


class NdrAnomalyStatusUpdate(RequestModel):
    status: Literal["acknowledged", "resolved", "false_positive"]
    note: str | None = Field(default=None, min_length=1, max_length=500)


class NdrBindingRead(ResponseModel):
    site_id: UUID
    vlan: int | None
    ip: str
    mac: str
    source: str
    gateway: bool
    count: int
    first_seen: datetime
    last_seen: datetime


class NdrBindingList(ResponseModel):
    items: list[NdrBindingRead]
    total: int


# --- Fase 7E.7: respuesta a anomalías (solo registro, nunca acción en la red) -----------------


class NdrResponseSuggestion(ResponseModel):
    suggestion_id: str
    kind: Literal["network_control", "manual", "playbook"]
    title: str
    rationale: str
    instructions: list[str]
    # Solo en kind=network_control: el control de la Fase 7A.6 ya validado.
    control_type: str | None
    target: dict[str, object] | None
    direction: str | None
    # Solo en kind=playbook.
    playbook_key: str | None


class NdrResponsePlan(ResponseModel):
    anomaly_id: UUID
    # Siempre false: Sentra no integra puntos de control; las solicitudes se aplican fuera.
    applied_by_sentra: bool
    note: str
    # Incidentes que ya incluyen la detección de la anomalía: destino natural de la solicitud.
    incidents: list[NdrIncidentRef]
    suggestions: list[NdrResponseSuggestion]


class NdrControlRequest(RequestModel):
    """Registrar en un incidente la solicitud de control de una sugerencia del plan."""

    incident_id: UUID
    suggestion_id: str = Field(min_length=3, max_length=200)
    justification: str = Field(min_length=10, max_length=4000)
    expires_at: datetime | None = None

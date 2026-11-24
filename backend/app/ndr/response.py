"""Respuesta a anomalías NDR (Fase 7E.7): plan sugerido y solicitudes de control de red.

Nada de esto toca la red. Sentra no integra firewalls, resolvedores DNS, proxies ni switches
(app/incidents/network_controls.py), así que un bloqueo es una SOLICITUD registrada en un
incidente, con su justificación, que un admin aprueba o rechaza y que alguien aplica FUERA de
Sentra siguiendo las instrucciones. Por eso cada sugerencia lleva:

- `kind="network_control"`: un control del flujo de la Fase 7A.6 (tipo, objetivo, sentido)
  ya validado con las mismas reglas (prefijos mínimos, dominios completos...);
- `kind="manual"`: pasos que solo puede dar una persona (apagar un puerto del switch,
  activar DHCP snooping, revisar el equipo) y que Sentra no puede representar como control;
- `kind="playbook"`: el playbook de solo lectura que reúne contexto del activo.

Las sugerencias se derivan de la evidencia de la anomalía con reglas fijas por regla NDR; no
hay inferencias ni acciones automáticas, y una anomalía "observed" solo sugiere revisión.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Literal

from app.incidents.network_controls import ControlTargetError, check_direction, normalize_target
from app.models.ndr import NdrAnomaly
from app.ndr.addresses import is_external

SuggestionKind = Literal["network_control", "manual", "playbook"]
NDR_PLAYBOOK = "investigate_network_anomaly"
_CLEARTEXT_PORTS = {"ftp": ("tcp", 21), "telnet": ("tcp", 23), "tftp": ("udp", 69)}


@dataclass
class Suggestion:
    suggestion_id: str
    kind: SuggestionKind
    title: str
    rationale: str
    instructions: list[str] = field(default_factory=list)
    control_type: str | None = None
    target: dict[str, Any] | None = None
    direction: str | None = None
    playbook_key: str | None = None


def _host_cidr(ip: str) -> str | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return f"{address.compressed}/{32 if address.version == 4 else 128}"


def _control(
    suggestion_id: str,
    title: str,
    rationale: str,
    control_type: str,
    target: dict[str, Any],
    direction: str | None,
    instructions: list[str],
) -> Suggestion | None:
    """Solo si el objetivo pasa la validación de los controles de red (si no, nada)."""
    try:
        normalized = normalize_target(control_type, target)
        checked = check_direction(control_type, direction)
    except ControlTargetError:
        return None
    return Suggestion(
        suggestion_id=suggestion_id,
        kind="network_control",
        title=title,
        rationale=rationale,
        instructions=instructions,
        control_type=control_type,
        target=normalized,
        direction=checked,
    )


def _block_remote(ip: str, why: str) -> Suggestion | None:
    cidr = _host_cidr(ip)
    if cidr is None or not is_external(ip):
        return None
    return _control(
        f"block_address:{cidr}",
        f"Bloquear el tráfico saliente hacia {ip}",
        why,
        "block_address",
        {"cidr": cidr},
        "outbound",
        [
            f"En el cortafuegos perimetral, denegar la salida hacia {cidr} desde el site.",
            "Comprobar antes que la IP no es un servicio compartido (CDN, nube) del negocio.",
            "Registrar en la solicitud dónde y cuándo se aplicó (Marcar aplicado).",
        ],
    )


def _block_domain(domain: str, why: str) -> Suggestion | None:
    return _control(
        f"block_domain:{domain}",
        f"Bloquear la resolución de {domain}",
        why,
        "block_domain",
        {"domain": domain},
        None,
        [
            f"En el resolvedor DNS corporativo, responder NXDOMAIN (o sinkhole) para {domain} y"
            " sus subdominios.",
            "Un bloqueo solo por DNS se salta con DoH/DoT o conectando por IP: valorar también el"
            " cortafuegos.",
        ],
    )


def _manual(suggestion_id: str, title: str, rationale: str, steps: list[str]) -> Suggestion:
    return Suggestion(suggestion_id, "manual", title, rationale, steps)


def suggestions(row: NdrAnomaly, has_asset: bool) -> list[Suggestion]:
    evidence: dict[str, Any] = dict(row.evidence or {})
    rule = row.rule_id
    found: list[Suggestion | None] = []
    if row.verdict == "observed":
        found.append(
            _manual(
                "review",
                "Revisar y documentar",
                "Es un hecho observado sin juicio: no justifica por sí solo un bloqueo.",
                ["Confirmar con el responsable si el uso es esperado y documentarlo en la nota."],
            )
        )
        if rule == "NDR-PROTO-001":
            service = str(evidence.get("service") or "")
            transport, port = _CLEARTEXT_PORTS.get(service, (None, None))
            if transport and port:
                found.append(
                    _control(
                        f"block_port:{transport}/{port}",
                        f"Restringir {service} entrante en el site",
                        "El servicio transmite credenciales en claro; lo correcto es retirarlo o"
                        " sustituirlo por su versión cifrada.",
                        "block_port",
                        {"port": port, "protocol": transport},
                        "inbound",
                        [
                            f"Deshabilitar {service} en {row.subject_ip} o sustituirlo"
                            " (SSH, SFTP).",
                            "Si no se puede retirar aún, limitar el acceso a las IP de gestión.",
                        ],
                    )
                )
    elif rule in ("NDR-ARP-001", "NDR-ARP-002", "NDR-ARP-003", "NDR-MITM-001", "NDR-DHCP-001"):
        mac = row.subject_mac or "la MAC del sujeto"
        found.append(
            _manual(
                "isolate_switch_port",
                "Localizar y aislar el puerto del switch",
                "Sentra no gestiona switches: la contención de capa 2 se hace en el equipo de red.",
                [
                    f"Buscar {mac} en la tabla MAC del switch (ver «Correlación» de la anomalía).",
                    "Si el puerto es de acceso y el equipo no es legítimo, deshabilitarlo o"
                    " moverlo a una VLAN de cuarentena.",
                    "Activar Dynamic ARP Inspection y DHCP snooping en la VLAN afectada.",
                    "Revisar las cachés ARP de los equipos afectados tras la contención.",
                ],
            )
        )
    elif rule in ("NDR-SCAN-001", "NDR-PROTO-002"):
        found.append(
            _manual(
                "contain_source",
                f"Contener el equipo de origen {row.subject_ip}",
                "El origen recorre o abre sesiones en la red interna; un bloqueo de una IP"
                " remota no aplica.",
                [
                    "Confirmar si es un escáner o un administrador autorizado.",
                    "Si no lo es, aislar el equipo (flujo de Aislamiento con doble confirmación) o"
                    " su puerto del switch.",
                    "Revisar inicios de sesión recientes en los equipos destino.",
                ],
            )
        )
    elif rule == "NDR-BEH-003":
        found.append(
            _block_remote(
                str(evidence.get("dst_ip") or ""),
                "Conexiones periódicas muy regulares hacia esta IP: patrón típico de C2.",
            )
        )
    elif rule == "NDR-TI-001":
        value = str(evidence.get("indicator_value") or "")
        kind = evidence.get("indicator_type")
        why = (
            f"El valor figura como {evidence.get('classification')} en la fuente"
            f" {evidence.get('source')}."
        )
        if kind in ("ipv4", "ipv6"):
            found.append(_block_remote(value, why))
        elif kind == "cidr":
            found.append(
                _control(
                    f"block_address:{value}",
                    f"Bloquear el tráfico saliente hacia {value}",
                    why,
                    "block_address",
                    {"cidr": value},
                    "outbound",
                    ["Una red completa puede contener servicios legítimos: revisar antes."],
                )
            )
        elif kind in ("domain", "hostname"):
            found.append(_block_domain(value, why))
    elif rule == "NDR-DNS-002":
        parent = str(evidence.get("parent") or "")
        if parent:
            found.append(
                _block_domain(parent, "Nombres codificados bajo este dominio: posible túnel DNS.")
            )
    elif rule == "NDR-DNS-003":
        found.append(
            _block_remote(
                str(evidence.get("resolver_ip") or ""),
                "El equipo usa un resolvedor externo en lugar de los anunciados por DHCP.",
            )
        )
    elif rule == "NDR-BEH-001":
        found.append(
            _manual(
                "review_exfiltration",
                "Revisar el volumen enviado",
                "La anomalía es de volumen; el destino concreto está en los flujos de esa hora.",
                [
                    "Abrir «Flujos y metadatos» filtrando por la IP para ver los destinos.",
                    "Si el destino no es un servicio corporativo (copias, nube), solicitar su"
                    " bloqueo y aislar el equipo.",
                ],
            )
        )
    if has_asset and row.verdict != "observed":
        found.append(
            Suggestion(
                suggestion_id=f"playbook:{NDR_PLAYBOOK}",
                kind="playbook",
                title="Reunir contexto del activo",
                rationale="Solo lectura: anomalías y tráfico NDR del activo, timeline y riesgo.",
                instructions=["Ejecutar el playbook desde Response sobre el activo atribuido."],
                playbook_key=NDR_PLAYBOOK,
            )
        )
    return [s for s in found if s is not None]

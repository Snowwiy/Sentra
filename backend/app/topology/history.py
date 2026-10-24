"""Historial de topología: contenido de un snapshot y diferencias (Fase 6E.1).

Funciones puras, sin base de datos, para probar cada regla por separado:

- `canonical_hash` decide si dos estados son el mismo (mismo JSON canónico = mismo hash).
- `diff_snapshots` compara dos contenidos y devuelve cambios con evidencia. Una ausencia en
  un snapshot nunca es una eliminación: un enlace que falta es `link_not_observed` y un nodo
  que falta sin retirada explícita es `device_not_observed`. La eliminación de un enlace
  (`link_removed`) la decide el servicio tras varias reconstrucciones con la fuente sana.

Un snapshot guarda, por nodo, solo lo que define su identidad y su papel en la red (nombre,
IP, MAC, fabricante, tipo, rol, estado, gateways, asociación Wi-Fi) y, por enlace, sus
extremos, clase, relación, confianza, puertos y VLAN. Nada de riesgo ni criticidad: cambian
por motivos que no son de red y llenarían el historial de ruido.
"""

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Campos de nodo que se comparan y el tipo de cambio que produce cada uno.
NODE_FIELDS: dict[str, str] = {
    "ip": "ip_changed",
    "mac": "mac_changed",
    "label": "name_changed",
    "vendor": "vendor_changed",
    "role": "role_changed",
    "device_type": "classification_changed",
    "status": "connectivity_changed",
    "gateways": "gateway_changed",
}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
KIND_RANK = {"physical": 0, "logical": 1, "observed": 2, "candidate": 3, "unknown": 4}
MAX_EVIDENCE = 8
_VLAN = re.compile(r"\bvlan (\d{1,4})\b", re.IGNORECASE)
_SSID = re.compile(r"\bSSID (.{1,64}?);")


def canonical(value: Any) -> bytes:
    """JSON canónico (claves ordenadas, sin espacios): base del hash y del export firmado."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def canonical_hash(nodes: Mapping[str, Any], links: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical({"nodes": nodes, "links": links})).hexdigest()


def vlan_of(evidence: Iterable[Mapping[str, Any]]) -> int | None:
    """VLAN citada en la evidencia de un enlace de tabla MAC (el constructor la escribe así)."""
    for item in evidence:
        match = _VLAN.search(str(item.get("detail") or ""))
        if match:
            return int(match.group(1))
    return None


def ssid_of(evidence: Iterable[Mapping[str, Any]]) -> str | None:
    for item in evidence:
        match = _SSID.search(str(item.get("detail") or ""))
        if match:
            return match.group(1).strip() or None
    return None


def pair_key(link: Mapping[str, Any]) -> str:
    """Identidad de la RELACIÓN entre dos nodos, sin puertos ni clase.

    El link_key de 6D incluye el puerto: si un equipo cambia de boca del switch, el enlace
    viejo queda ausente y aparece otro. Comparando por pareja + familia de relación se
    reconoce como un cambio de puerto y no como «enlace eliminado + enlace nuevo».
    """
    ends = sorted((str(link["s"]), str(link["t"])))
    family = str(link.get("rel") or "")
    if family in ("fdb_edge", "fdb_shared", "fdb_unmapped"):
        family = "fdb"
    return f"{family}|{ends[0]}|{ends[1]}"


@dataclass
class ChangeDraft:
    change_type: str
    subject_type: str
    subject_key: str
    subject_label: str | None
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    confidence: str
    evidence: list[dict[str, Any]] = field(default_factory=list)
    asset_public_id: str | None = None


@dataclass
class DiffContext:
    """Lo que el diff necesita saber además de los dos contenidos.

    - `quality`: calidad del snapshot nuevo (informativa en la evidencia).
    - `degraded_nodes`: nodos cuya evidencia falló en su última consulta (SNMP sin respuesta,
      agente sin contacto).
    - `retired_nodes`: nodos que faltan porque su activo se archivó (retirada explícita).
    """

    quality: str = "complete"
    degraded_nodes: frozenset[str] = frozenset()
    retired_nodes: frozenset[str] = frozenset()
    observed_at: datetime | None = None


def _asset_of(node_id: str) -> str | None:
    return node_id.split(":", 1)[1] if node_id.startswith("asset:") else None


def _ev(source: str, detail: str, at: datetime | None) -> dict[str, Any]:
    return {"source": source, "detail": detail[:255], "observed_at": at.isoformat() if at else None}


def _label(nodes: Mapping[str, Any], key: str) -> str:
    node = nodes.get(key) or {}
    return str(node.get("label") or key)[:255]


def _node_changes(
    old: Mapping[str, Any], new: Mapping[str, Any], ctx: DiffContext
) -> list[ChangeDraft]:
    out: list[ChangeDraft] = []
    at = ctx.observed_at
    for key in sorted(set(new) - set(old)):
        node = new[key]
        out.append(
            ChangeDraft(
                "device_appeared",
                "node",
                key,
                _label(new, key),
                None,
                dict(node),
                "high",
                [_ev("topology", f"Node first present in the topology ({node.get('kind')})", at)],
                _asset_of(key),
            )
        )
    for key in sorted(set(old) - set(new)):
        node = old[key]
        if key in ctx.retired_nodes:
            change, confidence, detail = (
                "device_retired",
                "high",
                "The asset was archived: retired from the inventory",
            )
        else:
            # Falta en el grafo pero no hay retirada explícita: activo borrado por la política
            # de ciclo de vida, fusionado en otro o equipo de red archivado. No se afirma que
            # el dispositivo se haya ido de la red, solo que ya no es un nodo.
            change, confidence, detail = (
                "device_not_observed",
                "medium",
                "The node is no longer part of the topology inventory",
            )
        out.append(
            ChangeDraft(
                change,
                "node",
                key,
                _label(old, key),
                dict(node),
                None,
                confidence,
                [_ev("topology", detail, at)],
                _asset_of(key),
            )
        )
    for key in sorted(set(old) & set(new)):
        before, after = old[key], new[key]
        for name, change in NODE_FIELDS.items():
            if before.get(name) == after.get(name):
                continue
            if name == "status":
                out.extend(_status_change(key, before, after, new, ctx))
                continue
            if after.get(name) in (None, [], "") and name not in ("gateways",):
                # Un dato que deja de informarse no es un cambio del dispositivo (la fuente
                # dejó de verlo); el siguiente valor real sí lo será.
                continue
            confidence = "medium" if name in ("label", "vendor", "device_type") else "high"
            out.append(
                ChangeDraft(
                    change,
                    "node",
                    key,
                    _label(new, key),
                    {name: before.get(name)},
                    {name: after.get(name)},
                    confidence,
                    [
                        _ev(
                            "topology",
                            f"{name} changed from {before.get(name)!s:.60} to"
                            f" {after.get(name)!s:.60}",
                            at,
                        )
                    ],
                    _asset_of(key),
                )
            )
        if before.get("wifi") != after.get("wifi") and after.get("wifi"):
            out.extend(_wifi_change(key, before.get("wifi"), after["wifi"], new, ctx))
    return out


def _status_change(
    key: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    nodes: Mapping[str, Any],
    ctx: DiffContext,
) -> list[ChangeDraft]:
    old_status, new_status = before.get("status"), after.get("status")
    if new_status is None or old_status is None:
        return []
    change, confidence = "connectivity_changed", "high"
    detail = f"Status changed from {old_status} to {new_status}"
    if new_status == "offline" and not after.get("managed"):
        # Sin agente, "offline" ya lo decide el discovery solo tras scans COMPLETOS sin
        # respuesta (network_misses): es la única ausencia que se puede afirmar.
        change = "device_disappeared"
        detail = "Not seen by complete discovery scans (status offline)"
    elif new_status == "unknown":
        change, confidence = "device_not_observed", "low"
        detail = "No recent evidence about the device (status unknown)"
    return [
        ChangeDraft(
            change,
            "node",
            key,
            _label(nodes, key),
            {"status": old_status},
            {"status": new_status},
            confidence,
            [_ev("topology", detail, ctx.observed_at)],
            _asset_of(key),
        )
    ]


def _wifi_change(
    key: str,
    before: Mapping[str, Any] | None,
    after: Mapping[str, Any],
    nodes: Mapping[str, Any],
    ctx: DiffContext,
) -> list[ChangeDraft]:
    if before is None:
        change = "wifi_association_changed"
    elif before.get("ap") != after.get("ap"):
        change = "wifi_ap_changed"
    else:
        change = "wifi_association_changed"
    return [
        ChangeDraft(
            change,
            "node",
            key,
            _label(nodes, key),
            {"wifi": dict(before) if before else None},
            {"wifi": dict(after)},
            "medium",
            [
                _ev(
                    "wlan",
                    f"Wi-Fi association: AP {_label(nodes, str(after.get('ap')))}"
                    f" SSID {after.get('ssid') or 'not observed'}",
                    ctx.observed_at,
                )
            ],
            _asset_of(key),
        )
    ]


def _link_label(nodes: Mapping[str, Any], link: Mapping[str, Any]) -> str:
    return f"{_label(nodes, str(link['s']))} - {_label(nodes, str(link['t']))}"[:255]


def _link_asset(link: Mapping[str, Any]) -> str | None:
    return _asset_of(str(link["t"])) or _asset_of(str(link["s"]))


def _link_changes(
    old_nodes: Mapping[str, Any],
    new_nodes: Mapping[str, Any],
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    ctx: DiffContext,
) -> list[ChangeDraft]:
    out: list[ChangeDraft] = []
    at = ctx.observed_at
    old_pairs: dict[str, list[str]] = {}
    for key, link in old.items():
        old_pairs.setdefault(pair_key(link), []).append(key)
    new_pairs: dict[str, list[str]] = {}
    for key, link in new.items():
        new_pairs.setdefault(pair_key(link), []).append(key)
    matched_old: set[str] = set()
    for key in sorted(new):
        link = new[key]
        if key in old:
            matched_old.add(key)
            out.extend(_same_link(key, old[key], link, new_nodes, at))
            continue
        # ¿Misma pareja y relación con otra clave (otro puerto u otra clase)?
        candidates = [k for k in old_pairs.get(pair_key(link), []) if k not in new]
        if candidates:
            previous_key = sorted(candidates)[0]
            matched_old.add(previous_key)
            previous = old[previous_key]
            if (previous.get("sp"), previous.get("tp")) != (link.get("sp"), link.get("tp")):
                out.append(
                    ChangeDraft(
                        "link_port_changed",
                        "link",
                        key,
                        _link_label(new_nodes, link),
                        {"source_port": previous.get("sp"), "target_port": previous.get("tp")},
                        {"source_port": link.get("sp"), "target_port": link.get("tp")},
                        "medium",
                        [
                            _ev(
                                str(link.get("rel") or "topology"),
                                f"Port changed from {previous.get('sp') or '?'} to"
                                f" {link.get('sp') or '?'}",
                                at,
                            )
                        ],
                        _link_asset(link),
                    )
                )
            out.extend(_same_link(key, previous, link, new_nodes, at, ports=False))
            continue
        out.append(
            ChangeDraft(
                "link_added",
                "link",
                key,
                _link_label(new_nodes, link),
                None,
                dict(link),
                str(link.get("c") or "low"),
                [_ev(str(link.get("rel") or "topology"), "Link derived from new evidence", at)],
                _link_asset(link),
            )
        )
    for key in sorted(set(old) - matched_old):
        link = old[key]
        # Una ausencia en UN snapshot nunca es «eliminado»: eso lo decide el registro tras
        # varias reconstrucciones con la fuente sana (record_link_removals en el servicio).
        out.append(
            ChangeDraft(
                "link_not_observed",
                "link",
                key,
                _link_label(old_nodes, link),
                dict(link),
                None,
                "low",
                [
                    _ev(
                        str(link.get("rel") or "topology"),
                        "Not derived in the latest rebuild; not concluded as removed",
                        at,
                    )
                ],
                _link_asset(link),
            )
        )
    return out


def _same_link(
    key: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    nodes: Mapping[str, Any],
    at: datetime | None,
    *,
    ports: bool = True,
) -> list[ChangeDraft]:
    out: list[ChangeDraft] = []
    checks: list[tuple[str, str]] = [
        ("vlan", "link_vlan_changed"),
        ("k", "link_kind_changed"),
        ("c", "link_confidence_changed"),
    ]
    if ports and (before.get("sp"), before.get("tp")) != (after.get("sp"), after.get("tp")):
        checks.insert(0, ("sp", "link_port_changed"))
    for name, change in checks:
        if before.get(name) == after.get(name):
            continue
        if name == "vlan" and after.get(name) is None:
            continue
        out.append(
            ChangeDraft(
                change,
                "link",
                key,
                _link_label(nodes, after),
                {name: before.get(name)},
                {name: after.get(name)},
                "medium",
                [
                    _ev(
                        str(after.get("rel") or "topology"),
                        f"{name} changed from {before.get(name)} to {after.get(name)}",
                        at,
                    )
                ],
                _link_asset(after),
            )
        )
    return out


def diff_snapshots(
    old_nodes: Mapping[str, Any],
    old_links: Mapping[str, Any],
    new_nodes: Mapping[str, Any],
    new_links: Mapping[str, Any],
    ctx: DiffContext,
) -> list[ChangeDraft]:
    """Cambios del estado viejo al nuevo, nodos primero y luego enlaces (orden estable)."""
    return [
        *_node_changes(old_nodes, new_nodes, ctx),
        *_link_changes(old_nodes, new_nodes, old_links, new_links, ctx),
    ]

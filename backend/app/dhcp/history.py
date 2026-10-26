"""Historial de identidad de los activos (Fase 6E.2, tabla asset_identity_history).

El nombre, la IP, la MAC, el fabricante y el tipo de un activo se escriben desde muchos sitios
(discovery, agente, inventario, fusión, DHCP, etiqueta manual). En vez de repetir el registro
en cada uno, un listener `before_flush` mira qué columnas de identidad cambiaron en los activos
modificados y añade una fila por cambio en la misma transacción: si la transacción se deshace,
el historial también. No registra la creación de un activo (no hay valor anterior) ni un valor
que no se llegó a cargar (no se sabe cuál era).
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

from app.discovery.classify import AGENT_HOSTNAME, DHCP_LEASE
from app.models.asset import Asset
from app.models.dhcp import AssetIdentityHistory

# Columna del activo -> campo del historial.
_FIELDS = {
    "device_name": "name",
    "custom_label": "label",
    "primary_ip": "ip",
    "mac_address": "mac",
    "vendor": "vendor",
    "device_type": "device_type",
}
_STRONG_NAME_SOURCES = {AGENT_HOSTNAME, DHCP_LEASE}
MAX_VALUE = 255


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = getattr(value, "value", value)
    return str(text)[:MAX_VALUE]


def _source_and_confidence(asset: Asset, field: str) -> tuple[str, str]:
    managed = asset.is_managed
    if field == "label":
        return "manual", "high"
    if field == "name":
        source = asset.name_source or ("agent" if managed else "discovery")
        return source[:24], "high" if source in _STRONG_NAME_SOURCES else "medium"
    if field == "vendor":
        return "oui", "medium"
    if field == "device_type":
        # Fase 7A.4: un tipo fijado por un admin no es una clasificación.
        if asset.manual_device_type and asset.device_type == asset.manual_device_type:
            return "manual", "high"
        confidence = _text(asset.classification_confidence) or "low"
        return "classification", confidence[:8]
    return ("agent", "high") if managed else ("discovery", "medium")


def _record(session: Session, flush_context: Any, instances: Any) -> None:
    now: datetime | None = None
    for obj in list(session.dirty):
        if not isinstance(obj, Asset) or obj.id is None:
            continue
        state = inspect(obj)
        for column, field in _FIELDS.items():
            history = state.attrs[column].history
            if not history.added or not history.deleted:
                continue
            old, new = _text(history.deleted[0]), _text(history.added[0])
            if old == new:
                continue
            if now is None:
                now = datetime.now(UTC)
            source, confidence = _source_and_confidence(obj, field)
            session.add(
                AssetIdentityHistory(
                    asset_id=obj.id,
                    field=field,
                    old_value=old,
                    new_value=new,
                    source=source,
                    confidence=confidence,
                    observed_at=now,
                )
            )


def install() -> None:
    """Registra el listener una sola vez (idempotente: event.contains lo comprueba)."""
    if not event.contains(Session, "before_flush", _record):
        event.listen(Session, "before_flush", _record)

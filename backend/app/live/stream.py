"""Stream SSE del Live SOC (Fase 7F.7).

Diseño (docs/fase-7f-live-soc.md):

* **Sin memoria compartida ni Redis.** Cada conexión consulta la base con un cursor por
  canal (el último id visto de detecciones, alertas, actividad de casos y alertas SIEM). Con
  varios workers cada uno sirve sus conexiones y todos leen la misma base: no hay nada que
  sincronizar.
* **Reanudable.** Cada mensaje lleva `id:` con los cuatro cursores. El navegador lo reenvía
  como `Last-Event-ID` al reconectar y el stream sigue donde se quedó. Si el atraso supera
  LIVE_BACKLOG_LIMIT, se salta al presente y se avisa (`degraded`, `backlog_skipped`).
* **Acotado.** Como mucho PAGE filas por canal y consulta, sin colas en memoria. Duración
  máxima por conexión (el cliente reconecta y todo se revalida), latido para proxies, y
  límites de conexiones por usuario y por proceso.
* **Permisos en el servidor.** Los canales se eligen con los permisos del usuario al
  conectar y en cada revalidación (sesión revocada o caducada, usuario desactivado o rol
  cambiado). El filtro de site se aplica en SQL.
* **Sin datos simulados.** Solo se envía lo que está en la base.
"""

import json
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import Engine, exists, func, select
from sqlalchemy.orm import Session

from app.core.permissions import Permission
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.incident import Incident, IncidentActivity, IncidentAsset
from app.models.siem import SiemEvent, SiemSource
from app.services.site_service import in_site

PAGE = 100
CHANNELS = ("detection", "alert", "incident", "siem")
_PREFIX = {"detection": "d", "alert": "a", "incident": "i", "siem": "s"}
_CURSOR_RE = re.compile(r"^d(\d{1,19})-a(\d{1,19})-i(\d{1,19})-s(\d{1,19})$")

# Permiso que exige cada canal además de monitoring:read (el del propio stream).
CHANNEL_PERMISSIONS: dict[str, Permission] = {
    "detection": Permission.MONITORING_READ,
    "alert": Permission.MONITORING_READ,
    "incident": Permission.INCIDENTS_READ,
    # Las alertas SIEM son eventos individuales (IPs, usuarios): siem:evidence.
    "siem": Permission.SIEM_EVIDENCE,
}


def allowed_channels(permissions: frozenset[Permission]) -> tuple[str, ...]:
    return tuple(c for c in CHANNELS if CHANNEL_PERMISSIONS[c] in permissions)


@dataclass
class Cursor:
    detection: int = 0
    alert: int = 0
    incident: int = 0
    siem: int = 0

    def encode(self) -> str:
        return f"d{self.detection}-a{self.alert}-i{self.incident}-s{self.siem}"

    @classmethod
    def decode(cls, value: str | None) -> "Cursor | None":
        """None si no hay cursor o no tiene la forma exacta (se empieza en el presente)."""
        if not value or len(value) > 100:
            return None
        match = _CURSOR_RE.fullmatch(value.strip())
        if match is None:
            return None
        d, a, i, s = (int(g) for g in match.groups())
        return cls(d, a, i, s)

    def get(self, channel: str) -> int:
        return int(getattr(self, channel))

    def set(self, channel: str, value: int) -> None:
        setattr(self, channel, value)


@dataclass
class LiveItem:
    channel: str
    id: int
    payload: dict[str, Any]


@dataclass
class PollResult:
    items: list[LiveItem] = field(default_factory=list)
    # Algún canal devolvió una página llena: queda atraso por leer.
    more: bool = False
    # Cursor explícito por canal cuando avanza más allá del último elemento enviado.
    advance: dict[str, int] = field(default_factory=dict)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _enum(value: Any) -> str:
    return str(getattr(value, "value", value))


class LiveReader:
    """Consultas del stream. Una sesión corta por llamada: no retiene conexiones."""

    def __init__(self, engine: Engine, site_id: int | None) -> None:
        self._engine = engine
        self._site_id = site_id

    def _session(self) -> Session:
        return Session(bind=self._engine, expire_on_commit=False)

    def heads(self) -> Cursor:
        """Últimos ids actuales (para empezar en el presente)."""
        with self._session() as s:
            return Cursor(
                int(s.scalar(select(func.coalesce(func.max(Detection.id), 0))) or 0),
                int(s.scalar(select(func.coalesce(func.max(Alert.id), 0))) or 0),
                int(s.scalar(select(func.coalesce(func.max(IncidentActivity.id), 0))) or 0),
                int(s.scalar(select(func.coalesce(func.max(SiemEvent.id), 0))) or 0),
            )

    def backlog(self, cursor: Cursor, channels: tuple[str, ...], limit: int) -> bool:
        """True si algún canal tiene más de `limit` filas pendientes (se contará como salto)."""
        with self._session() as s:
            for channel in channels:
                model: Any = {
                    "detection": Detection,
                    "alert": Alert,
                    "incident": IncidentActivity,
                    "siem": SiemEvent,
                }[channel]
                pending = select(model.id).where(model.id > cursor.get(channel))
                if channel == "siem":
                    pending = pending.where(SiemEvent.category == "detection")
                pending = pending.limit(limit + 1)
                if int(s.scalar(select(func.count()).select_from(pending.subquery())) or 0) > limit:
                    return True
        return False

    def poll(self, cursor: Cursor, channels: tuple[str, ...]) -> PollResult:
        result = PollResult()
        with self._session() as s:
            for channel in channels:
                if channel == "siem":
                    items, head = self._siem(s, cursor.siem)
                    if len(items) < PAGE and head > cursor.siem:
                        # Nada más que enviar hasta `head`: se salta el resto de eventos SIEM
                        # (no alertas) para no volver a recorrerlos en cada consulta.
                        result.advance["siem"] = head
                else:
                    fetch: Callable[[Session, int], list[LiveItem]] = getattr(self, f"_{channel}")
                    items = fetch(s, cursor.get(channel))
                result.items.extend(items)
                if len(items) >= PAGE:
                    result.more = True
        return result

    def _detection(self, s: Session, after: int) -> list[LiveItem]:
        query = (
            select(Detection, Asset)
            .join(Asset, Asset.id == Detection.asset_id)
            .where(Detection.id > after)
        )
        condition = in_site(Detection.asset_id, self._site_id)
        if condition is not None:
            query = query.where(condition)
        rows = s.execute(query.order_by(Detection.id).limit(PAGE)).all()
        # Solo campos de catálogo y del activo: nunca detalles ni evidencia de endpoint
        # (esos exigen telemetry:read y se ven en el detalle de la detección).
        return [
            LiveItem(
                "detection",
                d.id,
                {
                    "id": str(d.public_id),
                    "rule_id": d.rule_id,
                    "title": d.title,
                    "severity": _enum(d.severity),
                    "confidence": _enum(d.confidence),
                    "status": _enum(d.status),
                    "asset_id": str(asset.public_id),
                    "asset_name": asset.display_name,
                    "at": _iso(d.last_seen_at),
                },
            )
            for d, asset in rows
        ]

    def _alert(self, s: Session, after: int) -> list[LiveItem]:
        query = select(Alert, Asset).join(Asset, Asset.id == Alert.asset_id).where(Alert.id > after)
        condition = in_site(Alert.asset_id, self._site_id)
        if condition is not None:
            query = query.where(condition)
        rows = s.execute(query.order_by(Alert.id).limit(PAGE)).all()
        return [
            LiveItem(
                "alert",
                a.id,
                {
                    "id": str(a.public_id),
                    "rule": _enum(a.rule),
                    "severity": _enum(a.severity),
                    "status": _enum(a.status),
                    "message": a.message,
                    "asset_id": str(asset.public_id),
                    "asset_name": asset.display_name,
                    "at": _iso(a.opened_at),
                },
            )
            for a, asset in rows
        ]

    def _incident(self, s: Session, after: int) -> list[LiveItem]:
        query = (
            select(IncidentActivity, Incident)
            .join(Incident, Incident.id == IncidentActivity.incident_id)
            .where(IncidentActivity.id > after)
        )
        if self._site_id is not None:
            # Un caso pertenece a un site si tiene algún activo de ese site.
            query = query.where(
                exists(
                    select(IncidentAsset.id)
                    .join(Asset, Asset.id == IncidentAsset.asset_id)
                    .where(
                        IncidentAsset.incident_id == Incident.id,
                        Asset.site_id == self._site_id,
                    )
                )
            )
        rows = s.execute(query.order_by(IncidentActivity.id).limit(PAGE)).all()
        return [
            LiveItem(
                "incident",
                act.id,
                {
                    "id": str(inc.public_id),
                    "number": inc.number,
                    "title": inc.title,
                    "severity": _enum(inc.severity),
                    "status": _enum(inc.status),
                    "action": act.action,
                    "summary": act.summary,
                    "actor": act.actor,
                    "at": _iso(act.occurred_at),
                },
            )
            for act, inc in rows
        ]

    def _siem(self, s: Session, after: int) -> tuple[list[LiveItem], int]:
        # Solo alertas (categoría detection): el resto de eventos SIEM puede ser miles por
        # segundo y se consulta en la búsqueda. El máximo se lee ANTES y acota la consulta:
        # una alerta que entra entre las dos lecturas queda para la siguiente, no se pierde.
        head = int(s.scalar(select(func.coalesce(func.max(SiemEvent.id), 0))) or 0)
        query = (
            select(SiemEvent, SiemSource)
            .join(SiemSource, SiemSource.id == SiemEvent.source_id)
            .where(
                SiemEvent.id > after,
                SiemEvent.id <= head,
                SiemEvent.category == "detection",
            )
        )
        if self._site_id is not None:
            query = query.where(SiemEvent.site_id == self._site_id)
        rows = s.execute(query.order_by(SiemEvent.id).limit(PAGE)).all()
        items = [
            LiveItem(
                "siem",
                e.id,
                {
                    "id": str(e.event_id),
                    "source_name": src.name,
                    "source_type": e.source_type,
                    "event_type": e.event_type,
                    "severity": e.severity,
                    "message": e.message,
                    "src_ip": e.src_ip,
                    "dst_ip": e.dst_ip,
                    "origin": (e.attribution or {}).get("origin"),
                    "at": _iso(e.observed_at),
                },
            )
            for e, src in rows
        ]
        return items, head


def sse(event: str, data: dict[str, Any], event_id: str | None = None) -> str:
    """Mensaje SSE. `data` va en una sola línea JSON: un salto de línea en un campo de texto
    no puede inyectar campos SSE (json.dumps lo escapa)."""
    lines = [f"event: {event}"]
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.append("data: " + json.dumps(data, separators=(",", ":"), ensure_ascii=False))
    return "\n".join(lines) + "\n\n"


class StreamSlots:
    """Conexiones abiertas en ESTE proceso (por usuario y total). Sin estado compartido: con
    varios workers el límite efectivo es por worker, documentado así."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_user: dict[int, int] = {}
        self._total = 0

    def acquire(self, user_id: int, per_user: int, total: int) -> bool:
        with self._lock:
            if self._total >= total or self._by_user.get(user_id, 0) >= per_user:
                return False
            self._by_user[user_id] = self._by_user.get(user_id, 0) + 1
            self._total += 1
            return True

    def release(self, user_id: int) -> None:
        with self._lock:
            count = self._by_user.get(user_id, 0) - 1
            if count <= 0:
                self._by_user.pop(user_id, None)
            else:
                self._by_user[user_id] = count
            self._total = max(0, self._total - 1)

    @property
    def total(self) -> int:
        return self._total

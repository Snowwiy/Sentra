"""Asociaciones manuales de identidad (Fase 7B.2, docs/device-identity-wifi.md).

Una ASOCIACIÓN dice "esta observación es este dispositivo conocido" cuando la evidencia
automática no puede demostrarlo (MAC privada que rotó, registro descubierto duplicado,
cliente Wi-Fi sin coincidencia). Siempre la decide un admin con motivo, tras una vista
previa con la evidencia; nunca la crea el motor de identidad.

No fusiona historiales ni borra nada:
- `asset_alias`: el registro alias se ARCHIVA (se conserva con todo su historial) y su MAC
  pasa a resolverse al activo destino en los siguientes discovery;
- `wlan_client`: el cliente Wi-Fi queda asociado al activo con base `manual`.
Revocar la asociación deshace exactamente lo que hizo (`previous_state`) y queda auditado.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, CheckConstraint, DateTime, ForeignKey, Index, String, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

LINK_KINDS = ("asset_alias", "wlan_client")


class AssetIdentityLink(Base):
    __tablename__ = "asset_identity_links"
    __table_args__ = (
        Index("ix_asset_identity_links_target", "target_asset_id"),
        Index("ix_asset_identity_links_alias", "alias_asset_id"),
        Index("ix_asset_identity_links_wlan_client", "wlan_client_id"),
        Index("ix_asset_identity_links_site", "site_id"),
        CheckConstraint(
            "kind IN ('asset_alias', 'wlan_client')", name="ck_asset_identity_links_kind"
        ),
        CheckConstraint(
            "(kind = 'asset_alias' AND wlan_client_id IS NULL)"
            " OR (kind = 'wlan_client' AND alias_asset_id IS NULL)",
            name="ck_asset_identity_links_subject",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    kind: Mapped[str] = mapped_column(String(16))
    target_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    # El alias puede borrarse más tarde (limpieza 5C.2): la asociación conserva su foto en
    # `evidence` y la FK queda nula.
    alias_asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    wlan_client_id: Mapped[int | None] = mapped_column(
        ForeignKey("wlan_clients.id", ondelete="SET NULL")
    )
    # MAC observada que la asociación resuelve al destino (null si no hay MAC).
    mac: Mapped[str | None] = mapped_column(String(17))
    reason: Mapped[str] = mapped_column(String(500))
    # Foto de lo que se asoció y de la evidencia mostrada en la vista previa.
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB)
    # Estado anterior exacto para deshacer (archivado del alias, asociación previa del
    # cliente Wi-Fi).
    previous_state: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(String(64))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(String(500))

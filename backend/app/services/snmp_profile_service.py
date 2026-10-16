"""Perfiles de credenciales SNMP (Fase 6B, docs/snmp-network-intelligence.md).

Reglas de seguridad:
- Los secretos (passphrases v3, comunidad v2c) son de solo escritura: entran al crear o rotar
  y se cifran en el acto (app/core/secret_box.py). Ninguna respuesta de la API, entrada de
  auditoría, log ni informe los contiene.
- Alcance de site explícito: un perfil solo sirve para equipos de su site y solo se entrega
  a un sensor de ese site, para un job concreto ya iniciado (credentials_for_job).
- Revocar destruye el secreto guardado (no solo lo marca): un perfil revocado no puede volver
  a usarse por error. Para recuperar el acceso se crea otro perfil.
- SNMPv2c solo si SNMP_ALLOW_V2C=true; si se deshabilita después, los perfiles v2c existentes
  dejan de entregarse a los sensores (credentials_unavailable) sin borrarse.
"""

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import (
    SecretStoreUnavailableError,
    SiteConflictError,
    SiteNotFoundError,
    SnmpProfileNotFoundError,
)
from app.core.secret_box import SecretBox, SecretDecryptError, SecretStoreError, open_secret_box
from app.models.network import NetworkDevice, SnmpCredentialProfile
from app.models.site import Site
from app.schemas.network import (
    SnmpProfileCreate,
    SnmpProfileList,
    SnmpProfileRead,
    SnmpProfileRevoke,
    SnmpProfileRotate,
    SnmpProfileUpdate,
    check_credentials,
)
from app.services import audit_service
from app.services.audit_service import Actor
from app.services.site_service import site_refs

logger = logging.getLogger(__name__)


class CredentialsUnavailableError(Exception):
    """El perfil de un job no puede entregarse al sensor (motivo en `reason`, sin secretos)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def secret_context(profile_public: uuid.UUID, site_public: uuid.UUID) -> str:
    """AAD del secreto: lo liga al perfil y a su site (un blob copiado no se descifra)."""
    return f"snmp-profile:{profile_public}:site:{site_public}"


def secret_box(settings: Settings) -> SecretBox:
    try:
        return open_secret_box(settings.snmp_credential_key_file, settings.snmp_key_readers)
    except SecretStoreError as exc:
        # El detalle (ruta, permisos) va solo al log del servidor, nunca a la respuesta.
        logger.error("SNMP secret store unavailable", extra={"error": str(exc)})
        raise SecretStoreUnavailableError(
            "The encrypted SNMP credential store is not configured on the server"
        ) from exc


def secret_store_available(settings: Settings) -> bool:
    try:
        open_secret_box(settings.snmp_credential_key_file, settings.snmp_key_readers)
    except SecretStoreError:
        return False
    return True


def _secret_values(
    version: str, auth: str | None, priv: str | None, community: str | None
) -> dict[str, str]:
    if version == "v3":
        assert auth is not None and priv is not None  # noqa: S101  (validado en el esquema)
        return {"auth_password": auth, "priv_password": priv}
    assert community is not None  # noqa: S101
    return {"community": community}


class SnmpProfileService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    # --- lectura -----------------------------------------------------------------------------

    def _reads(self, rows: list[SnmpCredentialProfile]) -> list[SnmpProfileRead]:
        if not rows:
            return []
        sites = site_refs(self._session)
        counts = dict(
            self._session.execute(
                select(NetworkDevice.profile_id, func.count())
                .where(
                    NetworkDevice.profile_id.in_([row.id for row in rows]),
                    NetworkDevice.status == "active",
                )
                .group_by(NetworkDevice.profile_id)
            ).all()
        )
        return [
            SnmpProfileRead(
                profile_id=row.public_id,
                site_id=sites[row.site_id].public_id,
                site_name=sites[row.site_id].name,
                name=row.name,
                description=row.description,
                snmp_version=row.snmp_version,
                security_level="authPriv" if row.snmp_version == "v3" else "community",
                username=row.username,
                auth_protocol=row.auth_protocol,
                priv_protocol=row.priv_protocol,
                status=row.status,
                secret_configured=bool(row.secret_blob),
                secret_updated_at=row.secret_updated_at if row.secret_blob else None,
                secret_revision=row.secret_revision,
                devices_count=int(counts.get(row.id, 0)),
                created_at=row.created_at,
                created_by=row.created_by,
                updated_at=row.updated_at,
                revoked_at=row.revoked_at,
                revoked_by=row.revoked_by,
                revoke_reason=row.revoke_reason,
                version=row.version,
            )
            for row in rows
        ]

    def list(self, site_id: int | None, include_revoked: bool) -> SnmpProfileList:
        query = select(SnmpCredentialProfile).order_by(
            SnmpCredentialProfile.site_id, SnmpCredentialProfile.name
        )
        if site_id is not None:
            query = query.where(SnmpCredentialProfile.site_id == site_id)
        if not include_revoked:
            query = query.where(SnmpCredentialProfile.status == "active")
        return SnmpProfileList(
            items=self._reads(list(self._session.scalars(query).all())),
            secret_store_available=secret_store_available(self._settings),
            v2c_allowed=self._settings.snmp_allow_v2c,
        )

    def row(self, public_id: uuid.UUID, *, lock: bool = False) -> SnmpCredentialProfile:
        query = select(SnmpCredentialProfile).where(SnmpCredentialProfile.public_id == public_id)
        if lock:
            query = query.with_for_update()
        row = self._session.scalar(query)
        if row is None:
            raise SnmpProfileNotFoundError("SNMP profile not found")
        return row

    def get(self, public_id: uuid.UUID) -> SnmpProfileRead:
        return self._reads([self.row(public_id)])[0]

    # --- escritura ---------------------------------------------------------------------------

    def create(self, body: SnmpProfileCreate, actor: Actor) -> SnmpProfileRead:
        session = self._session
        site = session.scalar(select(Site).where(Site.public_id == body.site_id))
        if site is None:
            raise SiteNotFoundError("Site not found")
        if site.status != "active":
            raise SiteConflictError("site_not_active", f"Site is {site.status}")
        if body.snmp_version == "v2c" and not self._settings.snmp_allow_v2c:
            raise SiteConflictError(
                "snmp_v2c_disabled", "SNMPv2c is disabled on this server (SNMP_ALLOW_V2C)"
            )
        box = secret_box(self._settings)
        now = datetime.now(UTC)
        public_id = uuid.uuid4()
        values = _secret_values(
            body.snmp_version,
            body.auth_password.get_secret_value() if body.auth_password else None,
            body.priv_password.get_secret_value() if body.priv_password else None,
            body.community.get_secret_value() if body.community else None,
        )
        blob, kid = box.encrypt(values, secret_context(public_id, site.public_id))
        row = SnmpCredentialProfile(
            public_id=public_id,
            site_id=site.id,
            name=body.name,
            description=body.description,
            snmp_version=body.snmp_version,
            username=body.username if body.snmp_version == "v3" else None,
            auth_protocol=body.auth_protocol,
            priv_protocol=body.priv_protocol,
            secret_blob=blob,
            secret_key_id=kid,
            secret_revision=1,
            secret_updated_at=now,
            status="active",
            created_by=actor.name,
        )
        try:
            with session.begin_nested():
                session.add(row)
                session.flush()
        except IntegrityError as exc:
            raise SiteConflictError(
                "snmp_profile_name_taken", "A profile with this name already exists in the site"
            ) from exc
        audit_service.record(
            session,
            actor,
            "snmp_profile_created",
            target_type="snmp_profile",
            target_id=row.public_id,
            details={
                "site_id": str(site.public_id),
                "name": row.name,
                "snmp_version": row.snmp_version,
                "auth_protocol": row.auth_protocol,
                "priv_protocol": row.priv_protocol,
            },
            commit=False,
        )
        session.commit()
        logger.info("snmp profile created", extra={"profile": str(row.public_id)})
        return self.get(row.public_id)

    def _locked(self, public_id: uuid.UUID, version: int) -> SnmpCredentialProfile:
        row = self.row(public_id, lock=True)
        if row.status == "revoked":
            raise SiteConflictError("snmp_profile_revoked", "SNMP profile is revoked")
        if row.version != version:
            raise SiteConflictError(
                "snmp_profile_conflict",
                "SNMP profile changed since it was loaded; reload and retry",
                [{"current_version": row.version}],
            )
        return row

    def update(
        self, public_id: uuid.UUID, body: SnmpProfileUpdate, actor: Actor
    ) -> SnmpProfileRead:
        row = self._locked(public_id, body.version)
        changed = []
        if body.name is not None and body.name != row.name:
            row.name = body.name
            changed.append("name")
        if body.description is not None and body.description != row.description:
            row.description = body.description or None
            changed.append("description")
        if changed:
            row.version += 1
            try:
                with self._session.begin_nested():
                    self._session.flush()
            except IntegrityError as exc:
                raise SiteConflictError(
                    "snmp_profile_name_taken",
                    "A profile with this name already exists in the site",
                ) from exc
            audit_service.record(
                self._session,
                actor,
                "snmp_profile_updated",
                target_type="snmp_profile",
                target_id=row.public_id,
                details={"changed": changed},
                commit=False,
            )
        self._session.commit()
        return self.get(public_id)

    def rotate(
        self, public_id: uuid.UUID, body: SnmpProfileRotate, actor: Actor
    ) -> SnmpProfileRead:
        """Sustituye el secreto (y en v3, opcionalmente, usuario y protocolos).

        Los jobs que ya recibieron la credencial anterior terminan con ella; los siguientes
        reciben la nueva. secret_revision permite ver en el historial con cuál se hizo cada uno.
        """
        session = self._session
        row = self._locked(public_id, body.version)
        try:
            check_credentials(row.snmp_version, body, require_all=False)
        except ValueError as exc:
            raise SiteConflictError("snmp_profile_invalid", str(exc)) from exc
        if row.snmp_version == "v2c" and not self._settings.snmp_allow_v2c:
            raise SiteConflictError(
                "snmp_v2c_disabled", "SNMPv2c is disabled on this server (SNMP_ALLOW_V2C)"
            )
        box = secret_box(self._settings)
        site = session.get(Site, row.site_id)
        assert site is not None  # noqa: S101  (FK RESTRICT)
        context = secret_context(row.public_id, site.public_id)
        changed: list[str] = []
        if row.snmp_version == "v3":
            nothing = (
                body.auth_password is None
                and body.priv_password is None
                and body.username is None
                and body.auth_protocol is None
                and body.priv_protocol is None
            )
            if nothing:
                raise SiteConflictError("snmp_profile_invalid", "Nothing to rotate")
            try:
                current = box.decrypt(row.secret_blob, context)
            except SecretDecryptError:
                current = {}
            auth = (
                body.auth_password.get_secret_value()
                if body.auth_password
                else current.get("auth_password")
            )
            priv = (
                body.priv_password.get_secret_value()
                if body.priv_password
                else current.get("priv_password")
            )
            if not auth or not priv:
                # El secreto actual no se puede leer (clave retirada): hay que dar los dos.
                raise SiteConflictError(
                    "snmp_profile_invalid",
                    "Both auth_password and priv_password are required for this rotation",
                )
            if auth == priv:
                raise SiteConflictError(
                    "snmp_profile_invalid", "auth_password and priv_password must differ"
                )
            values = {"auth_password": auth, "priv_password": priv}
            if body.auth_password is not None:
                changed.append("auth")
            if body.priv_password is not None:
                changed.append("priv")
            if body.username is not None and body.username != row.username:
                row.username = body.username
                changed.append("username")
            if body.auth_protocol is not None and body.auth_protocol != row.auth_protocol:
                row.auth_protocol = body.auth_protocol
                changed.append("auth_protocol")
            if body.priv_protocol is not None and body.priv_protocol != row.priv_protocol:
                row.priv_protocol = body.priv_protocol
                changed.append("priv_protocol")
        else:
            if body.community is None:
                raise SiteConflictError("snmp_profile_invalid", "A new community is required")
            values = {"community": body.community.get_secret_value()}
            changed.append("community")
        row.secret_blob, row.secret_key_id = box.encrypt(values, context)
        row.secret_revision += 1
        row.secret_updated_at = datetime.now(UTC)
        row.version += 1
        # Los jobs ya encolados llevan la revisión y los protocolos anteriores: el sensor los
        # rechazaría al no coincidir con la credencial nueva. Se cancelan y se piden de nuevo.
        from app.services.network_jobs import cancel_profile_polls

        cancelled = cancel_profile_polls(session, row.id, "snmp_profile_rotated")
        audit_service.record(
            session,
            actor,
            "snmp_profile_rotated",
            target_type="snmp_profile",
            target_id=row.public_id,
            details={
                "changed": changed,
                "revision": row.secret_revision,
                "polls_cancelled": cancelled,
            },
            commit=False,
        )
        session.commit()
        return self.get(public_id)

    def revoke(
        self, public_id: uuid.UUID, body: SnmpProfileRevoke, actor: Actor
    ) -> SnmpProfileRead:
        from app.services.network_jobs import cancel_profile_polls

        session = self._session
        row = self._locked(public_id, body.version)
        now = datetime.now(UTC)
        row.status = "revoked"
        row.revoked_at = now
        row.revoked_by = actor.name
        row.revoke_reason = body.reason
        # Se destruye el secreto: una revocación no debe dejar una credencial recuperable.
        row.secret_blob = ""
        row.version += 1
        cancelled = cancel_profile_polls(session, row.id, "snmp_profile_revoked")
        audit_service.record(
            session,
            actor,
            "snmp_profile_revoked",
            target_type="snmp_profile",
            target_id=row.public_id,
            details={"reason": body.reason, "polls_cancelled": cancelled},
            commit=False,
        )
        session.commit()
        return self.get(public_id)


def rekey_all(session: Session, settings: Settings) -> dict[str, int]:
    """Vuelve a cifrar todos los perfiles activos con la clave activa (CLI snmp-rekey).

    Los que no se pueden descifrar (clave ya retirada) se cuentan y se dejan como están: el
    admin debe rotar su credencial. Nunca imprime ni devuelve secretos.
    """
    box = secret_box(settings)
    sites = site_refs(session)
    counts = {"rekeyed": 0, "already_current": 0, "unreadable": 0}
    rows = session.scalars(
        select(SnmpCredentialProfile)
        .where(SnmpCredentialProfile.status == "active")
        .order_by(SnmpCredentialProfile.id)
        .with_for_update()
    ).all()
    for row in rows:
        if row.secret_key_id == box.active_kid:
            counts["already_current"] += 1
            continue
        context = secret_context(row.public_id, sites[row.site_id].public_id)
        try:
            values = box.decrypt(row.secret_blob, context)
        except SecretDecryptError:
            counts["unreadable"] += 1
            continue
        blob, kid = box.encrypt(values, context)
        # Se verifica el recifrado antes de sustituir: el blob nuevo debe descifrar igual.
        if box.decrypt(blob, context) != values:
            raise SecretStoreError("re-encrypted SNMP secret did not verify")
        row.secret_blob, row.secret_key_id = blob, kid
        counts["rekeyed"] += 1
    audit_service.record(
        session,
        audit_service.CLI,
        "snmp_profiles_rekeyed",
        target_type="snmp_profile",
        details=dict(counts),
        commit=False,
    )
    session.commit()
    return counts

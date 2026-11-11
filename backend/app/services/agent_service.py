import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, object_session

from app.core.exceptions import (
    AgentRecoveryRequiredError,
    AgentRevokedError,
    AssetArchivedError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    SecureTransportRequiredError,
    UnauthorizedError,
)
from app.core.security import (
    MAX_CREDENTIAL_LENGTH,
    RECOVERY_TOKEN_PREFIX,
    enrollment_key_matches,
    generate_agent_token,
    hash_token,
    token_matches,
)
from app.isolation.state import reconcile_report
from app.models.asset import Asset, AssetStatus
from app.models.enrollment import AgentRecoveryToken
from app.models.response import AgentCommand
from app.repositories.asset_repository import AssetRepository
from app.schemas.agent import (
    AgentRegisterRequest,
    AgentRegisterResponse,
    AgentRotateResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    HostInfo,
)
from app.services import audit_service
from app.services.alert_service import resolve_offline_alert
from app.services.enrollment_token_service import EnrollmentTokenService
from app.services.identification import refresh_identity
from app.services.reconciliation import adopt_discovered
from app.vulnerabilities.queue import mark_dirty

# Copia de app/response/catalog.AGENT_COMMAND_TYPES sin importar el catálogo (que importa
# servicios que importan este módulo). test_response.py comprueba que coinciden.
AGENT_COMMAND_TYPES = frozenset(
    {
        "collect_inventory",
        "collect_processes",
        "collect_events",
        "collect_telemetry",
        "collect_diagnostics",
        "forensic_processes",
        "forensic_connections",
        "forensic_services",
        "forensic_scheduled_tasks",
        "forensic_persistence",
        "forensic_sessions",
        "forensic_network_config",
        "forensic_firewall_state",
        "forensic_file_metadata",
        "isolate_host",
        "release_isolation",
    }
)


def pending_commands(session: Session, asset: Asset, now: datetime) -> int:
    """Comandos de Response en cola para el agente actual del activo (heartbeat)."""
    if asset.agent_id is None:
        return 0
    return int(
        session.scalar(
            select(func.count())
            .select_from(AgentCommand)
            .where(
                AgentCommand.asset_id == asset.id,
                AgentCommand.agent_id == asset.agent_id,
                AgentCommand.status == "queued",
                AgentCommand.expires_at > now,
            )
        )
        or 0
    )


logger = logging.getLogger(__name__)
# Actor de las entradas de auditoría que genera el propio servidor (sin usuario).
SYSTEM = audit_service.Actor("system")


def record_contact(session: Session, asset: Asset, now: datetime) -> None:
    """Record proof of life from any authenticated agent call and resolve its offline alert.

    `now` must be server time so agents cannot fake liveness. One UPDATE with GREATEST
    because concurrent calls of one agent (heartbeat, telemetry, events, inventory) take
    `now` before they commit, not necessarily in the same order: last_seen_at must never move
    backwards. The UPDATE also takes the asset's row lock, which the offline sweeper honors
    (AlertService.sweep_offline), so no offline alert is opened for an asset that is
    reporting at that very moment. Every agent call resolves the offline alert, not only
    heartbeats: the asset is shown online as soon as any of them arrives.
    """
    result = session.execute(
        update(Asset)
        # Fase 5C.2: también por agent_id. Si una reconciliación movió este agente a otro
        # activo mientras esta petición esperaba el bloqueo de la fila, PostgreSQL reevalúa
        # el WHERE sobre la fila ya actualizada y no la toca: la petición se deshace entera
        # (409, el agente reintenta) y sus datos llegan al activo correcto en el reintento,
        # en vez de quedar en el duplicado archivado.
        .where(Asset.id == asset.id, Asset.agent_id == asset.agent_id)
        .values(last_seen_at=func.greatest(Asset.last_seen_at, now), status=AssetStatus.ONLINE)
    )
    if result.rowcount == 0:  # type: ignore[attr-defined]
        raise ConflictError("The agent was reassigned to another asset, retry")
    resolve_offline_alert(session, asset.id, now)


def apply_host_info(asset: Asset, host: HostInfo) -> None:
    # Fase 5B: un cambio de SO (actualización de build, kernel nuevo) cambia qué
    # vulnerabilidades de SO aplican; se encola su evaluación, nunca en cada heartbeat.
    os_changed = (asset.os_name, asset.os_version) != (host.os_name, host.os_version)
    # Plain attribute assignment: SQLAlchemy only issues an UPDATE (and bumps updated_at)
    # for values that actually changed.
    asset.hostname = host.hostname
    asset.os_name = host.os_name
    asset.os_version = host.os_version
    asset.architecture = host.architecture
    asset.primary_ip = str(host.primary_ip)
    asset.agent_version = host.agent_version
    # Se asigna aunque venga vacío: refleja cómo corre el agente que informa ahora (p. ej.
    # un servicio desinstalado y el agente lanzado a mano deja de mostrar "Servicio Windows").
    asset.agent_installation_method = host.installation_method
    # Fase 5C.1: solo se actualiza si llega. Un agente anterior (o uno que no pudo leer
    # /etc/machine-id) no borra la identidad ya conocida, que sirve para sugerir duplicados.
    if host.machine_id_hash:
        asset.machine_id_hash = host.machine_id_hash
    # Fase 5D: capacidades de Response declaradas por el agente, filtradas por la allowlist
    # del servidor. Solo si llegan: un agente anterior las deja en null (sin acciones).
    if host.capabilities is not None:
        capabilities = sorted(set(host.capabilities) & AGENT_COMMAND_TYPES)
        if asset.agent_capabilities != capabilities:
            asset.agent_capabilities = capabilities
            asset.agent_capabilities_at = datetime.now(UTC)
    # El agente es la fuente autoritativa del nombre y del tipo: se recalcula con lo que
    # acaba de reportar (sin escrituras si nada cambió).
    refresh_identity(asset)
    session = object_session(asset)
    if os_changed and session is not None and asset.id is not None:
        mark_dirty(session, [asset.id], "os_change")


# Fase 7D.1 (H04): cómo llegó una petición de agente, visto por el servidor (esquema tras
# TrustedProxyMiddleware y dirección real del cliente).
TRANSPORT_HTTPS = "https"
TRANSPORT_HTTP_LOOPBACK = "http_loopback"
TRANSPORT_HTTP_REMOTE = "http_remote"
SECURE_TRANSPORTS = frozenset({TRANSPORT_HTTPS, TRANSPORT_HTTP_LOOPBACK})
ROTATION_INSECURE_TRANSPORT = "insecure_transport"
ROTATION_OPERATOR = "operator_request"


def authenticate_agent(assets: AssetRepository, agent_id: UUID, token: str | None) -> Asset:
    """Return the asset of an agent whose bearer token is valid, or raise 401.

    Unknown agent, missing token and wrong token all produce the same error so a caller
    cannot probe which agent_ids exist.

    Fase 7D.1 (H01): también vale la credencial PENDIENTE de una rotación; su primer uso la
    promueve a vigente e invalida la anterior en la misma transacción (UPDATE condicionado,
    sin carreras entre peticiones simultáneas del agente). Un 401 ya no lleva a un
    re-enrolamiento que sustituya la identidad: el agente necesita su credencial vigente o
    una recuperación autorizada.
    """
    asset = assets.get_by_agent_id(agent_id)
    if (
        asset is None
        or token is None
        # Revocation also clears the hash; checking the flag too keeps a revoked agent out even
        # if a hash were ever restored by hand or by a buggy migration.
        or asset.agent_token_revoked_at is not None
    ):
        raise UnauthorizedError("Invalid or missing agent credentials")
    if token_matches(token, asset.agent_token_hash):
        return asset
    if token_matches(token, asset.agent_token_pending_hash):
        session = object_session(asset)
        if session is None:  # pragma: no cover - el repositorio siempre devuelve filas vivas
            raise UnauthorizedError("Invalid or missing agent credentials")
        _promote_pending(session, asset)
        return asset
    raise UnauthorizedError("Invalid or missing agent credentials")


def _promote_pending(session: Session, asset: Asset) -> None:
    """Primer uso de la credencial rotada: pasa a vigente y la anterior deja de valer."""
    pending = asset.agent_token_pending_hash
    result = session.execute(
        update(Asset)
        .where(Asset.id == asset.id, Asset.agent_token_pending_hash == pending)
        .values(
            agent_token_hash=pending,
            agent_token_issued_at=Asset.agent_token_pending_issued_at,
            agent_token_pending_hash=None,
            agent_token_pending_issued_at=None,
            agent_credential_source="rotation",
            # La rotación pedida (transporte inseguro u operador) queda cumplida: la
            # credencial anterior, quizá expuesta, ya no vale.
            agent_rotation_requested_at=None,
            agent_rotation_reason=None,
        )
        .execution_options(synchronize_session=False)
    )
    session.refresh(asset)
    if result.rowcount:  # type: ignore[attr-defined]
        audit_service.record(
            session,
            SYSTEM,
            "agent_credential_rotation_completed",
            target_type="asset",
            target_id=asset.public_id,
            details={"agent_id": str(asset.agent_id)},
            commit=False,
        )


def note_transport(asset: Asset, transport: str, now: datetime) -> None:
    """Inventario de transporte (H04): último transporte y exposición de la credencial.

    Una credencial que viajó por HTTP fuera de loopback se considera expuesta: se pide su
    rotación, que el agente 0.7.0 hace en cuanto pueda hablar por HTTPS. Nunca se corta a un
    agente por esto (lo dejaría sin monitorizar sin aviso); el panel lo lista para migrarlo.
    """
    if asset.agent_transport != transport:
        asset.agent_transport = transport
    asset.agent_transport_at = now
    if transport == TRANSPORT_HTTP_REMOTE:
        asset.agent_insecure_transport_at = now
        if asset.agent_rotation_requested_at is None:
            asset.agent_rotation_requested_at = now
            asset.agent_rotation_reason = ROTATION_INSECURE_TRANSPORT


def revoke_agent(session: Session, asset_public_id: UUID) -> Asset:
    """Invalidate an agent's token now and block its re-enrollment until reinstated.

    Revocation is per agent: other agents and the shared enrollment key keep working. The
    agent's next call gets 401 and its enrollment attempts get 403 agent_revoked, after
    which it backs off to its maximum retry interval. Its history is kept.
    """
    asset = AssetRepository(session).get_by_public_id(asset_public_id)
    if asset is None:
        raise NotFoundError("Asset not found")
    asset.agent_token_hash = None
    asset.agent_token_issued_at = None
    # Fase 7D.1: una rotación a medias tampoco sobrevive a la revocación.
    asset.agent_token_pending_hash = None
    asset.agent_token_pending_issued_at = None
    if asset.agent_token_revoked_at is None:
        asset.agent_token_revoked_at = datetime.now(UTC)
    session.commit()
    return asset


def reinstate_agent(session: Session, asset_public_id: UUID) -> Asset:
    """Allow a revoked agent to come back.

    No token is issued here. Fase 7D.1 (H01): la vuelta exige una autorización de
    recuperación para ESTE activo (POST /agents/{asset_id}/recovery-tokens): un token de
    enrolamiento ordinario ya no sustituye la identidad de un agent_id existente.
    """
    asset = AssetRepository(session).get_by_public_id(asset_public_id)
    if asset is None:
        raise NotFoundError("Asset not found")
    asset.agent_token_revoked_at = None
    session.commit()
    return asset


class AgentService:
    def __init__(
        self,
        session: Session,
        enrollment_key: str | None,
        enrollment_key_expires_at: datetime | None = None,
    ) -> None:
        self._session = session
        self._assets = AssetRepository(session)
        self._enrollment_key = enrollment_key
        self._enrollment_key_expires_at = enrollment_key_expires_at
        self._tokens = EnrollmentTokenService(session)

    def register(
        self,
        data: AgentRegisterRequest,
        provided_key: str | None,
        enrollment_token: str | None = None,
        transport: str = TRANSPORT_HTTPS,
        client_ip: str | None = None,
    ) -> tuple[AgentRegisterResponse, bool]:
        """Alta de una identidad NUEVA, o recuperación autorizada. Devuelve (respuesta, creado).

        Fase 7D.1 (H01), tres operaciones separadas:
        - alta: token de un solo uso (recomendado) o clave compartida legacy. Solo crea
          agent_ids que no existen; un agent_id existente responde 403
          agent_recovery_required SIN consumir el token (cualquier site, cualquier estado);
        - recuperación: una autorización `sentra_et_rec_...` emitida por un admin para ese
          activo, agent_id y site; un solo uso, vida corta (`_recover`);
        - rotación: con la credencial vigente, en POST /agents/credentials/rotate (`rotate`).
        """
        if enrollment_token is not None:
            recovery = self._recovery_row(enrollment_token)
            if recovery is not None:
                return self._recover(recovery, data, transport, client_ip), False
        bootstrap = None
        if enrollment_token is not None:
            bootstrap = self._tokens.lock_for_enrollment(enrollment_token, data)
        else:
            if self._enrollment_key is None:
                raise ForbiddenError("Agent enrollment is disabled on this server")
            if not enrollment_key_matches(provided_key, self._enrollment_key):
                raise UnauthorizedError("Invalid enrollment key")
            if (
                self._enrollment_key_expires_at is not None
                and datetime.now(UTC) >= self._enrollment_key_expires_at
            ):
                # Comprobado DESPUÉS de la clave: sin ella no se revela si caducó.
                raise ForbiddenError(
                    "The shared enrollment key expired (AGENT_ENROLLMENT_KEY_EXPIRES_AT);"
                    " create a one-time enrollment token"
                )

        # Bloqueo de la fila del agent_id si existe: una recuperación o rotación concurrente
        # de la misma identidad espera a que esta petición termine.
        existing = self._session.scalar(
            select(Asset).where(Asset.agent_id == data.agent_id).with_for_update()
        )
        # Checked only after the credential, so revocation status is never revealed to
        # callers without one. A rejected enrollment never consumes the token (rollback).
        if existing is not None:
            self._session.rollback()
            self._audit_refused(data, bootstrap is not None, transport, client_ip)
            if existing.agent_token_revoked_at is not None:
                raise AgentRevokedError("This agent has been revoked by an operator")
            if existing.archived_at is not None:
                raise AssetArchivedError("The asset of this agent is archived")
            raise AgentRecoveryRequiredError(
                "This agent_id is already enrolled; an administrator must authorize its"
                " recovery (recovery token for this asset)"
            )

        token = generate_agent_token()
        now = datetime.now(UTC)
        asset = self._assets.add(
            Asset(
                agent_id=data.agent_id,
                hostname=data.hostname,
                os_name=data.os_name,
                os_version=data.os_version,
                architecture=data.architecture,
                primary_ip=str(data.primary_ip),
                agent_version=data.agent_version,
                agent_installation_method=data.installation_method,
                machine_id_hash=data.machine_id_hash,
                ever_managed=True,
                # Fase 5F: el site del token (si lo tiene); si no, el site por defecto
                # (valor por defecto de la columna). Solo al crear: moverlo es una acción
                # explícita de un admin.
                **(
                    {"site_id": bootstrap.site_id}
                    if bootstrap is not None and bootstrap.site_id is not None
                    else {}
                ),
                # Registration alone does not prove the agent keeps running; it becomes
                # online with its first heartbeat or telemetry sample.
                status=AssetStatus.UNKNOWN,
                first_seen_at=now,
            )
        )
        refresh_identity(asset)
        if data.capabilities is not None:
            asset.agent_capabilities = sorted(set(data.capabilities) & AGENT_COMMAND_TYPES)
            asset.agent_capabilities_at = now
        asset.agent_token_hash = hash_token(token)
        asset.agent_token_issued_at = now
        asset.agent_credential_source = "enrollment_token" if bootstrap else "legacy_key"
        note_transport(asset, transport, now)

        try:
            self._session.flush()
            # Installed on a host discovery already knew: converge into this asset. Only by
            # address here (the agent reports MACs with its inventory, which retries it).
            adopt_discovered(self._session, asset, {str(data.primary_ip)}, set())
            self._note_duplicates(asset)
            if bootstrap is not None:
                self._tokens.consume(bootstrap, asset)
            else:
                logger.info(
                    "agent enrolled with the shared enrollment key (legacy)",
                    extra={"agent_id": str(data.agent_id)},
                )
            audit_service.record(
                self._session,
                SYSTEM,
                "agent_enrolled",
                target_type="asset",
                target_id=asset.public_id,
                details={
                    "agent_id": str(data.agent_id),
                    "method": asset.agent_credential_source,
                    "transport": transport,
                    "client_ip": client_ip,
                },
                commit=False,
            )
            self._session.commit()
        except IntegrityError as exc:
            # Dos altas simultáneas del mismo agent_id: la UNIQUE de assets.agent_id deja
            # entrar a una sola. La otra NO toma la identidad: al reintentar recibe 403
            # agent_recovery_required (y su token no se consumió).
            self._session.rollback()
            raise ConflictError("Agent registration in progress, retry") from exc

        response = AgentRegisterResponse(
            asset_id=asset.public_id,
            agent_id=data.agent_id,
            status=asset.status,
            first_seen_at=asset.first_seen_at,
            agent_token=token,
        )
        return response, True

    def _audit_refused(
        self, data: AgentRegisterRequest, with_token: bool, transport: str, ip: str | None
    ) -> None:
        # Intento de dar de alta un agent_id existente: puede ser un clon de máquina virtual,
        # una reinstalación que conservó el estado o una suplantación. Queda en la auditoría
        # (sin el token) para que un admin lo vea y, si es legítimo, autorice la recuperación.
        audit_service.record(
            self._session,
            SYSTEM,
            "agent_enrollment_refused",
            audit_service.DENIED,
            target_type="agent",
            target_id=str(data.agent_id),
            details={
                "reason": AgentRecoveryRequiredError.code,
                "method": "enrollment_token" if with_token else "legacy_key",
                "hostname": data.hostname[:255],
                "transport": transport,
                "client_ip": ip,
            },
        )

    # --- Recuperación (H01) ----------------------------------------------------------------

    def _recovery_row(self, token: str) -> AgentRecoveryToken | None:
        if not token.startswith(RECOVERY_TOKEN_PREFIX) or len(token) > MAX_CREDENTIAL_LENGTH:
            return None
        return self._session.scalar(
            select(AgentRecoveryToken)
            .where(AgentRecoveryToken.token_hash == hash_token(token))
            .with_for_update()
        )

    def _recover(
        self,
        row: AgentRecoveryToken,
        data: AgentRegisterRequest,
        transport: str,
        client_ip: str | None,
    ) -> AgentRegisterResponse:
        """Sustituye la credencial de UN agente existente con una autorización de admin.

        Todas las comprobaciones se hacen con las filas bloqueadas (token y activo) y el
        mismo 401 para cualquier motivo, igual que los tokens de enrolamiento: quien no
        tiene la autorización correcta no aprende nada. Consumo en la misma transacción.
        """
        now = datetime.now(UTC)
        asset = self._session.scalar(
            select(Asset).where(Asset.id == row.asset_id).with_for_update()
        )
        reason: str | None = None
        if transport not in SECURE_TRANSPORTS:
            reason = "insecure transport"
        elif row.state(now).value != "active":
            reason = row.state(now).value
        elif asset is None:
            reason = "asset deleted"
        elif row.agent_id != data.agent_id or asset.agent_id != data.agent_id:
            reason = "agent mismatch"
        elif row.site_id is not None and asset.site_id != row.site_id:
            reason = "site mismatch"
        elif row.expected_hostname and row.expected_hostname.lower() != data.hostname.lower():
            reason = "hostname mismatch"
        elif asset.agent_token_revoked_at is not None:
            reason = "agent revoked"
        elif asset.archived_at is not None:
            reason = "asset archived"
        if reason is not None or asset is None:
            self._session.rollback()
            logger.warning(
                "agent recovery rejected",
                extra={"reason": reason, "recovery_id": str(row.public_id)},
            )
            audit_service.record(
                self._session,
                SYSTEM,
                "agent_recovery_rejected",
                audit_service.DENIED,
                target_type="agent",
                target_id=str(data.agent_id),
                details={
                    "recovery": str(row.public_id),
                    "reason": reason,
                    "client_ip": client_ip,
                },
            )
            if reason == "insecure transport":
                raise SecureTransportRequiredError("Agent recovery requires HTTPS (or loopback)")
            raise UnauthorizedError("Invalid enrollment token")
        token = generate_agent_token()
        apply_host_info(asset, data)
        asset.agent_token_hash = hash_token(token)
        asset.agent_token_issued_at = now
        asset.agent_token_pending_hash = None
        asset.agent_token_pending_issued_at = None
        asset.agent_credential_source = "recovery"
        asset.agent_rotation_requested_at = None
        asset.agent_rotation_reason = None
        note_transport(asset, transport, now)
        row.used_at = now
        audit_service.record(
            self._session,
            SYSTEM,
            "agent_recovered",
            target_type="asset",
            target_id=asset.public_id,
            details={
                "agent_id": str(data.agent_id),
                "recovery": str(row.public_id),
                "authorized_by": row.created_by,
                "transport": transport,
                "client_ip": client_ip,
            },
            commit=False,
        )
        self._session.commit()
        logger.info(
            "agent recovered",
            extra={"asset_id": str(asset.public_id), "recovery_id": str(row.public_id)},
        )
        return AgentRegisterResponse(
            asset_id=asset.public_id,
            agent_id=data.agent_id,
            status=asset.status,
            first_seen_at=asset.first_seen_at or now,
            agent_token=token,
        )

    # --- Rotación (H01) --------------------------------------------------------------------

    def rotate(
        self, agent_id: UUID, token: str | None, transport: str, client_ip: str | None
    ) -> AgentRotateResponse:
        """Credencial nueva a cambio de la vigente (nunca con una clave de instalación).

        La fila del activo se bloquea y la credencial se comprueba bajo el bloqueo: dos
        rotaciones simultáneas no pueden dejar dos credenciales válidas nuevas. La nueva
        queda pendiente hasta su primer uso (ver authenticate_agent).
        """
        asset = self._session.scalar(
            select(Asset).where(Asset.agent_id == agent_id).with_for_update()
        )
        if (
            asset is None
            or token is None
            or asset.agent_token_revoked_at is not None
            or not (
                token_matches(token, asset.agent_token_hash)
                or token_matches(token, asset.agent_token_pending_hash)
            )
        ):
            self._session.rollback()
            raise UnauthorizedError("Invalid or missing agent credentials")
        if transport not in SECURE_TRANSPORTS:
            # La credencial nueva viajaría en claro: no se emite. La rotación pedida sigue
            # pendiente hasta que el agente hable por HTTPS.
            self._session.rollback()
            raise SecureTransportRequiredError("Credential rotation requires HTTPS")
        if asset.archived_at is not None:
            self._session.rollback()
            raise AssetArchivedError("The asset of this agent is archived")
        if token_matches(token, asset.agent_token_pending_hash):
            # El agente ya usa la pendiente (respuesta anterior recibida): se promueve antes.
            _promote_pending(self._session, asset)
        now = datetime.now(UTC)
        new_token = generate_agent_token()
        asset.agent_token_pending_hash = hash_token(new_token)
        asset.agent_token_pending_issued_at = now
        note_transport(asset, transport, now)
        audit_service.record(
            self._session,
            SYSTEM,
            "agent_credential_rotated",
            target_type="asset",
            target_id=asset.public_id,
            details={
                "agent_id": str(agent_id),
                "reason": asset.agent_rotation_reason,
                "client_ip": client_ip,
            },
            commit=False,
        )
        self._session.commit()
        return AgentRotateResponse(asset_id=asset.public_id, agent_token=new_token, issued_at=now)

    def _note_duplicates(self, asset: Asset) -> None:
        """Audita si el agente nuevo parece un activo ya conocido (reinstalación).

        Solo sugiere: nada se une automáticamente (docs/agent-asset-lifecycle.md). Un fallo
        aquí nunca impide enrolar: va en su propio SAVEPOINT.
        """
        # Import local: asset_lifecycle_service importa servicios que importan este módulo.
        from app.services.asset_lifecycle_service import AssetLifecycleService

        try:
            with self._session.begin_nested():
                found = AssetLifecycleService(self._session, timedelta(0)).detect_for_new_agent(
                    asset
                )
                if found:
                    audit_service.record(
                        self._session,
                        SYSTEM,
                        "asset_duplicate_detected",
                        target_type="asset",
                        target_id=asset.public_id,
                        details={
                            "candidates": [str(other.public_id) for other, _ in found[:10]],
                            "confidence": [result.confidence for _, result in found[:10]],
                            "reasons": sorted({r for _, result in found for r in result.reasons}),
                        },
                        commit=False,
                    )
        except Exception:
            logger.exception("duplicate detection failed at enrollment")

    def heartbeat(
        self, data: HeartbeatRequest, token: str | None, transport: str = TRANSPORT_HTTPS
    ) -> HeartbeatResponse:
        asset = authenticate_agent(self._assets, data.agent_id, token)
        now = datetime.now(UTC)
        record_contact(self._session, asset, now)
        note_transport(asset, transport, now)
        if data.host is not None:
            apply_host_info(asset, data.host)
        if data.telemetry is not None:
            # Se conserva lo que solo trae el lote de actividad (boot_id del árbol de procesos).
            asset.telemetry_status = {
                **(asset.telemetry_status or {}),
                **data.telemetry.model_dump(mode="json", exclude_none=True),
            }
            asset.telemetry_status_at = now
        if data.isolation is not None:
            reconcile_report(self._session, asset, data.isolation.model_dump(mode="json"), now)
        self._session.commit()
        return HeartbeatResponse(
            asset_id=asset.public_id,
            status=AssetStatus.ONLINE,
            # The stored value: a delayed heartbeat never reports an older time than the
            # newest contact already recorded.
            last_seen_at=asset.last_seen_at or now,
            pending_commands=pending_commands(self._session, asset, now),
            # Fase 7D.1: el agente 0.7.0 rota su credencial cuando lo ve. Solo se pide por un
            # transporte seguro: rotar por HTTP en claro expondría también la credencial nueva
            # (y el servidor la rechazaría con https_required).
            rotate_credential=(
                asset.agent_rotation_requested_at is not None and transport in SECURE_TRANSPORTS
            ),
        )

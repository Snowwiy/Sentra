"""Enrollment del sensor con un token de un solo uso.

El token de enrollment solo sirve para esta llamada: se envía en una cabecera dedicada (nunca
en la URL, que acaba en logs de proxies), se registra en el redactor de logs antes de
cualquier otra cosa y no se guarda en disco. Lo que se guarda es la credencial emitida.
"""

import logging
import string
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sentra_sensor import CAPABILITIES, __version__
from sentra_sensor.client import ApiError, SensorClient, Transport
from sentra_sensor.config import LocalConfig, validate_server_url
from sentra_sensor.credentials import CredentialStore, SensorIdentity
from sentra_sensor.logs import register_secret
from sentra_sensor.protocol import ServerConfig
from sentra_sensor.state import LocalState, host_metadata, save_state

logger = logging.getLogger("sentra_sensor.enrollment")

_TOKEN_CHARS = frozenset(string.ascii_letters + string.digits + "-_.~+/=")


class EnrollmentError(Exception):
    """Mensaje apto para mostrar al operador (nunca incluye el token)."""


def clean_token(raw: str) -> str:
    token = raw.strip()
    register_secret(token)
    # Juego de caracteres de token: evita inyectar cabeceras (CR/LF) o pegar basura.
    if not 16 <= len(token) <= 512 or not set(token) <= _TOKEN_CHARS:
        raise EnrollmentError("enrollment token has an invalid format")
    return token


@dataclass(frozen=True)
class EnrollmentResult:
    identity: SensorIdentity
    server_config: ServerConfig


def enroll(
    config: LocalConfig,
    server_url: str,
    token: str,
    transport: Transport,
    *,
    force: bool = False,
) -> EnrollmentResult:
    token = clean_token(token)
    server_url = validate_server_url(server_url)
    store = CredentialStore(config.credential_file())
    if store.exists() and not force:
        raise EnrollmentError(
            "this sensor is already enrolled; use --force to replace its credential"
        )
    client = SensorClient(server_url, transport, timeout=config.request_timeout_seconds)
    body = {
        **host_metadata(),
        "sensor_version": __version__,
        "capabilities": list(CAPABILITIES),
    }
    try:
        response = client.enroll(token, body)
    except ApiError as exc:
        if exc.status == 401:
            raise EnrollmentError(
                "the server rejected the enrollment token (unknown, expired, used or revoked)"
            ) from None
        if exc.status == 429:
            raise EnrollmentError("too many enrollment attempts; try again later") from None
        raise EnrollmentError(f"enrollment failed: HTTP {exc.status} {exc.code or ''}") from None
    credential = response.get("credential")
    if not isinstance(credential, str) or not credential:
        raise EnrollmentError("enrollment response did not include a credential")
    register_secret(credential)
    try:
        server_config = ServerConfig.parse(response.get("config"))
        identity = SensorIdentity(
            sensor_id=str(uuid.UUID(str(response["sensor_id"]))),
            site_id=str(uuid.UUID(str(response["site_id"]))),
            site_name=str(response.get("site_name") or ""),
            server_url=server_url,
            credential_issued_at=response.get("credential_issued_at"),
            enrolled_at=datetime.now(UTC).isoformat(),
            credential=credential,
        )
    except (KeyError, ValueError) as exc:
        raise EnrollmentError(f"unexpected enrollment response: {exc}") from None
    store.save(identity)
    save_state(config.state_file(), LocalState(server_config=server_config.to_json()))
    logger.info(
        "sensor enrolled", extra={"sensor_id": identity.sensor_id, "site_id": identity.site_id}
    )
    return EnrollmentResult(identity, server_config)

"""Resultado del enrolamiento, compartido por `--enroll` (instalador Linux) y el servicio Windows.

En Linux el instalador ejecuta `sentra-agent --enroll` como el usuario del servicio y lee el
código de salida. En Windows eso no es posible: el token individual se cifra con DPAPI en el
ámbito de la cuenta que lo guarda, y el instalador (un administrador interactivo) no puede
ejecutar procesos como la cuenta virtual `NT SERVICE\\SentraAgent`. Por eso es el propio
servicio quien enrola al arrancar y deja el resultado en `enrollment-status.json`, que el
instalador consulta. Ese archivo nunca contiene secretos.
"""

import json
import logging
import os
import threading
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from sentra_agent.client import TransportError
from sentra_agent.identity import write_atomic
from sentra_agent.logs import redact
from sentra_agent.runner import (
    Agent,
    CredentialsRejectedError,
    EnrollmentKeyMissingError,
    backoff_delay,
)

logger = logging.getLogger("sentra_agent")

# Códigos de salida de --enroll, leídos por el instalador Linux.
EXIT_ENROLLED = 0
EXIT_NO_CREDENTIAL = 3
EXIT_REJECTED = 4
EXIT_UNREACHABLE = 5

STATUS_FILE = "enrollment-status.json"

STATE_ENROLLED = "enrolled"
STATE_ALREADY_ENROLLED = "already_enrolled"
STATE_NO_CREDENTIAL = "no_credential"
STATE_REJECTED = "rejected"
STATE_UNREACHABLE = "unreachable"


@dataclass(frozen=True)
class EnrollmentOutcome:
    exit_code: int
    state: str
    # Una línea legible para el operador (instalador). Pasa por redact(): una excepción del
    # transporte o un cuerpo de error nunca deben filtrar un token a un archivo de estado.
    message: str
    agent_id: str
    asset_id: str | None


def enroll_once(agent: Agent) -> EnrollmentOutcome:
    """Enrola si hace falta (un solo intento) y describe el resultado."""
    agent_id = str(agent.identity.agent_id)
    before = agent.identity.token
    try:
        asset_id = agent.enroll()
    except EnrollmentKeyMissingError:
        return EnrollmentOutcome(
            EXIT_NO_CREDENTIAL,
            STATE_NO_CREDENTIAL,
            "not enrolled and no enrollment token/key configured",
            agent_id,
            None,
        )
    except CredentialsRejectedError as exc:
        return EnrollmentOutcome(
            EXIT_REJECTED,
            STATE_REJECTED,
            redact(f"enrollment refused by the server: {exc.reason}"),
            agent_id,
            None,
        )
    except TransportError as exc:
        return EnrollmentOutcome(
            EXIT_UNREACHABLE,
            STATE_UNREACHABLE,
            redact(f"server unreachable: {exc}"),
            agent_id,
            None,
        )
    asset = str(asset_id) if asset_id else None
    # Mismo token que antes: no se enroló nada (un token de un solo uso aportado no se usó).
    unchanged = before is not None and agent.identity.token == before
    state = STATE_ALREADY_ENROLLED if unchanged else STATE_ENROLLED
    message = f"{state.replace('_', ' ')}: agent_id={agent_id} asset_id={asset}"
    return EnrollmentOutcome(EXIT_ENROLLED, state, message, agent_id, asset)


def write_status(state_dir: Path, outcome: EnrollmentOutcome) -> Path:
    path = state_dir / STATUS_FILE
    payload = {
        **asdict(outcome),
        "updated_at": datetime.now(UTC).isoformat(),
        # Permite al instalador descartar un archivo escrito por un proceso anterior.
        "pid": os.getpid(),
    }
    # No es un secreto, pero se escribe igual de forma atómica: el instalador lo lee mientras
    # el servicio puede estar reescribiéndolo, y un JSON a medias parecería un error.
    write_atomic(path, json.dumps(payload, indent=2), private=False)
    return path


def bootstrap_service_enrollment(
    agent: Agent, stop_event: threading.Event
) -> EnrollmentOutcome | None:
    """Enrolamiento inicial del servicio Windows cuando el instalador dejó un token.

    Sin token pendiente no hace nada (arranque normal, upgrade o reinicio del equipo).
    Con token: reintenta mientras el servidor no responda (el token sigue en disco, protegido
    por la ACL del directorio de estado, hasta usarse o caducar) y, una vez resuelto
    (enrolado, ya enrolado o rechazado), borra el token: un token rechazado nunca volverá a
    servir y uno no usado no debe quedarse en disco.
    """
    if not agent.has_bootstrap():
        return None
    failures = 0
    while True:
        outcome = enroll_once(agent)
        write_status(agent.config.state_dir, outcome)
        logger.info("service enrollment", extra={"state": outcome.state, "detail": outcome.message})
        if outcome.state != STATE_UNREACHABLE:
            agent.discard_bootstrap()
            return outcome
        failures += 1
        delay = backoff_delay(
            failures, agent.config.interval_seconds, agent.config.max_backoff_seconds
        )
        if stop_event.wait(delay):
            # Parada del servicio con el servidor caído: el token se conserva para el
            # siguiente arranque, que lo reintentará.
            return outcome

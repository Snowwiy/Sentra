import os
import tempfile

# Must run before the app (and its cached settings) is imported: tests drive background jobs
# explicitly, and a live sweeper thread would race with assertions.
os.environ["BACKGROUND_JOBS_ENABLED"] = "false"
os.environ["METRICS_ENABLED"] = "false"
# Fixed test-only key so tests never depend on (or reveal) the developer's real .env value.
TEST_ENROLLMENT_KEY = "test-enrollment-key-0123456789abcdef"
os.environ["AGENT_ENROLLMENT_KEY"] = TEST_ENROLLMENT_KEY
# Same idea for the administration API (enrollment tokens).
TEST_ADMIN_KEY = "test-admin-key-0123456789abcdef-xyz"
os.environ["ADMIN_API_KEY"] = TEST_ADMIN_KEY
# Fase 5C: la sincronización por red es opt-in (false por defecto). Se fija aquí porque las
# variables de entorno del proceso ganan al .env: un .env de desarrollo con
# THREAT_INTEL_SYNC_ENABLED=true (pruebas reales) no debe cambiar lo que comprueban los tests.
# Los tests del modo con red lo activan de forma explícita.
os.environ["THREAT_INTEL_SYNC_ENABLED"] = "false"
# Fase 5C.2: la política de ciclo de vida se fija a sus valores por defecto por la misma
# razón (un .env de desarrollo con otros umbrales o con ASSET_AUTO_CLEANUP=true cambiaría lo
# que es stale o borrable). Los tests que necesitan otra política la construyen explícita.
os.environ["DISCOVERED_STALE_AFTER_HOURS"] = "72"
os.environ["DISCOVERED_STALE_MISSED_SCANS"] = "3"
os.environ["DISCOVERED_PURGE_AFTER_DAYS"] = "14"
os.environ["MANAGED_STALE_AFTER_DAYS"] = "30"
os.environ["ASSET_AUTO_CLEANUP"] = "false"
os.environ["ASSET_CLEANUP_BATCH_SIZE"] = "50"
os.environ["ASSET_CLEANUP_INTERVAL_MINUTES"] = "360"
# Fase 5D: Response Engine con sus valores por defecto, por la misma razón (un .env de
# desarrollo con RESPONSE_OFFLINE_AGENT_POLICY=queue o con Response apagado cambiaría lo que
# comprueban los tests). Los tests de otra política la construyen explícita.
os.environ["RESPONSE_ENABLED"] = "true"
os.environ["PLAYBOOKS_ENABLED"] = "true"
os.environ["RESPONSE_COMMAND_TTL_MINUTES"] = "15"
os.environ["RESPONSE_COMMAND_LEASE_SECONDS"] = "300"
os.environ["RESPONSE_RESULT_MAX_KB"] = "64"
os.environ["RESPONSE_OFFLINE_AGENT_POLICY"] = "block"
os.environ["RESPONSE_MAX_ACTIVE_PER_ASSET"] = "10"
os.environ["RESPONSE_SWEEP_INTERVAL_SECONDS"] = "15"
# Fase 5E: Reporting con sus valores por defecto, por la misma razón. Los artefactos van a
# una carpeta temporal propia de la sesión de tests (fuera del repositorio, como exige el
# almacenamiento), nunca a la carpeta de informes real del desarrollador.
os.environ["REPORT_ENABLED"] = "true"
os.environ["REPORT_OUTPUT_DIR"] = tempfile.mkdtemp(prefix="sentra-reports-test-")
os.environ["REPORT_MAX_RANGE_DAYS"] = "365"
os.environ["REPORT_MAX_ASSETS"] = "100"
os.environ["REPORT_MAX_ROWS"] = "500"
os.environ["REPORT_RETENTION_DAYS"] = ""
os.environ["REPORT_JOB_TIMEOUT_SECONDS"] = "300"
os.environ["REPORT_MAX_CONCURRENT"] = "3"
os.environ["REPORT_MAX_QUEUED_TOTAL"] = "20"
os.environ["REPORT_MAX_ARTIFACT_MB"] = "25"
os.environ["REPORT_WORKER_INTERVAL_SECONDS"] = "5"
# Fase 5F: sites y sensores con sus valores por defecto, por la misma razón (el .env del
# desarrollador no debe cambiar plazos, límites ni versiones mínimas de los tests).
os.environ["SENSOR_ENROLLMENT_TOKEN_TTL_MINUTES"] = "60"
os.environ["SENSOR_ENROLL_MAX_PER_MINUTE"] = "10"
os.environ["SENSOR_HEARTBEAT_MAX_PER_MINUTE"] = "30"
os.environ["SENSOR_POLL_MAX_PER_MINUTE"] = "30"
os.environ["SENSOR_HEARTBEAT_INTERVAL_SECONDS"] = "30"
os.environ["SENSOR_POLL_INTERVAL_SECONDS"] = "30"
os.environ["SENSOR_OFFLINE_AFTER_SECONDS"] = "180"
os.environ["SENSOR_STALE_AFTER_SECONDS"] = "86400"
os.environ["SENSOR_JOB_TTL_MINUTES"] = "60"
os.environ["SENSOR_JOB_LEASE_SECONDS"] = "120"
os.environ["SENSOR_RESULT_GRACE_SECONDS"] = "14400"
os.environ["SENSOR_JOB_MAX_ATTEMPTS"] = "2"
os.environ["SENSOR_MAX_REQUEST_KB"] = "1024"
os.environ["SENSOR_MAX_OBSERVATIONS_PER_BATCH"] = "500"
os.environ["SENSOR_MAX_PORTS_PER_OBSERVATION"] = "256"
os.environ["SENSOR_MAX_BATCHES_PER_JOB"] = "1000"
os.environ["SENSOR_MAX_CLOCK_SKEW_SECONDS"] = "300"
os.environ["SENSOR_MIN_VERSION"] = "0.1.0"
os.environ["SENSOR_RECOMMENDED_VERSION"] = "0.1.0"
os.environ["SENSOR_SWEEP_INTERVAL_SECONDS"] = "30"
# Fase 6A: retención de observaciones de discovery con su valor por defecto (sin purga), por
# la misma razón: un .env de desarrollo con otra retención no debe cambiar los tests.
os.environ["DISCOVERY_OBSERVATION_RETENTION_DAYS"] = ""
# Fase 6B: ajustes SNMP fijados para que un .env de desarrollo no cambie los tests. El fichero
# de claves es temporal (0600) y su clave es aleatoria en cada ejecución: ningún secreto de
# prueba queda en el repositorio.
_SNMP_KEY_DIR = tempfile.mkdtemp(prefix="sentra-snmp-keys-test-")
_SNMP_KEY_FILE = os.path.join(_SNMP_KEY_DIR, "snmp.keys")
with os.fdopen(os.open(_SNMP_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as _fh:
    import base64 as _b64
    import secrets as _secrets

    _fh.write("test1:" + _b64.b64encode(_secrets.token_bytes(32)).decode() + "\n")
os.environ["SNMP_CREDENTIAL_KEY_FILE"] = _SNMP_KEY_FILE
os.environ["SNMP_CREDENTIAL_KEY_READERS"] = ""
os.environ["SNMP_ALLOW_V2C"] = "false"
os.environ["SNMP_POLL_INTERVAL_MINUTES"] = ""
os.environ["SNMP_TIMEOUT_MS"] = "2000"
os.environ["SNMP_RETRIES"] = "1"
os.environ["SNMP_MAX_VARBINDS_PER_JOB"] = "50000"
os.environ["SNMP_MAX_ROWS_PER_TABLE"] = "10000"
os.environ["SNMP_JOB_DEADLINE_SECONDS"] = "300"
os.environ["SNMP_EDGE_PORT_MAX_MACS"] = "3"
os.environ["SNMP_HISTORY_RETENTION_DAYS"] = ""
# Fase 6D: pausa automática de consultas periódicas tras fallos repetidos (valor por defecto).
os.environ["SNMP_AUTO_PAUSE_FAILURES"] = "3"
# Fase 6C.3: retención del inventario Wi-Fi con su valor por defecto (sin purga).
os.environ["WLAN_HISTORY_RETENTION_DAYS"] = ""
# Fase 6C.4: fuentes oficiales del catálogo. Un .env con descargas activadas o una API key de
# NVD no debe cambiar lo que comprueban los tests (ninguno sale a Internet).
os.environ["VULN_SOURCE_SYNC_ENABLED"] = "false"
os.environ["VULN_SOURCE_AUTO_SYNC"] = ""
os.environ["VULN_SOURCE_SYNC_INTERVAL_HOURS"] = "12"
os.environ["VULN_SOURCE_STALE_HOURS"] = "72"
os.environ["VULN_SOURCE_URLS"] = ""
os.environ["VULN_SOURCE_MAX_DOWNLOAD_MB"] = "256"
os.environ["VULN_SOURCE_MAX_RECORDS"] = "500000"
os.environ["VULN_SOURCE_MAX_RETRIES"] = "4"
os.environ["VULN_OSV_ECOSYSTEMS"] = "Debian,Ubuntu,AlmaLinux,Rocky Linux"
os.environ["VULN_NVD_RESULTS_PER_PAGE"] = "2000"
os.environ["VULN_NVD_MAX_PAGES_PER_RUN"] = "100"
os.environ["VULN_NVD_INITIAL_DAYS"] = "120"
os.environ["NVD_API_KEY"] = ""
os.environ["NVD_API_KEY_FILE"] = ""
os.environ["VULN_BUILTIN_PRODUCT_MAP"] = "true"
# Fase 6D: motor de topología con sus valores por defecto, por la misma razón (un .env de
# desarrollo con otros topes cambiaría lo que es truncated). Los tests de límites construyen
# sus propios ajustes. El intervalo no arranca nada: BACKGROUND_JOBS_ENABLED=false.
os.environ["TOPOLOGY_REBUILD_INTERVAL_MINUTES"] = "15"
os.environ["TOPOLOGY_MAX_NODES"] = "1500"
os.environ["TOPOLOGY_MAX_LINKS"] = "5000"
# Fase 6E.1: historial de topología con sus valores por defecto, salvo el enfriamiento de la
# reconstrucción manual, que los tests de 6D desactivan (reconstruyen varias veces seguidas);
# los tests del enfriamiento construyen sus propios ajustes.
os.environ["TOPOLOGY_LINK_REMOVAL_CONFIRMATIONS"] = "3"
os.environ["TOPOLOGY_BUILD_RETENTION_DAYS"] = "30"
os.environ["TOPOLOGY_SNAPSHOT_RETENTION_DAYS"] = "180"
os.environ["NETWORK_CHANGE_RETENTION_DAYS"] = "365"
os.environ["TOPOLOGY_ABSENT_LINK_RETENTION_DAYS"] = "90"
os.environ["TOPOLOGY_MANUAL_REBUILD_COOLDOWN_SECONDS"] = "0"
# Fase 6E.2: identidad y DHCP.
os.environ["DHCP_IMPORT_MAX_KB"] = "2048"
os.environ["DHCP_LEASE_RETENTION_DAYS"] = "90"
os.environ["ASSET_IDENTITY_HISTORY_RETENTION_DAYS"] = "365"
# Fase 6E.3/6E.4: telemetría avanzada de endpoint.
os.environ["TELEMETRY_CMDLINE_POLICY"] = "redacted"
os.environ["TELEMETRY_ACTIVITY_MAX_PER_MINUTE"] = "1000"
os.environ["TELEMETRY_ACTIVITY_RETENTION_DAYS"] = "14"
os.environ["PROCESS_INSTANCE_RETENTION_DAYS"] = "30"
os.environ["FORENSICS_ARTIFACT_MAX_KB"] = "2048"
os.environ["FORENSICS_PACKAGE_MAX_MB"] = "64"
os.environ["ISOLATION_ENABLED"] = "false"
os.environ["ISOLATION_MAX_MINUTES"] = "240"
os.environ["ISOLATION_DEFAULT_MINUTES"] = "60"
# test_viewer_cannot_mutate_anything recorre todas las rutas mutables con un mismo usuario y
# desde 6B son más de 120 (el límite por defecto por minuto): sin esto respondería 429.
os.environ["API_MUTATIONS_PER_USER_PER_MINUTE"] = "1000"

# SENTRA QA: AI settings isolated from development environment
os.environ["AI_ENABLED"] = "false"
os.environ["AI_API_KEY"] = ""
os.environ["AI_ALLOW_EXTERNAL"] = "false"
os.environ["AI_REDACT"] = ""
os.environ["AI_MAX_RETRIES"] = "1"
os.environ["AI_RATE_LIMIT_PER_USER_PER_MINUTE"] = "6"
os.environ["AI_RATE_LIMIT_GLOBAL_PER_MINUTE"] = "30"
os.environ["AI_MAX_CONCURRENT"] = "2"
os.environ["AI_MAX_CONTEXT_ITEMS"] = "40"
os.environ["AI_MAX_OUTPUT_TOKENS"] = "1200"

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.api.auth import CSRF_HEADER, session_cookie_name
from app.core import passwords
from app.core.config import get_settings
from app.core.security import csrf_token_for
from app.db.session import build_engine, get_db
from app.main import create_app
from app.models.user import User
from app.services.auth_service import AuthService, SessionPolicy

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _alembic_config(url: str) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.attributes["database_url"] = url
    config.attributes["configure_logger"] = False
    return config


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    settings = get_settings()
    url = settings.test_database_url
    if not url:
        pytest.exit("TEST_DATABASE_URL is not set; see README (Tests).", returncode=2)
    # Tests truncate tables; refusing to share the main database prevents wiping real data.
    if url == settings.database_url:
        pytest.exit("TEST_DATABASE_URL must differ from DATABASE_URL.", returncode=2)

    # Run the real migrations (down then up) so tests also validate them.
    config = _alembic_config(url)
    command.downgrade(config, "base")
    command.upgrade(config, "head")

    engine = build_engine(url)
    yield engine
    engine.dispose()


class AgentClient(TestClient):
    """TestClient that behaves like a well-configured agent.

    It adds the enrollment key to registrations and remembers each issued token, then sends it
    as a Bearer credential on agent calls, so feature tests stay focused on their behavior.
    Passing explicit `headers` disables this, which is how the authentication tests send
    missing or wrong credentials.
    """

    tokens: dict[str, str]

    def post(self, url: Any, *, json: Any = None, headers: Any = None, **kwargs: Any) -> Any:
        agent_id = json.get("agent_id") if isinstance(json, dict) else None
        is_register = str(url).endswith("/agents/register")
        if headers is None:
            if is_register:
                headers = {"X-Enrollment-Key": TEST_ENROLLMENT_KEY}
            elif agent_id in self.tokens:
                headers = {"Authorization": f"Bearer {self.tokens[agent_id]}"}
        response = super().post(url, json=json, headers=headers, **kwargs)
        if is_register and response.status_code in (200, 201):
            self.tokens[str(agent_id)] = response.json()["agent_token"]
        return response


# Contraseña de los usuarios de prueba. El hash Argon2 se calcula una sola vez por sesión
# de pytest: con un hash por test la suite tardaría bastante más.
TEST_PASSWORD = "correct horse battery staple"
_TEST_HASH: list[str] = []


def _test_password_hash() -> str:
    if not _TEST_HASH:
        _TEST_HASH.append(passwords.hash_password(TEST_PASSWORD))
    return _TEST_HASH[0]


def create_user(session: Session, username: str, role: str = "admin", active: bool = True) -> User:
    now = datetime.now(UTC)
    user = User(
        username=username,
        password_hash=_test_password_hash(),
        role=role,
        is_active=active,
        created_at=now,
        updated_at=now,
        password_changed_at=now - timedelta(seconds=1),
    )
    session.add(user)
    session.commit()
    return user


def authenticate(
    test_client: TestClient, engine: Engine, role: str = "admin", username: str | None = None
) -> User:
    """Crea un usuario con ese rol y deja `test_client` con su sesión y su token CSRF.

    Equivale a un login del dashboard sin pasar por /auth/login (que se prueba aparte), así
    los tests de funcionalidad no dependen del rate limiting del login.
    """
    settings = get_settings()
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        user = create_user(session, username or f"{role}-{uuid4().hex[:8]}", role)
        token, _ = AuthService(session, SessionPolicy.from_settings(settings)).start_session(
            user, "testclient", "pytest"
        )
    test_client.cookies.set(session_cookie_name(settings), token)
    test_client.headers[CSRF_HEADER] = csrf_token_for(token)
    return user


@pytest.fixture
def client(engine: Engine) -> Iterator[TestClient]:
    """Cliente con sesión de admin (Fase 4G): las lecturas y acciones del dashboard exigen
    login. Los tests de autenticación usan `anonymous` o limpian las cookies."""
    app = create_app()
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def override_get_db() -> Iterator[Session]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    with AgentClient(app) as test_client:
        test_client.tokens = {}
        authenticate(test_client, engine, "admin", "admin")
        yield test_client

    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE evidence_packages, investigation_notes, forensic_artifacts,"
                " investigations, detection_exclusions, endpoint_activity, process_instances,"
                " asset_identity_history, dhcp_leases, dhcp_sources,"
                " network_changes, topology_snapshots, topology_links, topology_builds,"
                " system_events, asset_inventories,"
                " alerts, telemetry_samples, assets,"
                " discovery_jobs, agent_enrollment_tokens, audit_events, user_sessions, users,"
                " ai_local_settings, ai_model_benchmarks, ai_local_models, rate_limit_hits,"
                " detection_rules, detection_rule_stats, vulnerability_sources, playbooks,"
                " reports, site_networks, sensor_enrollment_tokens, sensors,"
                " network_devices, snmp_credential_profiles, wlan_observations,"
                " wlan_agent_reports, wlan_clients, wlan_bss, wlan_access_points,"
                " wlan_configured_networks"
                " RESTART IDENTITY CASCADE"
            )
        )
        # Fase 5F: el site por defecto lo crea la migración y no se borra (la función
        # sentra_default_site_id() lo necesita); se devuelve a su estado inicial.
        connection.execute(text("DELETE FROM sites WHERE NOT is_default"))
        connection.execute(
            text(
                "UPDATE sites SET name = 'Local', slug = 'local', status = 'active',"
                " description = NULL, location_label = NULL, timezone = 'UTC', version = 1,"
                " archived_at = NULL, archive_reason = NULL WHERE is_default"
            )
        )


def agent_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "agent_id": str(uuid4()),
        "hostname": "PC-ADMIN-01",
        "os_name": "Windows",
        "os_version": "11 Pro 24H2",
        "architecture": "x86_64",
        "primary_ip": "192.168.1.20",
        "agent_version": "0.1.0",
    }
    payload.update(overrides)
    return payload


@pytest.fixture
def registered_agent(client: TestClient) -> dict[str, Any]:
    """Register an agent and return its registration payload plus the API response."""
    payload = agent_payload()
    response = client.post("/api/v1/agents/register", json=payload)
    assert response.status_code == 201
    return {"payload": payload, "response": response.json()}

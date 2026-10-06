import ipaddress
import os
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.discovery.ports import parse_ports
from app.discovery.targets import DiscoveryScope


def parse_name_list(value: str) -> list[str]:
    """Comma separated names, blanks dropped."""
    return [item.strip() for item in value.split(",") if item.strip()]


AINetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
_LAN_RANGES: tuple[AINetwork, ...] = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


def parse_ai_local_networks(value: str) -> tuple[AINetwork, ...]:
    """'192.168.1.0/24,fd00::/64' -> redes donde se autoriza un servidor de IA local.

    Solo se aceptan subredes de RFC 1918 o ULA (fc00::/7). Se rechazan Internet, link-local
    (incluye 169.254.169.254, metadatos de nube), CGNAT y rangos como 0.0.0.0/0: autorizar
    uno de esos convertiría un destino externo en "local" y saltaría AI_ALLOW_EXTERNAL.
    """
    networks: list[AINetwork] = []
    for item in parse_name_list(value):
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValueError(f"AI_LOCAL_NETWORKS has an invalid network: {item!r}") from None
        # Lista cerrada de rangos de LAN en vez de `is_private`, que también incluye rangos
        # reservados (0.0.0.0/8, documentación, benchmarking) que no son una LAN real.
        if not any(
            network.version == lan.version and network.subnet_of(lan)  # type: ignore[arg-type]
            for lan in _LAN_RANGES
        ):
            raise ValueError(f"AI_LOCAL_NETWORKS only accepts private LAN networks, got {item!r}")
        networks.append(network)
    return tuple(networks)


def parse_networks(value: str, setting: str) -> tuple[AINetwork, ...]:
    """'127.0.0.1,10.0.0.0/24' -> redes. Rechaza comodines y redes /0 (Fase 4M).

    Se usa para TRUSTED_PROXIES y METRICS_ALLOWED_NETWORKS: confiar en "todo Internet" es
    exactamente el error que estas listas existen para evitar, así que nunca se acepta.
    """
    networks: list[AINetwork] = []
    for item in parse_name_list(value):
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValueError(f"{setting} has an invalid address or network: {item!r}") from None
        if network.prefixlen == 0:
            raise ValueError(f"{setting} must not trust every address ({item!r})")
        networks.append(network)
    return tuple(networks)


def parse_model_directories(value: str) -> tuple[str, ...]:
    """'D:\\Models;E:\\IA' -> raíces autorizadas para importar modelos locales (Fase 4J.2).

    Separador ';' (como PATH en Windows) porque las rutas de Windows llevan ':'. Solo rutas
    absolutas: una relativa dependería del directorio de arranque de la API y podría acabar
    autorizando una carpeta distinta de la que el admin cree.
    """
    roots: list[str] = []
    for item in value.replace("\n", ";").split(";"):
        item = item.strip()
        if not item:
            continue
        if "\x00" in item or not os.path.isabs(item):
            raise ValueError(f"AI_MODEL_DIRECTORIES only accepts absolute paths, got {item!r}")
        roots.append(item)
    return tuple(roots)


def parse_performance_thresholds(value: str) -> tuple[float, float, float]:
    """'30,15,7' -> tokens/s mínimos de Excellent, Good y Usable (por debajo: Slow)."""
    try:
        parts = tuple(float(part.strip()) for part in value.split(","))
    except ValueError:
        raise ValueError("AI_PERFORMANCE_THRESHOLDS must be three numbers, e.g. 30,15,7") from None
    if len(parts) != 3 or not parts[0] > parts[1] > parts[2] > 0:
        raise ValueError("AI_PERFORMANCE_THRESHOLDS must be three decreasing positive numbers")
    return parts[0], parts[1], parts[2]


def parse_risk_thresholds(value: str) -> tuple[int, int, int, int]:
    """'20,40,60,80' -> límites inferiores de low, medium, high y critical."""
    try:
        parts = tuple(int(part.strip()) for part in value.split(","))
    except ValueError:
        raise ValueError("RISK_LEVEL_THRESHOLDS must be four integers, e.g. 20,40,60,80") from None
    if len(parts) != 4 or not 0 < parts[0] < parts[1] < parts[2] < parts[3] <= 100:
        raise ValueError("RISK_LEVEL_THRESHOLDS must be four increasing integers between 1 and 100")
    return parts[0], parts[1], parts[2], parts[3]


def parse_critical_events(value: str) -> list[tuple[str, int]]:
    """`Provider:EventID,...` into (provider, event id) pairs. Raises ValueError."""
    events = []
    for item in parse_name_list(value):
        provider, separator, code = item.rpartition(":")
        if not separator or not provider.strip() or not code.strip().isdigit():
            raise ValueError(f"expected Provider:EventID, got {item!r}")
        events.append((provider.strip(), int(code)))
    return events


class Settings(BaseSettings):
    """Application settings. Every value comes from environment variables or a `.env` file."""

    # hide_input_in_errors: un valor inválido nunca se copia al mensaje de error (podría ser
    # DATABASE_URL con la contraseña o una clave), solo el nombre del campo y el motivo.
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"), extra="ignore", hide_input_in_errors=True
    )

    app_name: str = "Sentra API"
    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"

    database_url: str = Field(description="SQLAlchemy URL, e.g. postgresql+psycopg://...")
    test_database_url: str | None = None

    # Largest accepted request body. Real inventories are well under 1 MB; the limit leaves
    # room for the inventory caps while stopping memory exhaustion by huge uploads.
    max_request_bytes: int = Field(default=4 * 1024 * 1024, ge=1024)

    # Comma separated list of origins allowed to call the API from a browser.
    cors_origins: str = ""

    # Shared secret agents must present to register. Unset means registration is disabled
    # (fail closed): an open registration endpoint would let anyone inject fake assets.
    agent_enrollment_key: SecretStr | None = Field(default=None, min_length=24)

    # One-time enrollment tokens (recommended over the shared key): lifetime when created
    # without an explicit one. See services/enrollment_token_service.py.
    enrollment_token_ttl_minutes: int = Field(default=15, ge=1, le=1440)

    # Key for the administration API (X-Admin-Key): creating, listing and revoking
    # enrollment tokens. Unset (the default) disables those endpoints; the CLI keeps working.
    # Desde la Fase 4G es un mecanismo LEGACY para automatización servidor a servidor: el
    # dashboard usa login y roles, y el navegador nunca recibe ni envía esta clave.
    admin_api_key: SecretStr | None = Field(default=None, min_length=24)

    # --- Fase 4G: login del dashboard, sesiones y RBAC (ver docs/authentication.md) ---
    # Caducidad absoluta de una sesión y caducidad por inactividad.
    session_ttl_hours: int = Field(default=12, ge=1, le=168)
    session_idle_minutes: int = Field(default=60, ge=5, le=1440)
    # Atributo Secure de la cookie de sesión. Sin valor: activo solo con
    # ENVIRONMENT=production. Con Secure el navegador solo la envía por HTTPS, así que en
    # producción la API tiene que servirse por HTTPS (reverse proxy); HTTP en la LAN es solo
    # para desarrollo y no protege las contraseñas ni la cookie frente a quien escuche la red.
    session_cookie_secure: bool | None = None
    # strict: el navegador no envía la cookie en peticiones iniciadas desde otro sitio
    # (primera barrera contra CSRF; la segunda es el token X-CSRF-Token).
    session_cookie_samesite: Literal["strict", "lax"] = "strict"
    # Login: fallos por usuario+dirección, intentos por dirección y fallos por usuario
    # (cualquier dirección) dentro de la ventana. Ver services/auth_service.py.
    login_rate_window_minutes: int = Field(default=15, ge=1, le=1440)
    login_max_failures_per_user_ip: int = Field(default=5, ge=1, le=1000)
    login_max_attempts_per_ip: int = Field(default=30, ge=1, le=10_000)
    login_max_failures_per_user: int = Field(default=50, ge=1, le=100_000)
    # POST /agents/register por dirección y minuto. No afecta a heartbeat/telemetría.
    agent_register_max_per_minute: int = Field(default=30, ge=1, le=10_000)
    # Nombres de host aceptados en la cabecera Host (TrustedHostMiddleware), separados por
    # coma, p. ej. "sentra.lan,192.168.50.201,localhost". Vacío: sin comprobación (LAN de
    # desarrollo). Recomendado en producción contra DNS rebinding y cabeceras Host falsas.
    allowed_hosts: str = ""

    # URL agents use to reach this server, shown in the dashboard's install command
    # (e.g. http://192.168.50.201:8000). Unset: suggested from this machine's addresses.
    agent_server_url: str | None = Field(
        default=None, pattern=r"^https?://[A-Za-z0-9.\-\[\]:]+(/[A-Za-z0-9._~/-]*)?$"
    )

    # An asset is reported offline when it has not been seen for this many seconds.
    heartbeat_timeout_seconds: int = Field(default=90, gt=0)

    # Alert rules. CPU and RAM must stay above the threshold for `alert_sustained_samples`
    # consecutive samples so short spikes do not page anyone; disk alerts on a single sample
    # because disk usage does not spike and fills steadily.
    alert_cpu_percent: float = Field(default=90, gt=0, le=100)
    alert_ram_percent: float = Field(default=90, gt=0, le=100)
    alert_disk_percent: float = Field(default=90, gt=0, le=100)
    alert_sustained_samples: int = Field(default=3, ge=1, le=100)

    # Services whose stop is worth an alert (comma separated service names, case
    # insensitive; empty disables the rule). Defaults: Event Log, Defender, Windows Firewall,
    # the services an attacker stops first. Evaluated on every inventory snapshot.
    alert_watched_services: str = "EventLog,WinDefend,mpssvc"
    # Host events that open an alert by themselves, as Provider:EventID (comma separated).
    # Defaults: unexpected reboot (Kernel-Power 41), unexpected shutdown (6008), Security
    # and System log cleared (1102, 104).
    alert_critical_events: str = (
        "Microsoft-Windows-Kernel-Power:41,EventLog:6008,"
        "Microsoft-Windows-Eventlog:1102,Microsoft-Windows-Eventlog:104"
    )
    # Burst of error/critical host events: at least COUNT within MINUTES on one asset.
    alert_event_burst_count: int = Field(default=10, ge=2, le=10_000)
    alert_event_burst_minutes: int = Field(default=10, ge=1, le=1440)
    # Event-based alerts (critical event, burst, admin change) have no condition that
    # clears: they resolve once nothing new fired for this long.
    alert_event_quiet_minutes: int = Field(default=60, ge=1, le=10_080)

    # Background jobs (offline detection). Disabled in tests, which drive jobs explicitly.
    background_jobs_enabled: bool = True
    offline_sweep_interval_seconds: int = Field(default=30, ge=5)

    # Data retention in days. Unset (the default) keeps everything: deleting monitoring
    # history is the operator's decision. See services/retention_service.py.
    telemetry_retention_days: int | None = Field(default=None, ge=1)
    event_retention_days: int | None = Field(default=None, ge=1)
    # Inventory change history, and resolved alerts (active alerts are never deleted).
    change_retention_days: int | None = Field(default=None, ge=1)
    alert_retention_days: int | None = Field(default=None, ge=1)
    retention_sweep_interval_seconds: int = Field(default=3600, ge=60)

    # --- Agentless network discovery (app/discovery). Off unless networks are listed. ---
    # Comma separated CIDRs/addresses Sentra may probe, e.g. "192.168.1.0/24,10.0.10.0/24".
    # Empty (the default) disables discovery entirely. Public Internet space is refused
    # unless DISCOVERY_ALLOW_PUBLIC_NETWORKS=true; 0.0.0.0/0 is always refused.
    discovery_allowed_networks: str = ""
    # Addresses/networks never probed, even inside an allowed network.
    discovery_excluded: str = ""
    discovery_allow_public_networks: bool = False
    # Largest network accepted (addresses), so a /8 typo is refused, not scanned.
    discovery_max_hosts_per_network: int = Field(default=1024, ge=1, le=65_536)
    # Port profiles (minimal, common, windows, printers, web) and/or ports and ranges.
    discovery_ports: str = "common"
    discovery_timeout_ms: int = Field(default=800, ge=50, le=10_000)
    # Probes in flight at once, and started per second, for the whole server.
    discovery_concurrency: int = Field(default=64, ge=1, le=256)
    discovery_max_probes_per_second: int = Field(default=200, ge=1, le=5000)
    discovery_icmp: bool = True
    discovery_reverse_dns: bool = True
    # Sondas de nombre de hosts vivos: mDNS, NetBIOS y SSDP/UPnP (app/discovery/names.py).
    discovery_identify: bool = True
    # Ficheros OUI del IEEE (oui.csv, mam.csv, oui36.csv) separados por coma, para resolver
    # el fabricante de la NIC sin consultar Internet. Vacío: fabricante desconocido.
    discovery_oui_file: str = ""
    # Periodic runs over every allowed network; unset = manual only (CLI `discover`).
    discovery_interval_minutes: int | None = Field(default=None, ge=5, le=10_080)
    # A run is stopped (results kept as partial) after this long.
    discovery_job_timeout_minutes: int = Field(default=30, ge=1, le=1440)
    # Complete runs without seeing a host before it is reported offline/disappeared.
    discovery_offline_after_misses: int = Field(default=3, ge=1, le=100)

    # --- Fase 4H: motor de detección y correlación (ver docs/detection-engine.md) ---
    # Desactivarlo deja de crear señales y detecciones; la ingesta sigue igual.
    detection_enabled: bool = True
    # Cada cuánto el job interno evalúa las señales pendientes (latencia de una detección).
    detection_eval_interval_seconds: int = Field(default=5, ge=1, le=3600)
    # AUTH-001: fallos de logon de la misma cuenta en el mismo activo dentro de la ventana.
    detection_auth_failure_threshold: int = Field(default=5, ge=2, le=10_000)
    detection_auth_failure_window_minutes: int = Field(default=5, ge=1, le=1440)
    # Correlaciones de secuencia corta (CORR-001 fallos -> éxito, CORR-002 PowerShell ->
    # persistencia) y de cambios administrativos (CORR-003 exposición, CORR-004 cuenta nueva).
    detection_correlation_window_minutes: int = Field(default=15, ge=1, le=1440)
    detection_change_window_minutes: int = Field(default=60, ge=1, le=1440)
    # Patrones repetitivos (caídas del mismo servicio, apagados inesperados).
    detection_repeat_threshold: int = Field(default=3, ge=2, le=1000)
    detection_repeat_window_minutes: int = Field(default=1440, ge=1, le=10_080)
    # Eventos más antiguos no generan señales: el primer envío de un agente recién instalado
    # (o un backlog muy viejo) no debe convertir el pasado en detecciones nuevas.
    detection_max_event_age_hours: int = Field(default=24, ge=1, le=720)
    # Las señales son estado temporal para correlacionar; la evidencia útil queda copiada.
    detection_signal_retention_hours: int = Field(default=48, ge=1, le=2160)
    # Servicios de control de seguridad vigilados por DEF-003 (Windows y Linux).
    detection_security_services: str = "WinDefend,mpssvc,EventLog,wscsvc,Sense,auditd,firewalld,ufw"
    # Detecciones con esta severidad o más abren una alerta security_detection; "off" nunca.
    detection_alert_min_severity: Literal["medium", "high", "critical", "off"] = "high"
    # Reglas desactivadas por id (p. ej. "PROC-001,NET-004"); un id desconocido impide arrancar.
    detection_disabled_rules: str = ""
    # Detecciones RESUELTAS más antiguas se borran (con su evidencia). Las abiertas o
    # reconocidas nunca. Sin valor (por defecto) no se borra nada.
    detection_retention_days: int | None = Field(default=None, ge=1)

    # --- Fase 5A: reglas personalizadas y Sigma (ver docs/custom-detection-rules.md) ---
    # Confianza de una regla Sigma importada (Sigma no la define). Conservadora por defecto:
    # una regla de terceros no prueba nada en este entorno hasta que alguien la revisa.
    sigma_default_confidence: Literal["low", "medium"] = "low"
    # Prueba contra datos históricos (solo admin): rango máximo, filas examinadas, tiempo y
    # pruebas por minuto y usuario. Protegen la base de datos de un escaneo sin límite.
    rule_test_max_hours: int = Field(default=72, ge=1, le=720)
    rule_test_max_rows: int = Field(default=20_000, ge=100, le=200_000)
    rule_test_timeout_seconds: int = Field(default=10, ge=1, le=60)
    rule_test_per_minute: int = Field(default=6, ge=1, le=120)

    # --- Fase 4I: Risk Engine (ver docs/risk-engine.md) ---
    # Desactivarlo detiene el job de riesgo; las lecturas muestran el último valor calculado.
    risk_enabled: bool = True
    # Cada cuánto el job procesa la cola de recálculo (latencia tras una detección).
    risk_eval_interval_seconds: int = Field(default=15, ge=1, le=3600)
    # Cada cuánto se recalculan los activos con riesgo > 0 para aplicar el decay temporal.
    risk_decay_interval_minutes: int = Field(default=15, ge=1, le=1440)
    # Todo activo se recalcula al menos con esta frecuencia (cubre cambios sin aviso).
    risk_full_refresh_hours: int = Field(default=6, ge=1, le=168)
    # Activos por lote (una transacción por lote; cada activo en su SAVEPOINT).
    risk_batch_size: int = Field(default=100, ge=1, le=1000)
    # Límites inferiores de low, medium, high y critical (0-100, estrictamente crecientes).
    risk_level_thresholds: str = "20,40,60,80"
    # Decay: semivida de la actividad (last_seen de la detección) y de una detección
    # resuelta (desde resolved_at); pasada la memoria, una resuelta deja de contar.
    risk_activity_half_life_hours: float = Field(default=24, gt=0, le=720)
    risk_resolved_half_life_hours: float = Field(default=12, gt=0, le=720)
    risk_resolved_memory_hours: int = Field(default=72, ge=1, le=2160)
    # Peso mínimo de una detección NO resuelta por antigüedad: sin resolver sigue contando.
    risk_active_floor: float = Field(default=0.25, ge=0, le=1)
    # Un puerto sensible abierto hace menos de esto pesa más (cambio reciente de exposición).
    risk_exposure_recent_hours: int = Field(default=24, ge=1, le=720)
    # Snapshot de historial cuando el score cambia al menos esto, o cada intervalo si cambió.
    risk_snapshot_min_delta: int = Field(default=5, ge=1, le=100)
    risk_snapshot_interval_minutes: int = Field(default=60, ge=1, le=10_080)
    # Datos del agente más antiguos que esto restan confianza (evaluación incompleta).
    risk_stale_data_hours: int = Field(default=24, ge=1, le=720)
    # Alerta risk_critical al cruzar hacia critical, como mucho una por activo y cooldown.
    risk_alert_enabled: bool = True
    risk_alert_cooldown_hours: int = Field(default=6, ge=0, le=720)
    # Snapshots de riesgo más antiguos se borran. Sin valor (por defecto) no se borra nada.
    risk_history_retention_days: int | None = Field(default=None, ge=1)

    # --- Fase 5B: Vulnerability & Exposure Management (ver docs/vulnerability-management.md) ---
    # Desactivarlo detiene la evaluación automática; los findings guardados se siguen viendo
    # y gestionando. Sin catálogo importado no hay nada que evaluar (no se descarga ninguno).
    vuln_enabled: bool = True
    # Cada cuánto el job atiende la cola de activos pendientes (inventario, SO, puertos,
    # contexto o catálogo cambiados). Nunca en cada heartbeat.
    vuln_eval_interval_seconds: int = Field(default=30, ge=5, le=3600)
    # Reevaluación completa de cada activo aunque no cambie nada (caducidad de riesgos
    # aceptados, evidencia antigua, exposición).
    vuln_full_refresh_hours: int = Field(default=24, ge=1, le=720)
    vuln_batch_size: int = Field(default=50, ge=1, le=1000)
    # Inventario más antiguo que esto: la evidencia se marca como antigua (no se resuelve).
    vuln_stale_inventory_hours: int = Field(default=72, ge=1, le=8760)
    # Capturas COMPLETAS consecutivas sin el componente antes de resolver por desinstalación.
    vuln_missing_threshold: int = Field(default=2, ge=1, le=10)
    # Catálogo local: tamaño máximo del fichero (la API además está limitada por
    # MAX_REQUEST_BYTES; los catálogos grandes se importan por CLI, por lotes) y registros.
    vuln_catalog_max_mb: int = Field(default=64, ge=1, le=2048)
    vuln_catalog_max_records: int = Field(default=200_000, ge=1, le=2_000_000)
    # Registros por transacción en la importación por CLI.
    vuln_import_batch_size: int = Field(default=1000, ge=50, le=20_000)
    # Alertas internas solo por cambios relevantes (crítica confirmada, alta confirmada con
    # el servicio expuesto, reaparición, pasa a estar expuesta); las potenciales nunca.
    vuln_alert_enabled: bool = True
    vuln_alert_cooldown_hours: int = Field(default=24, ge=0, le=720)

    # --- Fase 4J: AI Security Insights (ver docs/ai-security-insights.md) ---
    # Apagado por defecto: Sentra funciona completo sin IA. Encenderlo solo habilita el
    # análisis bajo demanda; la ingesta, las detecciones y el riesgo nunca dependen de él.
    ai_enabled: bool = False
    # Único protocolo soportado: API de chat compatible con OpenAI (/v1/chat/completions),
    # que exponen tanto servidores locales (llama.cpp, vLLM, LM Studio, Ollama...) como
    # proveedores externos. El cliente nunca puede elegir proveedor, URL ni modelo.
    ai_provider: Literal["openai_compatible"] = "openai_compatible"
    # URL base que termina en /v1, p. ej. http://127.0.0.1:11434/v1. Sin query ni fragmento.
    ai_base_url: str | None = Field(
        default=None, pattern=r"^https?://[A-Za-z0-9.\-\[\]:]+(/[A-Za-z0-9._~/-]*)?$"
    )
    ai_model: str | None = Field(default=None, max_length=128)
    # Solo servidor: nunca se registra, nunca se audita y nunca llega al navegador.
    ai_api_key: SecretStr | None = None
    # Tiempo total máximo de una llamada (incluye conexión y lectura) y límites parciales.
    ai_timeout_seconds: int = Field(default=60, ge=5, le=600)
    ai_connect_timeout_seconds: float = Field(default=5, gt=0, le=60)
    ai_read_timeout_seconds: float = Field(default=45, gt=0, le=600)
    # Elementos de contexto (detecciones, contribuciones, puertos, evidencias) por análisis.
    ai_max_context_items: int = Field(default=40, ge=5, le=200)
    ai_max_output_tokens: int = Field(default=1200, ge=200, le=8000)
    # Proveedores externos (fuera de loopback, AI_LOCAL_NETWORKS o AI_LOCAL_HOSTS) bloqueados
    # salvo permiso explícito: los datos de seguridad no salen del servidor sin decisión del
    # admin. Nunca hay fallback de un proveedor local caído a uno externo (Fase 4J.1).
    ai_allow_external: bool = False
    # Redes privadas (CIDR) autorizadas para un servidor de IA en la LAN. Loopback siempre es
    # local; una IP privada fuera de esta lista NO es local (autorización explícita, 4J.1).
    ai_local_networks: str = ""
    # Nombres de host del servidor de IA propio. Deben resolver a loopback o a una IP de
    # AI_LOCAL_NETWORKS: se comprueba la IP real conectada antes de enviar nada.
    ai_local_hosts: str = ""
    # Datos que se seudonimizan antes de enviarlos: usernames, hostnames, ips, paths.
    ai_redact: str = ""
    # Pide response_format JSON al servidor. Algunos servidores locales no lo aceptan.
    ai_json_mode: bool = True
    # Un insight se marca stale al caducar o cuando cambian los datos que lo respaldan.
    ai_insight_ttl_minutes: int = Field(default=60, ge=1, le=10_080)
    # Llamadas reales al modelo (no las respuestas de caché) por usuario y en total.
    ai_rate_limit_per_user_per_minute: int = Field(default=6, ge=1, le=1000)
    ai_rate_limit_global_per_minute: int = Field(default=30, ge=1, le=10_000)
    # Llamadas simultáneas al modelo; el resto recibe 429 en vez de ocupar hilos esperando.
    ai_max_concurrent: int = Field(default=2, ge=1, le=32)
    # Reintentos ante JSON inválido (0 = ninguno).
    ai_max_retries: int = Field(default=1, ge=0, le=3)

    # --- Fase 4J.2: gestor de modelos locales (ver docs/local-model-manager.md) ---
    # Runtime inicial detrás de AI_BASE_URL. El admin puede cambiarlo desde la UI (se guarda
    # en ai_local_settings); la URL nunca: sigue siendo configuración del servidor (4J.1).
    ai_runtime: Literal["openai_compatible", "llama_cpp", "ollama", "vllm"] = "openai_compatible"
    # Raíces autorizadas (separadas por ';') desde las que se pueden registrar ficheros
    # GGUF. Vacío = no se puede importar ningún fichero (los modelos del runtime sí).
    ai_model_directories: str = ""
    # Tamaño máximo de un fichero de modelo registrado.
    ai_model_max_file_gb: int = Field(default=256, ge=1, le=4096)
    # Catálogo adicional (JSON) que amplía o actualiza el incluido en Sentra. Opcional.
    ai_model_catalog_file: str | None = None
    # Contexto operativo por defecto para recomendar modelos. Los análisis normales de
    # Sentra no necesitan el máximo: el Context Builder ya limita la evidencia.
    ai_default_context_tokens: int = Field(default=16384, ge=2048, le=1_048_576)
    # Margen de seguridad sobre VRAM y RAM al estimar si un modelo cabe.
    ai_memory_safety_margin_percent: int = Field(default=10, ge=0, le=50)
    # Límites del benchmark local: tokens generados por pasada y duración total.
    ai_benchmark_max_tokens: int = Field(default=128, ge=16, le=1024)
    ai_benchmark_timeout_seconds: int = Field(default=180, ge=10, le=1800)
    # tokens/s de generación para Excellent, Good y Usable (uso SOC interactivo).
    ai_performance_thresholds: str = "30,15,7"

    # --- Fase 4M: despliegue central en producción (ver docs/production-deployment.md) ---
    # Reverse proxies (IPs o CIDR) cuyas cabeceras X-Forwarded-For/-Proto se aceptan. Desde
    # cualquier otra dirección se ignoran, así un cliente no puede falsificar su IP (rate
    # limiting, auditoría) ni el esquema. Por defecto loopback: Caddy/nginx en el mismo
    # servidor, o el proxy de Vite en desarrollo. Vacío: no se confía en ninguno.
    trusted_proxies: str = "127.0.0.1,::1"
    # Dónde viven los contadores de rate limiting. memory: por proceso (desarrollo, un único
    # worker). database: tabla rate_limit_hits en PostgreSQL, compartida entre workers y
    # persistente tras reiniciar. auto: database en producción, memory en el resto.
    rate_limit_backend: Literal["auto", "memory", "database"] = "auto"
    # Peticiones mutables (POST/PATCH...) del dashboard por usuario y minuto: frena scripts
    # o UI manipulada que abusen de incidentes, discovery, IA... Un operador real no llega.
    api_mutations_per_user_per_minute: int = Field(default=120, ge=1, le=100_000)
    # Búsquedas de texto libre (parámetro q, ILIKE en SQL) por usuario y minuto.
    api_searches_per_user_per_minute: int = Field(default=120, ge=1, le=100_000)

    # Pool de conexiones de la API (SQLAlchemy). Acotado: nunca conexiones ilimitadas. El
    # máximo por worker es DB_POOL_SIZE + DB_MAX_OVERFLOW; con varios workers se multiplica y
    # debe quedar por debajo de max_connections de PostgreSQL.
    db_pool_size: int = Field(default=10, ge=1, le=200)
    db_max_overflow: int = Field(default=10, ge=0, le=200)
    # Espera máxima por una conexión libre; agotada, la petición recibe 503 (reintentable).
    db_pool_timeout_seconds: int = Field(default=10, ge=1, le=300)
    # Renovar conexiones con más de esta edad (firewalls que cortan TCP inactivo). 0: nunca.
    db_pool_recycle_seconds: int = Field(default=1800, ge=0, le=86_400)
    db_connect_timeout_seconds: int = Field(default=5, ge=1, le=120)
    # statement_timeout de las conexiones de la API y sus jobs (no de Alembic). Sin valor: sin
    # límite (desarrollo). En producción se recomienda 120: evita consultas colgadas sin
    # cortar las purgas por lotes ni los recálculos, que trabajan en transacciones cortas.
    db_statement_timeout_seconds: int | None = Field(default=None, ge=1, le=86_400)

    # Logs: json (una línea por evento, para journald/SIEM) o text (lectura humana en consola).
    log_format: Literal["json", "text"] = "json"
    # Fichero de log con rotación propia (útil en Windows Server). Vacío: solo stdout, que en
    # Linux recoge journald con su propia rotación.
    log_file: str | None = None
    log_file_max_mb: int = Field(default=50, ge=1, le=10_000)
    log_file_backups: int = Field(default=10, ge=1, le=1000)

    # Métricas Prometheus en /api/v1/metrics. Apagadas por defecto. Encendidas solo responden
    # a direcciones de METRICS_ALLOWED_NETWORKS y, si hay METRICS_TOKEN, con ese Bearer.
    metrics_enabled: bool = False
    metrics_allowed_networks: str = "127.0.0.1,::1"
    metrics_token: SecretStr | None = Field(default=None, min_length=32)

    # Copias de seguridad (python -m app.cli backup). Directorio fuera del webroot y fuera
    # del repositorio; retención en días de los ficheros sentra-*.dump de ese directorio.
    backup_dir: str | None = None
    backup_retention_days: int = Field(default=14, ge=1, le=3650)
    # Carpeta de pg_dump/pg_restore si no están en PATH (p. ej. C:\Program Files\PostgreSQL\18\bin).
    pg_bin_dir: str | None = None
    # frontend/dist que sirve el reverse proxy; solo lo comprueba `production-check`.
    frontend_dist_dir: str | None = None

    @field_validator("trusted_proxies", "metrics_allowed_networks")
    @classmethod
    def _check_networks(cls, value: str, info: ValidationInfo) -> str:
        parse_networks(value, (info.field_name or "").upper())
        return value

    @field_validator("log_file", "backup_dir", "pg_bin_dir", "frontend_dist_dir", mode="before")
    @classmethod
    def _blank_paths(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip() or None
        return value

    @field_validator("ai_redact")
    @classmethod
    def _check_ai_redact(cls, value: str) -> str:
        allowed = {"usernames", "hostnames", "ips", "paths", "owners"}
        unknown = set(parse_name_list(value.lower())) - allowed
        if unknown:
            raise ValueError(f"AI_REDACT has unknown values: {sorted(unknown)}")
        return value

    @field_validator("ai_local_networks")
    @classmethod
    def _check_ai_local_networks(cls, value: str) -> str:
        parse_ai_local_networks(value)
        return value

    @field_validator("ai_model_directories")
    @classmethod
    def _check_ai_model_directories(cls, value: str) -> str:
        parse_model_directories(value)
        return value

    @field_validator("ai_performance_thresholds")
    @classmethod
    def _check_ai_performance_thresholds(cls, value: str) -> str:
        parse_performance_thresholds(value)
        return value

    @field_validator("ai_model_catalog_file", mode="before")
    @classmethod
    def _blank_catalog_file(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip() or None
        return value

    @field_validator("ai_base_url", "ai_model", mode="before")
    @classmethod
    def _blank_ai_values(cls, value: object) -> object:
        # `AI_BASE_URL=` en .env significa "sin configurar", no un valor inválido.
        if isinstance(value, str):
            value = value.strip().rstrip("/") if value.strip().startswith("http") else value.strip()
            return value or None
        return value

    @field_validator("agent_server_url", mode="before")
    @classmethod
    def _blank_server_url(cls, value: object) -> object:
        # `AGENT_SERVER_URL=` in .env means "not set", not an invalid URL.
        if isinstance(value, str):
            value = value.strip().rstrip("/")
            return value or None
        return value

    @field_validator("cors_origins")
    @classmethod
    def _check_cors_origins(cls, value: str) -> str:
        # Las peticiones del dashboard llevan la cookie de sesión (credenciales): un comodín
        # permitiría a cualquier web leer datos con la sesión del operador. Se exige la lista
        # explícita de orígenes.
        if "*" in value:
            raise ValueError("CORS_ORIGINS must list explicit origins; '*' is not allowed")
        return value

    @field_validator("alert_critical_events")
    @classmethod
    def _check_critical_events(cls, value: str) -> str:
        # Fail at startup instead of silently ignoring a misspelled rule.
        parse_critical_events(value)
        return value

    @model_validator(mode="after")
    def _check_detection(self) -> "Settings":
        # Import local: el catálogo de reglas importa modelos, que no deben cargarse al leer
        # la configuración en contextos ligeros (alembic, CLI).
        from app.detection.rules import RULE_IDS

        unknown = set(parse_name_list(self.detection_disabled_rules)) - RULE_IDS
        if unknown:
            raise ValueError(f"DETECTION_DISABLED_RULES has unknown rule ids: {sorted(unknown)}")
        longest = max(
            self.detection_auth_failure_window_minutes,
            self.detection_correlation_window_minutes,
            self.detection_change_window_minutes,
            self.detection_repeat_window_minutes,
        )
        # Una señal purgada antes de cerrar su ventana haría que la correlación no ocurriera.
        if self.detection_signal_retention_hours * 60 < longest:
            raise ValueError(
                "DETECTION_SIGNAL_RETENTION_HOURS must cover the longest detection window"
            )
        return self

    @field_validator("risk_level_thresholds")
    @classmethod
    def _check_risk_thresholds(cls, value: str) -> str:
        # Unos umbrales mal escritos pararían la API al arrancar, nunca se "arreglan" solos.
        parse_risk_thresholds(value)
        return value

    @model_validator(mode="after")
    def _check_discovery(self) -> "Settings":
        # Same rule as for alert lists: a bad allowlist stops the API at startup, it is
        # never silently ignored or "fixed" into something that might scan more.
        self.discovery_scope()
        parse_ports(self.discovery_ports)
        return self

    def discovery_scope(self) -> DiscoveryScope:
        return DiscoveryScope.parse(
            self.discovery_allowed_networks,
            self.discovery_excluded,
            self.discovery_max_hosts_per_network,
            self.discovery_allow_public_networks,
        )

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def allowed_host_list(self) -> list[str]:
        return parse_name_list(self.allowed_hosts)

    @property
    def cookie_secure(self) -> bool:
        if self.session_cookie_secure is None:
            return self.is_production
        return self.session_cookie_secure

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def trusted_proxy_networks(self) -> tuple[AINetwork, ...]:
        return parse_networks(self.trusted_proxies, "TRUSTED_PROXIES")

    @property
    def metrics_networks(self) -> tuple[AINetwork, ...]:
        return parse_networks(self.metrics_allowed_networks, "METRICS_ALLOWED_NETWORKS")

    @property
    def effective_rate_limit_backend(self) -> Literal["memory", "database"]:
        if self.rate_limit_backend == "auto":
            return "database" if self.is_production else "memory"
        return self.rate_limit_backend


@lru_cache
def get_settings() -> Settings:
    return Settings()

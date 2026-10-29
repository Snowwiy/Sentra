"""Roles y permisos del dashboard (RBAC).

Los endpoints nunca comparan roles (`if role == "admin"`): piden un permiso concreto con
`require_permission(Permission.X)` (api/auth.py) y esta tabla decide qué roles lo tienen.
Así un rol nuevo, o mover una capacidad de un rol a otro, es un cambio en un único sitio y
una comparación de rol mal escrita no puede abrir un endpoint por accidente.

Mínimo privilegio: cada permiso de escritura se concede explícitamente; ningún rol hereda
"todo" por defecto salvo admin, que se construye como la unión de todos los permisos.
"""

import enum


class Role(enum.StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Permission(enum.StrEnum):
    # Lectura de monitorización: activos, telemetría, eventos, inventario, procesos,
    # exposición, alertas, resultados de discovery e información de agentes (sin secretos).
    MONITORING_READ = "monitoring:read"
    # Reconocer y resolver alertas.
    ALERTS_MANAGE = "alerts:manage"
    # Reconocer y resolver detecciones del motor (Fase 4H). Leerlas es monitoring:read.
    DETECTIONS_MANAGE = "detections:manage"
    # Cambiar datos de contexto de un activo que alteran el riesgo (criticidad, Fase 4I).
    # Solo admin: un viewer o analyst no puede rebajar el riesgo de un activo a mano.
    ASSETS_MANAGE = "assets:manage"
    # Fase 5C.1: ver sugerencias de posibles duplicados (reinstalaciones, activos descubiertos
    # del mismo equipo). Archivar, restaurar, borrar y reconciliar siguen siendo assets:manage
    # (y agents:manage para reconciliar): solo admin.
    ASSET_DUPLICATES_READ = "assets:duplicates_read"
    # Iniciar y cancelar descubrimientos de red (siempre dentro de la allowlist del servidor).
    DISCOVERY_RUN = "discovery:run"
    # Fase 6A: fijar límites de un discovery avanzado (timeouts, concurrencia, ritmo,
    # reintentos, hosts, duración) y puertos fuera del perfil, siempre bajo los topes del
    # servidor. Solo admin: cambia cuánta carga recibe la red de un site.
    DISCOVERY_TUNE = "discovery:tune"
    # Revocar y rehabilitar agentes.
    AGENTS_MANAGE = "agents:manage"
    # Crear, listar y revocar tokens de enrollment: dan acceso a la plataforma a un host nuevo.
    ENROLLMENT_MANAGE = "enrollment:manage"
    # Usuarios, roles, contraseñas y sesiones de otros usuarios.
    USERS_MANAGE = "users:manage"
    # Registro de auditoría.
    AUDIT_READ = "audit:read"
    # AI Security Insights (Fase 4J): pedir análisis de IA sobre datos que el rol ya puede
    # leer (se exige junto con monitoring:read; nunca amplía lo que el rol ve).
    AI_USE = "ai:use"
    # Gestor de modelos locales (Fase 4J.2): registrar, seleccionar y benchmarkear modelos,
    # cambiar el runtime y refrescar el perfil de hardware. Solo admin: cambiar el modelo
    # cambia lo que responde la IA a todos los usuarios.
    AI_MANAGE = "ai:manage"
    # Gestión de incidentes (Fase 4K). Leer casos, timeline, evidencia y notas.
    INCIDENTS_READ = "incidents:read"
    # Trabajar casos: crear, triage/investigación/contención, notas, adjuntar detecciones y
    # alertas, asignarse a sí mismo y resolver.
    INCIDENTS_MANAGE = "incidents:manage"
    # Acciones administrativas sobre casos: reasignar a otros, cerrar, reabrir y fusionar.
    INCIDENTS_ADMIN = "incidents:admin"
    # Reglas de detección (Fase 5A). Ver el catálogo de reglas (built-in, custom y Sigma),
    # sus versiones y estadísticas. No incluye datos de eventos.
    RULES_READ = "rules:read"
    # Validar reglas, probarlas contra eventos sintéticos y previsualizar Sigma. No guarda
    # nada ni crea detecciones.
    RULES_TEST = "rules:test"
    # Crear, importar, editar, versionar, activar, desactivar y retirar reglas, y probarlas
    # contra datos históricos. Solo admin: una regla cambia lo que Sentra detecta (o deja de
    # detectar) para todos.
    RULES_MANAGE = "rules:manage"
    # Vulnerability & Exposure Management (Fase 5B). Ver findings, su evidencia, historial,
    # exposición y el catálogo local importado (nunca el inventario completo de otro modo).
    VULNERABILITIES_READ = "vulnerabilities:read"
    # Trabajar findings: reconocer, marcar en mitigación, resolver (con motivo) y abrir un
    # incidente desde un finding.
    VULNERABILITIES_MANAGE = "vulnerabilities:manage"
    # Decisiones que ocultan riesgo o cambian lo que Sentra evalúa: aceptar riesgo, falso
    # positivo, reabrir, importar el catálogo y forzar una reevaluación. Solo admin.
    VULNERABILITIES_ADMIN = "vulnerabilities:admin"
    # Threat Intelligence (Fase 5C). Ver fuentes (sin secretos), su estado, indicadores,
    # matches con datos locales e inteligencia KEV/EPSS de los findings.
    THREAT_INTEL_READ = "threat_intel:read"
    # Trabajar matches: reconocer, descartar como falso positivo (con motivo) y abrir o
    # vincular un incidente desde un match.
    THREAT_INTEL_TRIAGE = "threat_intel:triage"
    # Gestionar fuentes (crear, configurar, activar, desactivar, archivar), pedir una
    # sincronización, importar IOCs y forzar el matching. Solo admin: cambia la inteligencia
    # que influye en la prioridad, el riesgo y las detecciones de todos.
    THREAT_INTEL_MANAGE = "threat_intel:manage"
    # Response Engine y Playbooks (Fase 5D). Ver el catálogo de acciones y playbooks y el
    # historial de ejecuciones (estado, objetivo, resultado acotado). No ejecuta nada.
    RESPONSE_READ = "response:read"
    # Previsualizar y ejecutar acciones LOW del catálogo y playbooks cuyos pasos permita el
    # rol. Cada acción exige además sus permisos de dominio (p. ej. detections:manage).
    RESPONSE_EXECUTE = "response:execute"
    # Acciones MEDIUM (mutaciones internas: abrir incidente, nota, archivar), administrar
    # playbooks (crear, versionar, activar, desactivar) y cancelar ejecuciones. Solo admin.
    RESPONSE_MANAGE = "response:manage"
    # Reporting (Fase 5E). Ver el catálogo de informes, el historial y descargar artefactos
    # de los tipos cuyos datos el rol ya puede leer (permisos de dominio de cada tipo).
    REPORTS_READ = "reports:read"
    # Previsualizar y generar informes técnicos acotados (incidente, activo, detecciones,
    # vulnerabilidades, riesgo, Response, ciclo de vida) y cancelar los propios.
    REPORTS_GENERATE = "reports:generate"
    # Resumen ejecutivo e informe técnico global, cancelar informes de otros y borrar
    # (expirar) artefactos. Solo admin.
    REPORTS_ADMIN = "reports:admin"
    # Fase 5F. Ver sites y sensores es monitoring:read (sin secretos). Crear, editar,
    # deshabilitar y archivar sites y sus redes autorizadas: solo admin, porque las redes de
    # un site son exactamente lo que sus sensores pueden escanear.
    SITES_MANAGE = "sites:manage"
    # Tokens de enrolamiento de sensores, revocar, deshabilitar, habilitar y rotar credencial:
    # dan o quitan a un proceso remoto la capacidad de observar una red. Solo admin.
    SENSORS_MANAGE = "sensors:manage"
    # Fase 6B. Ver equipos de red, interfaces, vecinos LLDP/CDP, VLANs y tablas MAC es
    # monitoring:read. Pedir y cancelar una consulta SNMP de un equipo ya registrado (con su
    # perfil y su sensor asignados por un admin): solo lectura en el equipo remoto.
    NETWORK_POLL = "network:poll"
    # Registrar, editar y archivar equipos de red y asignarles perfil y sensor: decide qué
    # direcciones de un site consulta un sensor y con qué credencial. Solo admin.
    NETWORK_MANAGE = "network:manage"
    # Perfiles de credenciales SNMP (crear, rotar, revocar). Solo admin: dan acceso de
    # lectura a la configuración de los equipos de red de un site.
    SNMP_CREDENTIALS_MANAGE = "snmp_credentials:manage"
    # Fase 6D. Leer el grafo de topología es monitoring:read. Reconstruirlo a demanda y
    # revisar enlaces (aceptar/rechazar): solo admin, porque la revisión cambia lo que ven
    # todos los usuarios y los informes, y una reconstrucción carga la base de datos.
    TOPOLOGY_MANAGE = "topology:manage"
    # Fase 6E.2. Declarar fuentes DHCP, importar leases y pedir lecturas a un sensor: solo
    # admin, porque una fuente decide qué nombre ven todos para cada equipo. Leer leases e
    # identidad es monitoring:read, como el resto del inventario.
    DHCP_MANAGE = "dhcp:manage"
    # Fase 6E.3/6E.4. Actividad del endpoint y árbol de procesos: líneas de comando, usuarios
    # y conexiones son datos sensibles, así que viewer no los ve.
    TELEMETRY_READ = "telemetry:read"
    # Fase 6E.6. Investigaciones forenses. Leer y adquirir (acciones de solo lectura del
    # Response Engine) y descargar evidencias: analyst. Cerrar, conservar y borrar: admin.
    FORENSICS_READ = "forensics:read"
    FORENSICS_ACQUIRE = "forensics:acquire"
    FORENSICS_DOWNLOAD = "forensics:download"
    FORENSICS_MANAGE = "forensics:manage"
    # Fase 6E.7. Aislamiento de un endpoint. Ver el estado y la vista previa: analyst.
    # Aislar y liberar: solo admin (acción automática sobre un activo, con confirmación).
    CONTAINMENT_PREVIEW = "containment:preview"
    CONTAINMENT_ISOLATE = "containment:isolate"
    CONTAINMENT_RELEASE = "containment:release"
    # Fase 7A: Analyst Tool Engine. Ver el catálogo de herramientas y el historial propio de
    # ejecuciones. Ninguna herramienta amplía lo que el rol ve: cada una exige además sus
    # permisos de dominio (p. ej. telemetry:read para el árbol de procesos).
    TOOLS_READ = "tools:read"
    # Ejecutar herramientas de lectura e investigación y pedir vistas previas de las de acción.
    # Confirmar una acción exige además los permisos del Response Engine o de casos.
    TOOLS_EXECUTE = "tools:execute"
    # Ver y cancelar ejecuciones de otros usuarios. Solo admin.
    TOOLS_MANAGE = "tools:manage"
    # Fase 7A.6: aprobar o rechazar una solicitud de control de red (puerto, servicio,
    # dirección, dominio, sitio o subida). Solo admin: decide qué se bloquearía. Proponerla y
    # trabajar las tareas de un caso es incidents:manage.
    NETWORK_CONTROLS_APPROVE = "network_controls:approve"
    # Fase 7B.1: crear, aprobar, revocar y aplicar operaciones de mantenimiento autorizadas
    # (docs/detection-attribution.md). Solo admin: una operación aprobada cierra como
    # mantenimiento verificado las detecciones cuya evidencia describe. Leerlas es
    # monitoring:read y dar un veredicto de analista es detections:manage.
    MAINTENANCE_MANAGE = "maintenance:manage"
    # Fase 7B.2: asociar a mano una observación (MAC, cliente Wi-Fi) a un activo y deshacerlo.
    # Solo admin: cambia la identidad de un dispositivo; las sugerencias se leen con
    # monitoring:read y nunca se aplican solas.
    IDENTITY_MANAGE = "identity:manage"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset(
        {
            Permission.MONITORING_READ,
            Permission.AI_USE,
            Permission.INCIDENTS_READ,
            Permission.RULES_READ,
            Permission.VULNERABILITIES_READ,
            Permission.THREAT_INTEL_READ,
            Permission.RESPONSE_READ,
            Permission.REPORTS_READ,
            Permission.TOOLS_READ,
        }
    ),
    # Analyst opera la seguridad (alertas, detecciones, discovery dentro de la allowlist)
    # pero no gestiona credenciales (agentes, tokens de enrollment) ni usuarios.
    Role.ANALYST: frozenset(
        {
            Permission.MONITORING_READ,
            Permission.ALERTS_MANAGE,
            Permission.DETECTIONS_MANAGE,
            Permission.DISCOVERY_RUN,
            Permission.ASSET_DUPLICATES_READ,
            Permission.AI_USE,
            Permission.INCIDENTS_READ,
            Permission.INCIDENTS_MANAGE,
            Permission.RULES_READ,
            Permission.RULES_TEST,
            Permission.VULNERABILITIES_READ,
            Permission.VULNERABILITIES_MANAGE,
            Permission.THREAT_INTEL_READ,
            Permission.THREAT_INTEL_TRIAGE,
            Permission.RESPONSE_READ,
            Permission.RESPONSE_EXECUTE,
            Permission.REPORTS_READ,
            Permission.REPORTS_GENERATE,
            Permission.NETWORK_POLL,
            Permission.TELEMETRY_READ,
            Permission.FORENSICS_READ,
            Permission.FORENSICS_ACQUIRE,
            Permission.FORENSICS_DOWNLOAD,
            Permission.CONTAINMENT_PREVIEW,
            Permission.TOOLS_READ,
            Permission.TOOLS_EXECUTE,
        }
    ),
    Role.ADMIN: frozenset(Permission),
}


def permissions_for(role: str) -> frozenset[Permission]:
    """Permisos de un rol; un valor desconocido (BD manipulada, rol retirado) no da ninguno."""
    try:
        return ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return frozenset()

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
    # Iniciar y cancelar descubrimientos de red (siempre dentro de la allowlist del servidor).
    DISCOVERY_RUN = "discovery:run"
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


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({Permission.MONITORING_READ, Permission.AI_USE}),
    # Analyst opera la seguridad (alertas, detecciones, discovery dentro de la allowlist)
    # pero no gestiona credenciales (agentes, tokens de enrollment) ni usuarios.
    Role.ANALYST: frozenset(
        {
            Permission.MONITORING_READ,
            Permission.ALERTS_MANAGE,
            Permission.DETECTIONS_MANAGE,
            Permission.DISCOVERY_RUN,
            Permission.AI_USE,
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

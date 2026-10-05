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


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({Permission.MONITORING_READ}),
    # Analyst opera la seguridad (alertas, discovery dentro de la allowlist) pero no gestiona
    # credenciales (agentes, tokens de enrollment) ni usuarios.
    Role.ANALYST: frozenset(
        {Permission.MONITORING_READ, Permission.ALERTS_MANAGE, Permission.DISCOVERY_RUN}
    ),
    Role.ADMIN: frozenset(Permission),
}


def permissions_for(role: str) -> frozenset[Permission]:
    """Permisos de un rol; un valor desconocido (BD manipulada, rol retirado) no da ninguno."""
    try:
        return ROLE_PERMISSIONS[Role(role)]
    except ValueError:
        return frozenset()

"""Reconocimiento de macOS a partir del os_name que informa un agente (Fase 6C.5).

Vive en core para que el enrolamiento, la gestión de agentes y el catálogo de respuesta
compartan la misma regla sin importarse entre sí. Las reglas existentes para Windows y Linux
no se tocan (cada sitio conserva la suya) para no cambiar cómo se clasifican activos ya
registrados.
"""

# El agente de macOS informa "macOS"; un agente anterior ejecutado en un Mac informaba
# "Darwin" (platform.system()), así que ambos cuentan como macOS. Se compara por prefijo para
# que un nombre libre que solo contenga "darwin" no se clasifique por accidente.
_MACOS_PREFIXES = ("macos", "mac os", "darwin")


def is_macos(os_name: str | None) -> bool:
    return (os_name or "").strip().lower().startswith(_MACOS_PREFIXES)

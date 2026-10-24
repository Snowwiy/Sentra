"""Aislamiento seguro del equipo (Fase 6E.7): piezas puras y backends de firewall.

Modelo de privilegios (pendiente de confirmar por el propietario): el agente NO gana
privilegios. Solo un helper separado y opcional (`python -m sentra_agent.isolation_helper`,
servicio LocalSystem en Windows / unidad systemd root en Linux) toca el firewall, con su propia
política local. El agente le pasa únicamente `{session_id, action, expires_at}`; las
direcciones permitidas las calcula el helper (nunca vienen de la petición).

- `addresses`: cálculo puro de lo permitido y de su complemento en rangos.
- `windows`: reglas de bloqueo del Firewall de Windows Defender en el grupo propio.
- `nft`: tabla propia `inet sentra_isolation` de nftables.
- `policy`: política local del helper (isolation.toml).
- `exchange`: formato y E/S de request.json / status.json / state.json.
- `client`: lado del agente (escribe la petición y espera el estado del helper).
"""

GROUP = "Sentra Isolation"
NFT_TABLE = "sentra_isolation"

# Estados del helper (heartbeat.isolation.helper) y de la sesión (heartbeat.isolation.state).
HELPER_ABSENT = "absent"
HELPER_DISABLED = "disabled"
HELPER_READY = "ready"
HELPER_ERROR = "error"
STATE_NONE = "none"
STATE_APPLYING = "applying"
STATE_ISOLATED = "isolated"
STATE_REVERTING = "reverting"
STATE_FAILED = "failed"

METHOD_WINDOWS = "windows_firewall"
METHOD_NFTABLES = "nftables"


class IsolationError(Exception):
    """Fallo con código estable (error_code del contrato)."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code

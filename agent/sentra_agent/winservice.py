"""Integración con el Service Control Manager (SCM) de Windows: servicio "SentraAgent".

Se llama a advapi32 con ctypes en lugar de usar pywin32/pythonservice.exe, igual que DPAPI en
credentials.py: sin dependencias extra, sin DLL que registrar y con el mismo python.exe
embebido como binario del servicio. El servicio es un servicio Windows estándar, visible en
services.msc, `Get-Service SentraAgent` y `sc.exe query SentraAgent`; no se oculta nada.

La lógica de estados (`StatusReporter`, `run_service_body`) no depende de Windows y se prueba
en cualquier plataforma; solo `dispatch()` toca el SCM.

🪟 VALIDACIÓN EN WINDOWS REAL: el arranque bajo el SCM, la parada y el reinicio por fallo solo
pueden comprobarse en un Windows físico (checklist en docs/agent-windows-installation.md).
"""

import logging
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger("sentra_agent")

SERVICE_NAME = "SentraAgent"
DISPLAY_NAME = "Sentra Agent"

SERVICE_WIN32_OWN_PROCESS = 0x10
SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4
SERVICE_ACCEPT_STOP = 0x1
SERVICE_ACCEPT_SHUTDOWN = 0x4
SERVICE_CONTROL_STOP = 1
SERVICE_CONTROL_INTERROGATE = 4
SERVICE_CONTROL_SHUTDOWN = 5
NO_ERROR = 0
ERROR_CALL_NOT_IMPLEMENTED = 120
# Con este código el SCM registra el fallo (evento 7024) y, con `sc.exe failureflag 1`, aplica
# las acciones de recuperación aunque el proceso haya terminado de forma ordenada.
ERROR_SERVICE_SPECIFIC_ERROR = 1066
ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063

# Un ciclo del agente puede tardar (inventario, wevtutil con timeout de 60 s por canal), y el
# bucle solo se detiene entre ciclos. Mientras se para, se informa al SCM cada pocos segundos
# con un checkpoint creciente para que no lo dé por colgado; pasado el límite se deja de
# insistir y el SCM decide (en un apagado del sistema, Windows termina el proceso).
STOP_WAIT_HINT_MS = 30_000
STOP_PING_SECONDS = 5.0
STOP_PING_LIMIT_SECONDS = 120.0


@dataclass(frozen=True)
class ServiceStatus:
    state: int
    controls_accepted: int = 0
    win32_exit_code: int = NO_ERROR
    service_exit_code: int = 0
    checkpoint: int = 0
    wait_hint_ms: int = 0


class StatusReporter:
    """Traduce el ciclo de vida del agente a los estados que espera el SCM."""

    def __init__(
        self,
        set_status: Callable[[ServiceStatus], None],
        stop_event: threading.Event,
        ping_seconds: float = STOP_PING_SECONDS,
        ping_limit_seconds: float = STOP_PING_LIMIT_SECONDS,
    ) -> None:
        self._set_status = set_status
        self.stop_event = stop_event
        self._ping_seconds = ping_seconds
        self._ping_limit = ping_limit_seconds
        self._lock = threading.Lock()
        self._checkpoint = 0
        self.state = SERVICE_STOPPED
        self._stopped = threading.Event()

    def report(
        self,
        state: int,
        win32_exit_code: int = NO_ERROR,
        service_exit_code: int = 0,
        only_if: int | None = None,
    ) -> None:
        # Todo el informe ocurre bajo el lock, incluida la llamada al SCM: así el hilo que
        # repite STOP_PENDING nunca puede enviar su informe después de STOPPED (el SCM
        # volvería a ver el servicio como "deteniéndose").
        with self._lock:
            if only_if is not None and self.state != only_if:
                return
            pending = state in (SERVICE_START_PENDING, SERVICE_STOP_PENDING)
            # El checkpoint solo tiene sentido en estados pendientes y debe crecer en cada
            # informe; en estados estables vale 0 (documentado en SERVICE_STATUS).
            self._checkpoint = self._checkpoint + 1 if pending else 0
            # Solo se aceptan órdenes de parada cuando ya está en marcha: durante el arranque
            # o la parada el SCM no debe enviar otra.
            accepted = (
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN if state == SERVICE_RUNNING else 0
            )
            self.state = state
            status = ServiceStatus(
                state=state,
                controls_accepted=accepted,
                win32_exit_code=win32_exit_code,
                service_exit_code=service_exit_code,
                checkpoint=self._checkpoint,
                wait_hint_ms=STOP_WAIT_HINT_MS if pending else 0,
            )
            if state == SERVICE_STOPPED:
                self._stopped.set()
            self._set_status(status)

    def handle_control(self, control: int) -> int:
        """HandlerEx del SCM. Debe volver enseguida: la parada real ocurre en el bucle."""
        if control in (SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN):
            if not self.stop_event.is_set():
                logger.info(
                    "service stop requested",
                    extra={
                        "control": "shutdown" if control == SERVICE_CONTROL_SHUTDOWN else "stop"
                    },
                )
                self.stop_event.set()
                self.report(SERVICE_STOP_PENDING)
                threading.Thread(target=self._ping_while_stopping, daemon=True).start()
            return NO_ERROR
        if control == SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR
        return ERROR_CALL_NOT_IMPLEMENTED

    def _ping_while_stopping(self) -> None:
        deadline = time.monotonic() + self._ping_limit
        while not self._stopped.wait(self._ping_seconds) and time.monotonic() < deadline:
            self.report(SERVICE_STOP_PENDING, only_if=SERVICE_STOP_PENDING)


def run_service_body(reporter: StatusReporter, body: Callable[[threading.Event], None]) -> int:
    """Ejecuta el agente como ServiceMain y devuelve el código de salida del servicio.

    Una excepción que escape del agente (p. ej. el directorio de estado no es escribible) se
    registra en el log y se informa al SCM como fallo, para que se apliquen las acciones de
    recuperación configuradas por el instalador (reinicio) y quede rastro en el visor de
    eventos (System, evento 7024).
    """
    reporter.report(SERVICE_START_PENDING)
    reporter.report(SERVICE_RUNNING)
    try:
        body(reporter.stop_event)
    except Exception:
        logger.exception("service stopped by an unexpected error")
        reporter.report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 1)
        return 1
    reporter.report(SERVICE_STOPPED)
    return 0


class NotRunningAsServiceError(Exception):
    """Se lanzó `--service` desde una consola en lugar de hacerlo el SCM."""


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _ServiceStatusStruct(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
        ]

    _HANDLER_EX = ctypes.WINFUNCTYPE(
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID
    )
    _SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))

    class _ServiceTableEntry(ctypes.Structure):
        _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", _SERVICE_MAIN)]

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    # Firmas explícitas: la conversión por defecto de ctypes truncaría punteros de 64 bits.
    _advapi32.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(_ServiceTableEntry)]
    _advapi32.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
    _advapi32.RegisterServiceCtrlHandlerExW.argtypes = [
        wintypes.LPCWSTR,
        _HANDLER_EX,
        wintypes.LPVOID,
    ]
    _advapi32.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
    _advapi32.SetServiceStatus.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ServiceStatusStruct),
    ]
    _advapi32.SetServiceStatus.restype = wintypes.BOOL

    def dispatch(body: Callable[[threading.Event], None]) -> int:
        """Conecta con el SCM y ejecuta `body` como el ServiceMain de SentraAgent.

        Bloquea hasta que el servicio se detiene. StartServiceCtrlDispatcherW debe llamarse
        desde el hilo principal; el SCM invoca ServiceMain en otro hilo y HandlerEx en este.
        """
        stop_event = threading.Event()
        holder: dict[str, int] = {"handle": 0, "code": 0}

        def set_status(status: ServiceStatus) -> None:
            raw = _ServiceStatusStruct(
                SERVICE_WIN32_OWN_PROCESS,
                status.state,
                status.controls_accepted,
                status.win32_exit_code,
                status.service_exit_code,
                status.checkpoint,
                status.wait_hint_ms,
            )
            if not _advapi32.SetServiceStatus(holder["handle"], ctypes.byref(raw)):
                logger.warning("SetServiceStatus failed", extra={"error": ctypes.get_last_error()})

        reporter = StatusReporter(set_status, stop_event)

        # Las referencias a los callbacks y a la tabla viven en este marco hasta que el
        # dispatcher vuelve: si el recolector los liberase antes, el SCM llamaría a memoria
        # liberada.
        @_HANDLER_EX  # type: ignore[untyped-decorator]
        def handler(control: int, _event: int, _data: int, _context: int) -> int:
            return reporter.handle_control(control)

        @_SERVICE_MAIN  # type: ignore[untyped-decorator]
        def service_main(_argc: int, _argv: object) -> None:
            handle = _advapi32.RegisterServiceCtrlHandlerExW(SERVICE_NAME, handler, None)
            if not handle:
                holder["code"] = ctypes.get_last_error() or 1
                return
            holder["handle"] = handle
            holder["code"] = run_service_body(reporter, body)

        table = (_ServiceTableEntry * 2)(
            _ServiceTableEntry(SERVICE_NAME, service_main), _ServiceTableEntry()
        )
        if not _advapi32.StartServiceCtrlDispatcherW(table):
            error = ctypes.get_last_error()
            if error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
                raise NotRunningAsServiceError
            raise OSError(error, "StartServiceCtrlDispatcherW failed")
        return holder["code"]

else:

    def dispatch(body: Callable[[threading.Event], None]) -> int:
        raise NotRunningAsServiceError

"""Fase 6B: el transporte real (pysnmp) contra un agente SNMP de pysnmp en 127.0.0.1.

Solo loopback, nada sale a la red. Verifica lo que el agente simulado en memoria no puede:
el cifrado authPriv de SNMPv3 de extremo a extremo, la conversión de tipos ASN.1 y que una
clave errónea se traduce en auth_failed (y un puerto sin agente en timeout).
"""

import asyncio
import contextlib
import gc
import logging
import socket
import threading
import time
import warnings
from collections.abc import Iterator
from typing import Any

import pytest

pytest.importorskip("pysnmp")
pytest.importorskip("cryptography")

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.hlapi.v3arch.asyncio import UdpTransportTarget

from sentra_sensor.snmp import catalog, pysnmp_adapter
from sentra_sensor.snmp.collector import SnmpCollector, SnmpCredentials
from sentra_sensor.snmp.pysnmp_adapter import make_transport, shutdown_loop
from sentra_sensor.snmp.transport import (
    ObjectId,
    SnmpAuthError,
    SnmpTimeoutError,
    SnmpUnreachableError,
    SnmpUnsupportedVersionError,
)

USER = "sentra-ro"
AUTH = "auth-pass-6b-test"  # valor ficticio de test
PRIV = "priv-pass-6b-test"  # valor ficticio de test
COMMUNITY = "community-6b-test"  # valor ficticio de test


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def agent_port() -> Iterator[int]:
    port = _free_port()
    ready = threading.Event()
    state: dict[str, Any] = {}

    def run() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        snmp_engine = engine.SnmpEngine()
        config.add_transport(
            snmp_engine,
            udp.DOMAIN_NAME,
            udp.UdpTransport().open_server_mode(("127.0.0.1", port)),
        )
        config.add_v3_user(
            snmp_engine,
            USER,
            config.USM_AUTH_HMAC192_SHA256,
            AUTH,
            config.USM_PRIV_CFB128_AES,
            PRIV,
        )
        config.add_vacm_user(snmp_engine, 3, USER, "authPriv", (1, 3, 6), (1, 3, 6))
        config.add_v1_system(snmp_engine, "ro-area", COMMUNITY)
        config.add_vacm_user(snmp_engine, 2, "ro-area", "noAuthNoPriv", (1, 3, 6), (1, 3, 6))
        snmp_context = context.SnmpContext(snmp_engine)
        # Solo respondedores de lectura (GET, GETNEXT, GETBULK).
        cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
        cmdrsp.NextCommandResponder(snmp_engine, snmp_context)
        cmdrsp.BulkCommandResponder(snmp_engine, snmp_context)
        state["loop"], state["engine"] = loop, snmp_engine
        ready.set()
        loop.run_forever()
        # Mismo cierre ordenado que el transporte: cerrar el dispatcher con el bucle parado
        # y sin drenarlo dejaba su tarea handle_timeout en "cancelling" y el socket del
        # agente abierto (aviso "Task was destroyed but it is pending" al final de pytest).
        shutdown_loop(loop, snmp_engine)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert ready.wait(10)
    yield port
    state["loop"].call_soon_threadsafe(state["loop"].stop)
    thread.join(10)
    assert not thread.is_alive()
    assert state["loop"].is_closed()


def v3(auth: str = AUTH, priv: str = PRIV) -> SnmpCredentials:
    return SnmpCredentials("v3", USER, "sha256", "aes128", auth, priv)


def test_v3_authpriv_get_and_bulk(agent_port: int) -> None:
    transport = make_transport("127.0.0.1", agent_port, v3(), 3000, 1)
    try:
        values = dict(transport.get([catalog.SYS_DESCR, catalog.SYS_OBJECT_ID]))
        assert isinstance(values[catalog.SYS_DESCR], bytes)
        assert isinstance(values[catalog.SYS_OBJECT_ID], ObjectId)  # no se pierde como None
        rows = transport.get_bulk(catalog.oid("1.3.6.1.2.1.1"), 5)
        assert rows and all(name > catalog.oid("1.3.6.1.2.1.1") for name, _ in rows)
    finally:
        transport.close()


def test_collector_over_real_transport(agent_port: int) -> None:
    emitted: list[dict[str, Any]] = []
    collector = SnmpCollector(
        ("system", "interfaces", "lldp"),
        lambda: make_transport("127.0.0.1", agent_port, v3(), 3000, 1),
        emitted.extend,
        max_varbinds=5000,
        max_rows=1000,
        max_repetitions=10,
        deadline_seconds=60,
    )
    report = collector.run()
    assert report.outcome == "completed"
    assert report.modules["system"] == "complete"
    assert report.modules["lldp"] == "unsupported"
    (system,) = [r for r in emitted if r["kind"] == "system"]
    assert system["sys_object_id"].startswith("1.3.6.1.4.1.")


def test_v2c_community_when_enabled(agent_port: int) -> None:
    creds = SnmpCredentials("v2c", community=COMMUNITY)
    transport = make_transport("127.0.0.1", agent_port, creds, 3000, 1)
    try:
        assert transport.get([catalog.SYS_DESCR])[0][1]
    finally:
        transport.close()


def test_wrong_v3_key_is_auth_failed(agent_port: int) -> None:
    transport = make_transport("127.0.0.1", agent_port, v3(auth="wrong-pass-6b"), 2000, 0)
    try:
        with pytest.raises(SnmpAuthError):
            transport.get([catalog.SYS_DESCR])
    finally:
        transport.close()


def test_port_without_agent_times_out() -> None:
    transport = make_transport("127.0.0.1", _free_port(), v3(), 300, 0)
    try:
        with pytest.raises(SnmpTimeoutError):
            transport.get([catalog.SYS_DESCR])
    finally:
        transport.close()


def test_v3_never_downgrades_to_no_priv() -> None:
    creds = SnmpCredentials("v3", USER, "sha256", None, AUTH, None)
    with pytest.raises(SnmpUnsupportedVersionError):
        make_transport("127.0.0.1", 161, creds, 1000, 0)
    with pytest.raises(SnmpUnsupportedVersionError):
        make_transport("127.0.0.1", 161, SnmpCredentials("v1", community="x"), 1000, 0)


class _LoopLeaks:
    """Recoge lo que un cierre incompleto deja: tareas destruidas pendientes y sockets.

    No filtra ni oculta avisos: los registra para que la prueba falle si aparece alguno.
    """

    def __init__(self) -> None:
        self.messages: list[str] = []

    def handler(self, loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
        self.messages.append(str(context.get("message")))

    def watch(self, loop: asyncio.AbstractEventLoop) -> None:
        loop.set_exception_handler(self.handler)


def _closed_port() -> int:
    return _free_port()  # nada escucha: la consulta acaba en timeout


# Recursos que puede dejar abiertos el transporte pysnmp. Fix 2: el gc.collect() de abajo
# recoge también basura de tests anteriores (en Windows, conexiones SQLite de spools sin
# cerrar); esas fugas se corrigieron en su origen (conftest.track_resource) y aquí solo se
# juzgan las de este transporte. Las demás no se ocultan: se vuelven a emitir para pytest.
_TRANSPORT_LEAK_MARKERS = ("socket", "transport", "event loop")


@contextlib.contextmanager
def _recorded_warnings() -> Iterator[list[warnings.WarningMessage]]:
    # Basura previa fuera de la ventana observada: sus avisos van a pytest como siempre.
    gc.collect()
    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        yield recorded
    for w in recorded:
        if not _is_transport_leak(w):
            warnings.warn_explicit(w.message, w.category, w.filename, w.lineno, source=w.source)


def _is_transport_leak(w: warnings.WarningMessage) -> bool:
    text = str(w.message).lower()
    return issubclass(w.category, ResourceWarning) and any(
        marker in text for marker in _TRANSPORT_LEAK_MARKERS
    )


def _assert_released(transport: Any, leaks: _LoopLeaks, recorded: list[Any]) -> None:
    loop = transport._loop
    assert loop.is_closed()
    del transport
    gc.collect()
    assert leaks.messages == []
    assert [str(w.message) for w in recorded if _is_transport_leak(w)] == []
    assert not [t for t in threading.enumerate() if t.name.startswith("asyncio_")]


def test_transport_leak_filter_keeps_pysnmp_leaks_and_forwards_others() -> None:
    # El alcance del filtro: un socket o transporte sin cerrar cuenta como fuga del
    # transporte; una conexión SQLite ajena no, pero tampoco desaparece.
    sock = warnings.WarningMessage(
        ResourceWarning("unclosed <socket.socket fd=9>"), ResourceWarning, "x.py", 1
    )
    loop_transport = warnings.WarningMessage(
        ResourceWarning("unclosed transport <_SelectorDatagramTransport>"),
        ResourceWarning,
        "x.py",
        1,
    )
    database = warnings.WarningMessage(
        ResourceWarning("unclosed database in <sqlite3.Connection object>"),
        ResourceWarning,
        "x.py",
        1,
    )
    assert _is_transport_leak(sock) and _is_transport_leak(loop_transport)
    assert not _is_transport_leak(database)
    with pytest.warns(ResourceWarning, match="unclosed database"), _recorded_warnings():
        warnings.warn(
            "unclosed database in <sqlite3.Connection object>", ResourceWarning, stacklevel=1
        )


def test_close_releases_dispatcher_task_and_socket(agent_port: int) -> None:
    leaks = _LoopLeaks()
    with _recorded_warnings() as recorded:
        transport = make_transport("127.0.0.1", agent_port, v3(), 3000, 1)
        leaks.watch(transport._loop)
        assert transport.get([catalog.SYS_DESCR])
        # La consulta deja vivo el temporizador del dispatcher (handle_timeout).
        timers = [t for t in asyncio.all_tasks(transport._loop) if not t.done()]
        assert timers
        transport.close()
        assert all(t.done() for t in timers)
        transport.close()  # idempotente
        _assert_released(transport, leaks, recorded)


def test_close_after_timeout_and_on_exception_paths() -> None:
    leaks = _LoopLeaks()
    with _recorded_warnings() as recorded:
        transport = make_transport("127.0.0.1", _closed_port(), v3(), 200, 0)
        leaks.watch(transport._loop)
        try:
            with pytest.raises(SnmpTimeoutError):
                transport.get([catalog.SYS_DESCR])
            raise RuntimeError("fallo del lector")
        except RuntimeError:
            pass
        finally:
            transport.close()
        _assert_released(transport, leaks, recorded)


def test_close_is_bounded_when_a_task_ignores_cancellation(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    transport = make_transport("127.0.0.1", _closed_port(), v3(), 200, 0)
    leaks = _LoopLeaks()
    leaks.watch(transport._loop)
    release = threading.Event()

    async def stubborn() -> None:
        # Simula una tarea que se resiste a la cancelación: el cierre no puede esperarla
        # para siempre.
        while not release.is_set():
            try:
                await asyncio.sleep(0.05)
            except asyncio.CancelledError:
                continue

    task = transport._loop.create_task(stubborn())
    transport._loop.run_until_complete(asyncio.sleep(0))  # la tarea arranca
    monkeypatch.setattr(pysnmp_adapter, "CLOSE_TIMEOUT_SECONDS", 0.3)
    started = time.monotonic()
    with caplog.at_level(logging.WARNING, logger="sentra_sensor.snmp"):
        transport.close()
    assert time.monotonic() - started < 3
    assert transport._loop.is_closed()
    assert any("did not finish on close" in r.getMessage() for r in caplog.records)
    release.set()
    del task, transport
    gc.collect()  # la tarea rebelde sí se destruye pendiente: es el caso que se acota


def test_init_failure_closes_the_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    loops: list[asyncio.AbstractEventLoop] = []
    real_new_loop = asyncio.new_event_loop

    def tracking_loop() -> asyncio.AbstractEventLoop:
        loop = real_new_loop()
        loops.append(loop)
        return loop

    async def unreachable(*args: Any, **kwargs: Any) -> Any:
        raise OSError("network unreachable")

    async def interrupted(*args: Any, **kwargs: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(asyncio, "new_event_loop", tracking_loop)
    monkeypatch.setattr(UdpTransportTarget, "create", unreachable)
    with pytest.raises(SnmpUnreachableError):
        make_transport("127.0.0.1", 161, v3(), 200, 0)
    monkeypatch.setattr(UdpTransportTarget, "create", interrupted)
    with pytest.raises(KeyboardInterrupt):
        make_transport("127.0.0.1", 161, v3(), 200, 0)
    assert len(loops) == 2 and all(loop.is_closed() for loop in loops)
    # Credencial inválida: ni siquiera se crea el bucle.
    with pytest.raises(SnmpUnsupportedVersionError):
        make_transport("127.0.0.1", 161, v3(priv=""), 200, 0)
    assert len(loops) == 2

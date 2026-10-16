"""Transporte SNMP real sobre pysnmp (Fase 6B). Único módulo que importa pysnmp.

- Solo get_cmd y bulk_cmd: este módulo no importa ninguna operación de escritura.
- SNMPv3 siempre authPriv (SHA-1/SHA-2 + AES); SNMPv2c solo si el servidor lo envía (la
  política v2c la decide el admin en el servidor). SNMPv1 no existe.
- lookupMib=False: los OIDs se tratan como números, sin cargar MIBs ni resolver nombres.
- pysnmp 7 es asíncrono: cada transporte tiene su propio bucle de eventos en el hilo del
  job y lo cierra al terminar con shutdown_loop (fix 1 de 6B, ver su docstring).
"""

import asyncio
import contextlib
import ipaddress
import logging
import socket
from collections.abc import Sequence
from typing import Any

from pyasn1.type import univ
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    Udp6TransportTarget,
    UdpTransportTarget,
    UsmUserData,
    bulk_cmd,
    get_cmd,
    usmAesBlumenthalCfb192Protocol,
    usmAesBlumenthalCfb256Protocol,
    usmAesCfb128Protocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACSHAAuthProtocol,
)
from pysnmp.proto import errind, rfc1905

from sentra_sensor.snmp.collector import SnmpCredentials
from sentra_sensor.snmp.transport import (
    ObjectId,
    Oid,
    SnmpAuthError,
    SnmpError,
    SnmpMalformedError,
    SnmpTimeoutError,
    SnmpUnreachableError,
    SnmpUnsupportedVersionError,
    Value,
    VarBind,
)

AUTH_PROTOCOLS: dict[str, Any] = {
    "sha": usmHMACSHAAuthProtocol,
    "sha224": usmHMAC128SHA224AuthProtocol,
    "sha256": usmHMAC192SHA256AuthProtocol,
    "sha384": usmHMAC256SHA384AuthProtocol,
    "sha512": usmHMAC384SHA512AuthProtocol,
}
# AES-192/256 con extensión de clave de draft-blumenthal (la de Net-SNMP). Algunos equipos
# Cisco usan la variante "Reeder" (3DES-like): con ellos, usar AES-128 (docs, Limitaciones).
PRIV_PROTOCOLS: dict[str, Any] = {
    "aes128": usmAesCfb128Protocol,
    "aes192": usmAesBlumenthalCfb192Protocol,
    "aes256": usmAesBlumenthalCfb256Protocol,
}
_AUTH_ERRORS = (
    errind.UnknownUserName,
    errind.WrongDigest,
    errind.DecryptionError,
    errind.UnknownSecurityName,
    errind.AuthenticationFailure,
    errind.AuthenticationError,
    errind.UnknownCommunityName,
)
_VERSION_ERRORS = (
    errind.UnsupportedSecurityLevel,
    errind.UnsupportedSecurityModel,
    errind.UnsupportedAuthProtocol,
    errind.UnsupportedPrivProtocol,
    errind.UnsupportedMsgProcessingModel,
)
# PDU errorStatus: tooBig(1), authorizationError(16).
_TOO_BIG = 1
_AUTHORIZATION_ERROR = 16
# Tope del cierre: cancelar tareas y parar el ejecutor de getaddrinfo nunca debe colgar el
# hilo del job. Holgado frente a lo que tarda de verdad (milisegundos).
CLOSE_TIMEOUT_SECONDS = 5.0

logger = logging.getLogger("sentra_sensor.snmp")


async def _drain(loop: asyncio.AbstractEventLoop, timeout: float) -> None:
    current = asyncio.current_task()
    pending = {task for task in asyncio.all_tasks(loop) if task is not current}
    for task in pending:
        task.cancel()
    if pending:
        _, stuck = await asyncio.wait(pending, timeout=timeout)
        if stuck:
            # No se espera más: el cierre acotado pesa más que un aviso en el log.
            logger.warning("snmp loop tasks did not finish on close", extra={"tasks": len(stuck)})
    await loop.shutdown_asyncgens()
    # UdpTransportTarget.create resuelve con loop.getaddrinfo, que usa el ejecutor por
    # defecto: se para aquí para no dejar su hilo vivo tras cerrar el bucle.
    try:
        await asyncio.wait_for(loop.shutdown_default_executor(), timeout)
    except TimeoutError:
        logger.warning("snmp resolver executor did not stop on close")


def shutdown_loop(
    loop: asyncio.AbstractEventLoop, engine: Any, timeout: float | None = None
) -> None:
    """Libera el dispatcher de pysnmp y cierra su bucle de forma ordenada y acotada.

    Causa del aviso "Task was destroyed but it is pending ... handle_timeout()":
    close_dispatcher() cierra los sockets UDP y cancela la tarea de temporizador del
    AsyncioDispatcher, pero cancelar solo marca la tarea como "cancelling" y el cierre del
    socket solo programa connection_lost; ambas cosas ocurren en la siguiente vuelta del
    bucle. Si el bucle se cierra sin volver a ejecutarse, la tarea queda pendiente para
    siempre (el GC la destruye con ese aviso) y el socket queda abierto hasta el GC
    (ResourceWarning "unclosed transport"). Por eso aquí, con el bucle parado:

    1. close_dispatcher() (cierra transportes y cancela el temporizador);
    2. se ejecuta el bucle una vez más para drenar: se cancela cualquier otra tarea viva y
       se espera, con tope, a que todas terminen; corren los connection_lost pendientes;
    3. se cierran los generadores asíncronos y el ejecutor por defecto, con tope;
    4. loop.close() siempre, aunque algo de lo anterior falle.

    Debe llamarse desde el hilo dueño del bucle y con el bucle parado. Es idempotente.
    """
    if loop.is_closed():
        return
    try:
        # De mejor esfuerzo: un fallo al cerrar no debe ocultar el resultado del job.
        with contextlib.suppress(Exception):
            engine.close_dispatcher()
        with contextlib.suppress(Exception):
            limit = CLOSE_TIMEOUT_SECONDS if timeout is None else timeout
            loop.run_until_complete(_drain(loop, limit))
    finally:
        loop.close()


def _auth_data(credentials: SnmpCredentials) -> Any:
    if credentials.snmp_version == "v2c":
        if not credentials.community:
            raise SnmpAuthError("missing community")
        # mpModel=1 = SNMPv2c. Nunca 0 (SNMPv1).
        return CommunityData(credentials.community, mpModel=1)  # noqa: S508  (v2c opt-in del admin)
    if credentials.snmp_version != "v3":
        raise SnmpUnsupportedVersionError("only SNMPv3 and SNMPv2c are supported")
    auth = AUTH_PROTOCOLS.get(credentials.auth_protocol or "")
    priv = PRIV_PROTOCOLS.get(credentials.priv_protocol or "")
    if (
        auth is None
        or priv is None
        or not credentials.username
        or not credentials.auth_password
        or not credentials.priv_password
    ):
        # Nunca se degrada a authNoPriv ni noAuthNoPriv.
        raise SnmpUnsupportedVersionError("SNMPv3 requires authPriv with SHA and AES")
    return UsmUserData(
        credentials.username,
        authKey=credentials.auth_password,
        privKey=credentials.priv_password,
        authProtocol=auth,
        privProtocol=priv,
    )


def _convert(value: Any) -> Value:
    if isinstance(value, rfc1905.NoSuchObject | rfc1905.NoSuchInstance):
        return None
    # Se comprueban las clases base de pyasn1: según la ruta de decodificación, pysnmp
    # entrega univ.ObjectIdentifier y no su subclase rfc1902 (comprobado con un agente real).
    # IpAddress, Opaque y Bits derivan de OctetString.
    if isinstance(value, univ.ObjectIdentifier):
        return ObjectId(".".join(str(part) for part in value.asTuple()))
    if isinstance(value, univ.OctetString):
        return bytes(value.asOctets())
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class PysnmpTransport:
    def __init__(
        self,
        target: str,
        port: int,
        credentials: SnmpCredentials,
        timeout_ms: int,
        retries: int,
    ) -> None:
        # Primero la credencial y la dirección: si no son válidas no se crea ni el bucle ni
        # el motor.
        self._auth = _auth_data(credentials)
        address = ipaddress.ip_address(target)
        factory = Udp6TransportTarget if address.version == 6 else UdpTransportTarget
        self._loop = asyncio.new_event_loop()
        try:
            self._engine = SnmpEngine()
            self._context = ContextData()
            self._target = self._loop.run_until_complete(
                factory.create((str(address), port), timeout=timeout_ms / 1000, retries=retries)
            )
        except (OSError, socket.gaierror) as exc:
            self.close()
            raise SnmpUnreachableError(type(exc).__name__) from exc
        except BaseException:
            # Cualquier otra salida (también KeyboardInterrupt o una cancelación) libera el
            # bucle antes de propagarse: nadie llamará a close() de un objeto sin construir.
            self.close()
            raise

    def _check(self, indication: Any, status: Any, varbinds: Any) -> list[VarBind]:
        if indication:
            if isinstance(indication, errind.RequestTimedOut):
                raise SnmpTimeoutError()
            if isinstance(indication, _AUTH_ERRORS):
                raise SnmpAuthError(type(indication).__name__)
            if isinstance(indication, _VERSION_ERRORS):
                raise SnmpUnsupportedVersionError(type(indication).__name__)
            raise SnmpError(type(indication).__name__)
        if status:
            if int(status) == _AUTHORIZATION_ERROR:
                raise SnmpAuthError("authorizationError")
            raise SnmpMalformedError(f"errorStatus {int(status)}")
        out: list[VarBind] = []
        for name, value in varbinds:
            if isinstance(value, rfc1905.EndOfMibView):
                break
            out.append((tuple(int(p) for p in name.asTuple()), _convert(value)))
        return out

    def get(self, oids: Sequence[Oid]) -> list[VarBind]:
        objects = [ObjectType(ObjectIdentity(".".join(map(str, o)))) for o in oids]
        indication, status, _, varbinds = self._loop.run_until_complete(
            get_cmd(
                self._engine, self._auth, self._target, self._context, *objects, lookupMib=False
            )
        )
        return self._check(indication, status, varbinds)

    def get_bulk(self, start: Oid, max_repetitions: int) -> list[VarBind]:
        repetitions = max_repetitions
        while True:
            indication, status, _, varbinds = self._loop.run_until_complete(
                bulk_cmd(
                    self._engine,
                    self._auth,
                    self._target,
                    self._context,
                    0,
                    repetitions,
                    ObjectType(ObjectIdentity(".".join(map(str, start)))),
                    lookupMib=False,
                )
            )
            # tooBig: la respuesta no cabe en un datagrama; se reintenta con menos filas.
            if not indication and status and int(status) == _TOO_BIG and repetitions > 1:
                repetitions = max(1, repetitions // 2)
                continue
            return self._check(indication, status, varbinds)

    def close(self) -> None:
        # Antes de crear el motor no hay dispatcher que liberar, solo el bucle.
        engine = getattr(self, "_engine", None)
        if engine is None:
            if not self._loop.is_closed():
                self._loop.close()
            return
        shutdown_loop(self._loop, engine)


def make_transport(
    target: str, port: int, credentials: SnmpCredentials, timeout_ms: int, retries: int
) -> PysnmpTransport:
    return PysnmpTransport(target, port, credentials, timeout_ms, retries)

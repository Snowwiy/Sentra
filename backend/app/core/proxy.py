"""Cabeceras de reverse proxy de confianza (Fase 4M).

En producción Sentra corre detrás de un reverse proxy (Caddy/nginx) que termina TLS. La
conexión TCP que ve la API es la del proxy, así que la IP real del navegador o del agente y
el esquema original (https) solo llegan en X-Forwarded-For y X-Forwarded-Proto.

Esas cabeceras las puede escribir cualquiera. Si se aceptaran de todos los clientes, un
atacante enviaría `X-Forwarded-For: 1.2.3.4` en cada intento de login y esquivaría el rate
limiting por dirección, o falsearía la IP que queda en la auditoría. Por eso solo se aplican
cuando el par TCP inmediato está en TRUSTED_PROXIES; desde cualquier otra dirección se ignoran
y la IP del cliente es el par real.

`Forwarded` (RFC 7239) no se interpreta: Caddy y nginx envían X-Forwarded-*, y aceptar dos
formatos solo abre la puerta a que discrepen.

Se implementa aquí y no con `uvicorn --proxy-headers` para que la regla sea una sola, esté
probada con Sentra y no dependa de cómo se lanzó uvicorn (en producción se arranca con
`--no-proxy-headers`, ver deploy/systemd/sentra.service).
"""

import ipaddress
from collections.abc import Iterable

from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import AINetwork

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Clave del scope ASGI donde queda el par TCP original (el proxy) para diagnóstico.
PROXY_PEER_KEY = "sentra.proxy_peer"


def parse_ip(value: str) -> IPAddress | None:
    """IP de un elemento de X-Forwarded-For o del par TCP; None si no es una IP válida.

    Acepta "[::1]" y quita el identificador de zona; nunca nombres de host (no se resuelven).
    """
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    value = value.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    # ::ffff:10.0.0.1 es la misma máquina que 10.0.0.1 (sockets dual-stack).
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def is_trusted(address: IPAddress | None, networks: Iterable[AINetwork]) -> bool:
    if address is None:
        return False
    return any(address.version == n.version and address in n for n in networks)


def resolve_client(
    peer: IPAddress, forwarded_for: str | None, networks: tuple[AINetwork, ...]
) -> IPAddress:
    """IP del cliente original a partir del par TCP y de X-Forwarded-For.

    Se recorre la cadena de derecha a izquierda: cada proxy de confianza añade a la derecha
    la IP de quien le habló. La primera dirección que NO es de confianza es el cliente; lo
    que hay a su izquierda lo escribió el propio cliente y no se cree. Un elemento inválido
    corta el recorrido y se queda el último salto válido (nunca basura como IP).
    """
    if not is_trusted(peer, networks) or not forwarded_for:
        return peer
    candidate = peer
    for hop in reversed(forwarded_for.split(",")):
        address = parse_ip(hop)
        if address is None:
            break
        candidate = address
        if not is_trusted(address, networks):
            break
    return candidate


class TrustedProxyMiddleware:
    """Middleware ASGI: fija scope["client"] y scope["scheme"] desde un proxy de confianza."""

    def __init__(self, app: ASGIApp, networks: tuple[AINetwork, ...]) -> None:
        self.app = app
        self.networks = networks

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Sentra solo sirve HTTP (sin websockets).
        if scope["type"] == "http" and self.networks and scope.get("client"):
            peer = parse_ip(str(scope["client"][0]))
            if peer is not None and is_trusted(peer, self.networks):
                headers = _header_values(scope)
                forwarded_for = ",".join(headers.get(b"x-forwarded-for", [])) or None
                client = resolve_client(peer, forwarded_for, self.networks)
                scope = dict(scope)
                scope[PROXY_PEER_KEY] = str(peer)
                scope["client"] = (str(client), 0)
                proto = headers.get(b"x-forwarded-proto")
                if proto:
                    # El valor del proxy más cercano (el último), solo http o https.
                    scheme = proto[-1].split(",")[-1].strip().lower()
                    if scheme in ("http", "https"):
                        scope["scheme"] = scheme
        await self.app(scope, receive, send)


def _header_values(scope: Scope) -> dict[bytes, list[str]]:
    values: dict[bytes, list[str]] = {}
    for name, value in scope.get("headers") or []:
        values.setdefault(name.lower(), []).append(value.decode("latin-1"))
    return values


# Sondas locales que pueden llegar por HTTP en loopback (systemd, monitorización, Prometheus).
HTTPS_EXEMPT_PATHS = frozenset({"/api/v1/health", "/api/v1/health/ready", "/api/v1/metrics"})


class HttpsRequiredMiddleware:
    """Producción: rechaza con 403 https_required cualquier petición que no llegó por HTTPS.

    El esquema es el de la conexión o, detrás de un proxy de TRUSTED_PROXIES, su
    X-Forwarded-Proto (TrustedProxyMiddleware corre antes). Así ni el login ni los agentes
    pueden usar HTTP en claro aunque alguien publique el puerto interno por error: la
    contraseña o el token ya viajaron, pero la operación no se completa y el error dice qué
    corregir. Las sondas de salud y métricas quedan exentas (suelen ir por loopback).
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] == "http"
            and scope.get("scheme") != "https"
            and scope.get("path") not in HTTPS_EXEMPT_PATHS
        ):
            body = (
                b'{"error":{"code":"https_required","message":'
                b'"This Sentra server only accepts HTTPS; use https:// through the reverse proxy"}}'
            )
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                        (b"cache-control", b"no-store"),
                        (b"x-content-type-options", b"nosniff"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)

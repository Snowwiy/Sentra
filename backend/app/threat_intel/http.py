"""Cliente HTTP de las fuentes de inteligencia con protección SSRF. Solo stdlib.

Las URLs de las fuentes las fija el servidor (adapter o THREAT_INTEL_SOURCE_URLS); el
navegador nunca envía una URL para que el backend la descargue. Aun así, cada descarga se
trata como si el destino fuera hostil (DNS manipulado, redirecciones, servidor lento):

1. URL: solo https (http únicamente si la política lo permite fuera de producción y hacia
   una red autorizada), sin credenciales en la URL, sin esquemas file/ftp/gopher/data/...;
2. destino: el host se resuelve UNA vez y TODAS sus IPs deben ser públicas (is_global) o
   estar en THREAT_INTEL_ALLOWED_NETWORKS (espejo interno explícito). Loopback, link-local
   (incluye 169.254.169.254, metadatos de nube), multicast, reservadas, CGNAT, prefijos de
   traducción NAT64 y redes privadas no autorizadas se bloquean;
3. DNS rebinding: se conecta a la IP ya validada (no se vuelve a resolver) y, tras conectar
   y ANTES de enviar nada, se comprueba la IP real del socket. TLS verifica el certificado
   contra el nombre original (SNI), así que fijar la IP no debilita HTTPS;
4. redirecciones: como mucho MAX_REDIRECTS, cada destino pasa de nuevo por 1-3 y nunca se
   baja de https a http;
5. tiempos: conexión, lectura por bloque y un plazo total que acota cada lectura;
6. tamaño: tope de bytes con streaming a un fichero temporal (nunca el feed entero en RAM);
7. sin proxy del entorno ni cabeceras con secretos en logs; los errores no incluyen la URL
   completa ni el cuerpo de la respuesta.

Nunca se usa para un IOC: los indicadores no se visitan ni se resuelven.
"""

import hashlib
import http.client
import ipaddress
import socket
import ssl
import tempfile
import time
from dataclasses import dataclass
from typing import IO
from urllib.parse import urljoin, urlsplit

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

MAX_REDIRECTS = 3
_CHUNK = 64 * 1024
USER_AGENT = "Sentra-ThreatIntel/1.0"
# Prefijos que pueden "envolver" una IPv4 interna dentro de una IPv6 de apariencia pública.
_TRANSLATION = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("2002::/16"),
)
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


class FetchError(Exception):
    """Fallo de descarga con un código estable y un mensaje sin datos sensibles."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class FetchPolicy:
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    total_timeout: float = 120.0
    max_bytes: int = 64 * 1024 * 1024
    # Redes privadas autorizadas explícitamente (espejo interno de un feed).
    allowed_networks: tuple[Network, ...] = ()
    # http solo hacia allowed_networks y nunca en producción (ver config.py).
    allow_http: bool = False
    max_redirects: int = MAX_REDIRECTS


@dataclass
class FetchResult:
    # 200 o 304 (no modificado: no hay contenido).
    status: int
    body: IO[bytes] | None
    size: int
    sha256: str | None
    etag: str | None
    last_modified: str | None
    # Solo el host final (para logs y estado); nunca la URL con su query.
    final_host: str

    def close(self) -> None:
        if self.body is not None:
            self.body.close()


def _literal(host: str) -> IPAddress | None:
    try:
        address = ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def blocked_reason(address: IPAddress, policy: FetchPolicy) -> str | None:
    """Motivo por el que una IP no puede ser destino de una descarga, o None si se permite."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if any(address.version == n.version and address in n for n in policy.allowed_networks):
        return None
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        # Incluye 169.254.169.254 y fe80::/10 (metadatos de nube, autoconfiguración).
        return "link_local_or_metadata"
    if address.is_multicast or address.is_unspecified or address.is_reserved:
        return "reserved"
    if address.version == 4 and address in _CGNAT:
        return "private"
    if address.version == 6 and any(address in n for n in _TRANSLATION):
        return "translated"
    if not address.is_global:
        return "private"
    return None


def check_url(url: str, policy: FetchPolicy) -> tuple[str, str, int, str]:
    """(esquema, host, puerto, ruta+query) de una URL permitida, o FetchError."""
    if not isinstance(url, str) or len(url) > 2048 or any(c in url for c in " \r\n\t\x00"):
        raise FetchError("blocked_destination", "Invalid source URL")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http"):
        raise FetchError("blocked_destination", f"Scheme {scheme or '(none)'} is not allowed")
    if parts.username or parts.password:
        raise FetchError("blocked_destination", "Credentials in the source URL are not allowed")
    host = (parts.hostname or "").lower()
    if not host:
        raise FetchError("blocked_destination", "Source URL has no host")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise FetchError("blocked_destination", "Local host names are not allowed")
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise FetchError("blocked_destination", "Invalid port in source URL") from None
    literal = _literal(host)
    if literal is not None:
        reason = blocked_reason(literal, policy)
        if reason:
            raise FetchError(
                "blocked_destination", f"Destination address is not allowed ({reason})"
            )
    if scheme == "http":
        allowed = (
            policy.allow_http
            and literal is not None
            and any(literal.version == n.version and literal in n for n in policy.allowed_networks)
        )
        if not allowed:
            raise FetchError("blocked_destination", "Plain http is not allowed (use https)")
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    return scheme, host, port, target


def resolve(host: str, port: int, policy: FetchPolicy) -> list[IPAddress]:
    """Resuelve el host y exige que TODAS las IPs estén permitidas (anti rebinding mixto)."""
    literal = _literal(host)
    if literal is not None:
        return [literal]
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        raise FetchError("unavailable", "Source host could not be resolved") from None
    addresses: list[IPAddress] = []
    for info in infos:
        address = _literal(str(info[4][0]))
        if address is None:
            continue
        reason = blocked_reason(address, policy)
        if reason:
            raise FetchError(
                "blocked_destination", f"Source host resolves to a forbidden address ({reason})"
            )
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise FetchError("unavailable", "Source host could not be resolved")
    return addresses


class _Deadline:
    def __init__(self, total: float) -> None:
        self._end = time.monotonic() + total

    def left(self) -> float:
        remaining = self._end - time.monotonic()
        if remaining <= 0:
            raise FetchError("timeout", "The source did not answer in time")
        return remaining


def _connect(
    scheme: str, host: str, port: int, policy: FetchPolicy, deadline: _Deadline
) -> http.client.HTTPConnection:
    addresses = resolve(host, port, policy)
    last_error: Exception | None = None
    for address in addresses:
        try:
            sock = socket.create_connection(
                (str(address), port), timeout=min(policy.connect_timeout, deadline.left())
            )
        except TimeoutError as exc:
            last_error = exc
            continue
        except OSError as exc:
            last_error = exc
            continue
        try:
            # IP real del socket ANTES de enviar nada (defensa en profundidad).
            peer = _literal(str(sock.getpeername()[0]))
            if peer is None or blocked_reason(peer, policy):
                raise FetchError("blocked_destination", "Connected address is not allowed")
            if scheme == "https":
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)
            conn = (
                http.client.HTTPSConnection(host, port)
                if scheme == "https"
                else http.client.HTTPConnection(host, port)
            )
            # Conexión ya establecida con la IP validada: http.client no vuelve a resolver.
            conn.sock = sock
            return conn
        except FetchError:
            sock.close()
            raise
        except (ssl.SSLError, OSError) as exc:
            sock.close()
            if isinstance(exc, ssl.SSLCertVerificationError):
                raise FetchError("tls_error", "TLS certificate verification failed") from None
            last_error = exc
    if isinstance(last_error, TimeoutError):
        raise FetchError("timeout", "Connection to the source timed out")
    raise FetchError(
        "unavailable",
        f"Source unavailable ({type(last_error).__name__ if last_error else 'no address'})",
    )


def fetch(
    url: str,
    policy: FetchPolicy,
    *,
    etag: str | None = None,
    last_modified: str | None = None,
) -> FetchResult:
    """GET con todas las defensas. El llamador debe cerrar FetchResult (fichero temporal)."""
    deadline = _Deadline(policy.total_timeout)
    current = url
    for _ in range(policy.max_redirects + 1):
        scheme, host, port, target = check_url(current, policy)
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            # Sin compresión de transporte: el tamaño leído es el tamaño real.
            "Accept-Encoding": "identity",
        }
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
        conn = _connect(scheme, host, port, policy, deadline)
        try:
            try:
                if conn.sock is not None:
                    conn.sock.settimeout(min(policy.read_timeout, deadline.left()))
                conn.request("GET", target, headers=headers)
                response = conn.getresponse()
                if response.status in (301, 302, 303, 307, 308):
                    location = response.getheader("Location")
                    if not location:
                        raise FetchError("http_error", "Redirect without Location")
                    following = urljoin(current, location)
                    if scheme == "https" and urlsplit(following).scheme.lower() != "https":
                        raise FetchError("blocked_destination", "Redirect downgrades to http")
                    current = following
                    continue
                if response.status == 304:
                    return FetchResult(304, None, 0, None, etag, last_modified, host)
                if response.status != 200:
                    code = (
                        "unavailable"
                        if response.status in (408, 429) or response.status >= 500
                        else "http_error"
                    )
                    raise FetchError(code, f"Source answered HTTP {response.status}")
                declared = response.getheader("Content-Length")
                if declared and declared.isdigit() and int(declared) > policy.max_bytes:
                    raise FetchError(
                        "too_large", f"Source content exceeds {policy.max_bytes} bytes"
                    )
                body = tempfile.TemporaryFile()  # noqa: SIM115 (lo cierra FetchResult.close)
                digest = hashlib.sha256()
                size = 0
                try:
                    while True:
                        if conn.sock is not None:
                            conn.sock.settimeout(min(policy.read_timeout, deadline.left()))
                        chunk = response.read(_CHUNK)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > policy.max_bytes:
                            raise FetchError(
                                "too_large", f"Source content exceeds {policy.max_bytes} bytes"
                            )
                        digest.update(chunk)
                        body.write(chunk)
                except BaseException:
                    body.close()
                    raise
                body.seek(0)
                return FetchResult(
                    200,
                    body,
                    size,
                    digest.hexdigest(),
                    (response.getheader("ETag") or "")[:256] or None,
                    (response.getheader("Last-Modified") or "")[:64] or None,
                    host,
                )
            except TimeoutError:
                raise FetchError("timeout", "The source did not answer in time") from None
            except ssl.SSLCertVerificationError:
                raise FetchError("tls_error", "TLS certificate verification failed") from None
            except (OSError, http.client.HTTPException) as exc:
                raise FetchError(
                    "unavailable", f"Source unavailable ({type(exc).__name__})"
                ) from None
        finally:
            conn.close()
    raise FetchError("blocked_destination", "Too many redirects")

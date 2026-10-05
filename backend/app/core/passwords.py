"""Contraseñas y nombres de usuario del dashboard.

Hashing: Argon2id con argon2-cffi (implementación de referencia, sin criptografía propia) y
sus parámetros por defecto (perfil RFC 9106 de baja memoria: 64 MiB, 3 pasadas). A
diferencia de los tokens de agente (aleatorios de 256 bits, SHA-256 basta), una contraseña
la elige una persona y es adivinable: el hash tiene que ser lento y costoso en memoria para
que una copia filtrada de la tabla `users` no se pueda romper por fuerza bruta.

Política: longitud mínima y lista corta de contraseñas obviamente inválidas, sin reglas de
composición ("mayúscula + símbolo"), que empujan a contraseñas cortas y predecibles. No
consulta servicios externos.
"""

import re
import unicodedata

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

PASSWORD_MIN_LENGTH = 12
# Tope para que una contraseña enorme no sirva para gastar CPU/memoria del servidor.
PASSWORD_MAX_LENGTH = 256

USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 32
# Solo ASCII en minúsculas: evita usuarios que se ven iguales y son distintos
# ("admin" escrito con una letra cirílica, mayúsculas/minúsculas, espacios invisibles).
_USERNAME = re.compile(r"[a-z0-9][a-z0-9._-]*")

# Contraseñas que cumplen la longitud pero son las primeras que prueba cualquier atacante.
# Lista corta y local a propósito: no sustituye a un servicio de contraseñas filtradas.
_COMMON_PASSWORDS = frozenset(
    {
        "123456789012",
        "1234567890123",
        "12345678901234",
        "123456789abc",
        "1q2w3e4r5t6y",
        "aaaaaaaaaaaa",
        "abc123456789",
        "abcdefghijkl",
        "adminadmin12",
        "administrator",
        "changeme1234",
        "contraseña123",
        "contrasena123",
        "iloveyou1234",
        "letmein12345",
        "password1234",
        "password12345",
        "passwordpassword",
        "qwerty123456",
        "qwertyuiop12",
        "qwertyuiopas",
        "sentra123456",
        "sentrasentra",
        "welcome12345",
    }
)

_hasher = PasswordHasher()


class PolicyError(ValueError):
    """Contraseña o nombre de usuario que no cumple la política (mensaje para el operador)."""


def normalize_username(value: str) -> str:
    """Forma canónica con la que se guarda y se busca un usuario.

    NFKC + minúsculas + sin espacios alrededor: "Admin", " admin " y "admin" en
    caracteres de ancho completo son el mismo usuario, así la unicidad del índice es la
    que ve una persona.
    """
    return unicodedata.normalize("NFKC", value).strip().lower()


def validate_username(value: str) -> str:
    """Normaliza y valida; devuelve el nombre canónico o lanza PolicyError."""
    username = normalize_username(value)
    if not USERNAME_MIN_LENGTH <= len(username) <= USERNAME_MAX_LENGTH:
        raise PolicyError(
            f"Username must be {USERNAME_MIN_LENGTH}-{USERNAME_MAX_LENGTH} characters"
        )
    if not _USERNAME.fullmatch(username):
        raise PolicyError(
            "Username may only contain a-z, 0-9, '.', '_' and '-', starting with a letter or digit"
        )
    return username


def validate_password(password: str, username: str | None = None) -> None:
    """Lanza PolicyError si la contraseña no es aceptable. Nunca incluye la contraseña."""
    if len(password) < PASSWORD_MIN_LENGTH:
        raise PolicyError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters")
    if len(password) > PASSWORD_MAX_LENGTH:
        raise PolicyError(f"Password must be at most {PASSWORD_MAX_LENGTH} characters")
    if password.strip() != password or not password.strip():
        # Un espacio al principio o al final suele ser un error al copiar/pegar que luego
        # impide iniciar sesión; se rechaza en vez de recortarlo en silencio.
        raise PolicyError("Password must not start or end with whitespace")
    lowered = password.lower()
    if len(set(lowered)) <= 2 or lowered in _COMMON_PASSWORDS:
        raise PolicyError("Password is too common or too repetitive")
    if username:
        name = normalize_username(username)
        # Con nombres muy cortos ("ana") solo se rechaza la coincidencia exacta: buscarlo
        # como subcadena rechazaría frases normales ("mañana", "ventana").
        if lowered == name or (len(name) >= 4 and name in lowered):
            raise PolicyError("Password must not contain the username")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Comprobación en tiempo constante (argon2). False ante hash corrupto, nunca excepción."""
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    # Si en el futuro suben los parámetros por defecto, el hash se actualiza en el siguiente
    # login correcto, sin pedir a nadie que cambie su contraseña.
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


# Hash de una contraseña aleatoria que nadie conoce. El login lo verifica cuando el usuario
# no existe o está inactivo para que esa respuesta tarde lo mismo que una contraseña
# incorrecta: sin esto el tiempo de respuesta revelaría qué usuarios existen.
_DUMMY_HASH: str | None = None


def burn_verification_time(password: str) -> None:
    global _DUMMY_HASH  # cálculo perezoso, una vez por proceso
    if _DUMMY_HASH is None:
        _DUMMY_HASH = _hasher.hash("sentra-dummy-password-never-used")
    verify_password(password, _DUMMY_HASH)

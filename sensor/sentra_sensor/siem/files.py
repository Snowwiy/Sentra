"""Lector incremental de ficheros JSON Lines del sensor (Fase 7F.3): Suricata EVE, Zeek JSON,
alertas de Wazuh y JSON Lines genérico.

Garantías:
* Solo ficheros declarados dentro de `allowed_dir`. Al abrir se comprueba otra vez la ruta
  REAL (enlaces de directorio, junctions) y se rechaza un enlace simbólico o un punto de
  reanálisis en el propio fichero: un atacante con escritura en el directorio no puede hacer
  que el sensor lea /etc/shadow o la credencial del sensor.
* Offsets persistidos por fichero (identidad = dispositivo + inodo; en Windows, número de
  serie del volumen + índice de fichero NTFS, que es lo que devuelve stat) junto con una
  huella de los primeros bytes ya leídos (HEAD_BYTES). Al reiniciar se continúa donde se
  quedó. Cada pasada clasifica el fichero con los mismos criterios en todas las plataformas,
  tenga el descriptor abierto (Linux, macOS) o se reabra en cada pasada (Windows):
  - nuevo (sin offset guardado): desde el final o el principio según `start_at`;
  - rotado (otra identidad en la misma ruta): se cuenta `rotations` y se lee desde el
    principio; si el anterior seguía abierto, antes se termina por su descriptor;
  - truncado (misma identidad, tamaño menor que el offset): `truncations` y desde el principio;
  - sobrescrito (misma identidad, tamaño suficiente, pero la huella de los primeros bytes ya
    no coincide): también `truncations` y desde el principio, para no leer desde la mitad
    de un contenido distinto;
  - sin cambios o con líneas añadidas: se sigue desde el offset;
  - inaccesible (bloqueo de compartición en Windows, permisos, desaparecido durante la
    rotación): se anota el código y el offset guardado no se toca; se reintenta en la
    siguiente pasada.
  Límite: un fichero reescrito en el sitio con los mismos primeros HEAD_BYTES y un tamaño
  mayor o igual que el offset no se distingue de uno al que se han añadido líneas; y en
  sistemas de ficheros sin índice de fichero (st_ino = 0) una rotación se ve como truncado
  o sobrescritura. En ambos casos el comportamiento es conservador: nunca se relee sin fin
  ni se lee fuera de allowed_dir.
* Solo líneas completas: una línea a medio escribir se lee en la siguiente pasada. Una línea
  mayor que `max_line_bytes` se descarta entera y se cuenta; nunca se carga en memoria más
  de `max_line_bytes` + un bloque de lectura.
* Entrega al menos una vez: el offset se guarda DESPUÉS de que el lote está en el spool. Tras
  una caída entre ambos pasos se releen unas líneas y el servidor las deduplica.
* Saneado mínimo del registro según el formato: JSON válido y objeto; en Suricata se quitan
  las claves con contenido de la comunicación (payload, packet...). Lo demás lo hace el
  normalizador del servidor.
"""

import contextlib
import hashlib
import json
import logging
import os
import stat
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentra_sensor.credentials import atomic_write_json
from sentra_sensor.siem.config import FileInput
from sentra_sensor.siem.syslog import InputCounters, RateLimiter

logger = logging.getLogger("sentra_sensor.siem")

Sink = Callable[[str, dict[str, Any]], None]
Commit = Callable[[str], None]
READ_CHUNK = 256 * 1024
# Bytes del principio del fichero cuya huella se guarda con el offset (detecta sobrescrituras).
HEAD_BYTES = 256
# Entradas del directorio revisadas como mucho al buscar el fichero rotado (modo reapertura).
ROTATED_SCAN_LIMIT = 256
MAX_LINES_PER_CYCLE = 1000
# Bytes leídos como mucho por fichero y pasada (líneas malformadas incluidas): una pasada
# nunca se queda horas en un fichero enorme leído desde el principio.
MAX_BYTES_PER_CYCLE = 8 * 1024 * 1024
SURICATA_PAYLOAD_KEYS = frozenset(
    {
        "payload",
        "payload_printable",
        "packet",
        "packet_info",
        "http_request_body",
        "http_request_body_printable",
        "http_response_body",
        "http_response_body_printable",
        "stream",
        "rule",
    }
)
_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT
KEEP_OPEN = sys.platform != "win32"


class FileRefusedError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _strip(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        return None
    if isinstance(value, dict):
        return {k: _strip(v, depth + 1) for k, v in value.items() if k not in SURICATA_PAYLOAD_KEYS}
    if isinstance(value, list):
        return [_strip(v, depth + 1) for v in value]
    return value


def zeek_log_name(path: Path) -> str | None:
    """`conn.log`, `conn.2026-11-24-08-00-00.log` o `dns.log` → conn, dns. None si no es
    reconocible (el servidor inferirá el tipo por los campos)."""
    name = path.name.split(".", 1)[0]
    return name if name.isalnum() and len(name) <= 16 else None


def sanitize(fmt: str, line: str, path: Path) -> str | None:
    """Línea → registro reenviable, o None si no es un objeto JSON (se cuenta malformado)."""
    try:
        value = json.loads(line)
    except ValueError:
        return None
    if not isinstance(value, dict):
        return None
    if fmt == "suricata_eve":
        value = _strip(value)
    elif fmt == "zeek_json" and "_path" not in value:
        # Zeek con LogAscii::use_json no escribe el tipo de log en cada línea: sale del
        # nombre del fichero (el servidor también sabe inferirlo por los campos).
        log = zeek_log_name(path)
        if log:
            value["_path"] = log
    else:
        # Wazuh y JSON Lines se reenvían tal cual (el servidor valida y acota).
        return line.rstrip("\r")
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def file_identity(st: os.stat_result) -> str:
    return hashlib.sha256(f"{st.st_dev}:{st.st_ino}".encode()).hexdigest()[:16]


def _saved_int(value: object) -> int:
    """Entero no negativo de siem-offsets.json; 0 si falta o está dañado."""
    if isinstance(value, bool) or not isinstance(value, int | str):
        return 0
    try:
        number = int(value)
    except ValueError:
        return 0
    return max(0, number)


def _is_link(st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode):
        return True
    attributes = getattr(st, "st_file_attributes", 0)
    return bool(attributes & _REPARSE_POINT)


def _inside(path: Path, base: Path) -> bool:
    try:
        return Path(os.path.realpath(path)).is_relative_to(Path(os.path.realpath(base)))
    except (OSError, ValueError):
        return False


@dataclass
class _Open:
    identity: str
    handle: Any
    offset: int
    # Huella de los primeros `head_len` bytes (head_len <= HEAD_BYTES y <= offset).
    head_len: int = 0
    head_sha: str = ""


def _head(handle: Any, length: int) -> str:
    """SHA-256 (abreviado) de los primeros `length` bytes; "" si el fichero ya no los tiene."""
    if length <= 0:
        return ""
    handle.seek(0)
    data = handle.read(length)
    if len(data) != length:
        return ""
    return hashlib.sha256(data).hexdigest()[:32]


class FileTailer:
    """Una entrada `type = "file"`: un hilo que recorre sus ficheros cada `poll_interval_ms`."""

    def __init__(
        self,
        spec: FileInput,
        sink: Sink,
        commit: Commit,
        offsets_path: Path,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.spec = spec
        self._sink = sink
        self._commit = commit
        self._offsets_path = offsets_path
        self._clock = clock
        self.counters = InputCounters()
        self.limiter = RateLimiter(spec.max_records_per_second)
        self.state = "starting"
        self.error_code: str | None = None
        self.file_errors: dict[str, str] = {}
        self._open: dict[Path, _Open] = {}
        self._offsets: dict[str, dict[str, Any]] = self._load_offsets()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # --- offsets ---------------------------------------------------------------------

    def _key(self, path: Path) -> str:
        return f"{self.spec.name}|{path}"

    def _load_offsets(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self._offsets_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save_offsets(self) -> None:
        # Se relee y se fusiona: varias entradas comparten el fichero de offsets.
        current = self._load_offsets()
        mine = {k: v for k, v in self._offsets.items() if k.startswith(f"{self.spec.name}|")}
        current = {k: v for k, v in current.items() if not k.startswith(f"{self.spec.name}|")}
        current.update(mine)
        try:
            atomic_write_json(self._offsets_path, current)
        except OSError as exc:
            logger.warning(
                "siem offsets could not be saved",
                extra={"input": self.spec.name, "error": str(exc)},
            )

    # --- ciclo de vida ---------------------------------------------------------------

    def start(self) -> None:
        self.state = "running"
        self._thread = threading.Thread(
            target=self._run, name=f"siem-file-{self.spec.name}", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        for item in self._open.values():
            with contextlib.suppress(OSError):
                item.handle.close()
        self._open = {}
        if self.state != "error":
            self.state = "stopped"

    def _run(self) -> None:
        interval = self.spec.poll_interval_ms / 1000
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                logger.exception("siem file input failed", extra={"input": self.spec.name})
            self._stop.wait(interval)

    # --- lectura ---------------------------------------------------------------------

    def poll_once(self) -> int:
        """Una pasada por todos los ficheros. Devuelve las líneas reenviadas."""
        sent = 0
        for path in self.spec.paths:
            if self._stop.is_set():
                break
            try:
                sent += self._poll_file(path)
                self.file_errors.pop(str(path), None)
            except FileRefusedError as exc:
                self.file_errors[str(path)] = exc.code
            except FileNotFoundError:
                self.file_errors[str(path)] = "file_missing"
            except OSError:
                self.file_errors[str(path)] = "file_unreadable"
        if sent:
            # Primero el lote al spool, después el offset (entrega al menos una vez).
            self._commit(self.spec.name)
            self._save_offsets()
        refused = [c for c in self.file_errors.values() if c != "file_missing"]
        if len(self.file_errors) == len(self.spec.paths) and refused:
            self.state, self.error_code = "error", refused[0]
        elif self.state == "error":
            self.state, self.error_code = "running", None
        return sent

    def _check(self, path: Path) -> os.stat_result:
        st = os.lstat(path)
        if _is_link(st):
            raise FileRefusedError("symlink_refused")
        if not stat.S_ISREG(st.st_mode):
            raise FileRefusedError("not_a_regular_file")
        if not _inside(path, self.spec.allowed_dir):
            raise FileRefusedError("path_outside_allowed_dir")
        return st

    def _open_checked(self, path: Path, st: os.stat_result) -> Any:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags)
        handle = os.fdopen(fd, "rb")
        try:
            opened = os.fstat(handle.fileno())
            # Carrera entre la comprobación y la apertura: si no es el mismo fichero, fuera.
            if sys.platform != "win32" and (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                raise FileRefusedError("file_changed_while_opening")
        except BaseException:
            handle.close()
            raise
        return handle

    def _open_file(self, path: Path, st: os.stat_result) -> _Open:
        handle = self._open_checked(path, st)
        identity = file_identity(st)
        saved = self._offsets.get(self._key(path))
        if not saved:
            offset = st.st_size if self.spec.start_at == "end" else 0
            return _Open(identity, handle, offset)
        if saved.get("identity") != identity:
            # Otro fichero en la misma ruta (rotó con el descriptor cerrado: sensor parado o
            # Windows, que cierra en cada pasada): desde el principio.
            self.counters.add(rotations=1)
            return _Open(identity, handle, 0)
        offset = _saved_int(saved.get("offset"))
        if offset > st.st_size:
            # El mismo fichero, más corto que lo ya leído: truncado (también en Windows, donde
            # no hay descriptor abierto entre pasadas para notarlo de otra forma).
            self.counters.add(truncations=1)
            return _Open(identity, handle, 0)
        head_len = min(_saved_int(saved.get("head_len")), HEAD_BYTES, offset)
        head_sha = saved.get("head_sha") if head_len else ""
        if not isinstance(head_sha, str):
            head_len, head_sha = 0, ""
        return _Open(identity, handle, offset, head_len, head_sha)

    def _poll_file(self, path: Path) -> int:
        st = self._check(path)
        if KEEP_OPEN:
            # Con descriptor abierto la rotación se termina por ese descriptor (_poll_open);
            # sin él (primera pasada tras reiniciar) se busca el fichero rotado como en Windows.
            sent = 0 if path in self._open else self._recover_rotated(path, st)
            return sent + self._poll_open(path, st)
        # Windows: el handle solo vive durante la pasada y se cierra SIEMPRE, también si la
        # lectura falla. Un handle olvidado tras un error impediría al escritor renombrar el
        # fichero al rotar (WinError 32) hasta que el sensor se reiniciara.
        sent = self._recover_rotated(path, st)
        try:
            return sent + self._poll_open(path, st)
        finally:
            leftover = self._open.pop(path, None)
            if leftover is not None:
                with contextlib.suppress(OSError):
                    leftover.handle.close()

    def _poll_open(self, path: Path, st: os.stat_result) -> int:
        identity = file_identity(st)
        current = self._open.get(path)
        sent = 0
        if current is not None and current.identity != identity:
            # Rotación: se termina el fichero anterior por su descriptor y se pasa al nuevo.
            sent += self._drain(path, current, to_eof=True)
            current.handle.close()
            del self._open[path]
            self.counters.add(rotations=1)
            current = None
            self._offsets[self._key(path)] = {"identity": identity, "offset": 0}
        if current is None:
            current = self._open_file(path, st)
            self._open[path] = current
        if st.st_size < current.offset:
            self.counters.add(truncations=1)
            current.offset, current.head_len, current.head_sha = 0, 0, ""
        elif current.head_len and _head(current.handle, current.head_len) != current.head_sha:
            # Mismo fichero y tamaño suficiente, pero el principio ya no es el que se leyó:
            # se ha reescrito en el sitio. Se relee desde el principio.
            self.counters.add(truncations=1)
            current.offset, current.head_len, current.head_sha = 0, 0, ""
        sent += self._drain(path, current, to_eof=False)
        want = min(HEAD_BYTES, current.offset)
        if want != current.head_len:
            current.head_len, current.head_sha = want, _head(current.handle, want)
        self._offsets[self._key(path)] = {
            "identity": current.identity,
            "offset": current.offset,
            "head_len": current.head_len,
            "head_sha": current.head_sha,
        }
        # Sin KEEP_OPEN (Windows) el handle lo cierra _poll_file al terminar la pasada: un
        # fichero abierto impide que el escritor lo renombre al rotar.
        return sent

    def _recover_rotated(self, path: Path, st: os.stat_result) -> int:
        """Modo de reapertura (Windows, o cualquier plataforma tras un reinicio sin
        descriptor): si en la ruta hay OTRO fichero que el guardado, busca el anterior entre
        sus hermanos renombrados (`eve.json.1`, `eve.json-20261126`...) por su identidad y lee
        lo que quedaba pendiente desde el offset guardado. Así no se pierden las líneas
        escritas entre la última pasada y la rotación mientras el fichero rotado siga en el
        mismo directorio.

        Acotado y conservador: solo nombres que empiezan por el nombre original, como mucho
        ROTATED_SCAN_LIMIT entradas, ficheros regulares sin enlaces dentro de allowed_dir, con
        la misma identidad y la misma huella de los primeros bytes. Si no se encuentra (se
        comprimió, se movió a otro directorio o se borró), se sigue como antes: el nuevo se lee
        desde el principio y lo pendiente del anterior se pierde.
        """
        saved = self._offsets.get(self._key(path))
        if not saved or saved.get("identity") == file_identity(st):
            return 0
        offset = _saved_int(saved.get("offset"))
        head_len = min(_saved_int(saved.get("head_len")), HEAD_BYTES, offset)
        head_sha = saved.get("head_sha") if head_len else ""
        if not isinstance(head_sha, str):
            return 0
        rotated = self._find_rotated(path, str(saved.get("identity")))
        if rotated is None:
            return 0
        old_path, old_st = rotated
        if old_st.st_size <= offset:
            return 0  # nada pendiente
        try:
            item = _Open(file_identity(old_st), self._open_checked(old_path, old_st), offset)
        except (OSError, FileRefusedError):
            return 0
        try:
            if head_len and _head(item.handle, head_len) != head_sha:
                return 0  # misma identidad pero otro contenido: no se arriesga una lectura
            # Se emite con la ruta declarada: es la continuación del mismo flujo de logs.
            return self._drain(path, item, to_eof=True)
        finally:
            with contextlib.suppress(OSError):
                item.handle.close()

    def _find_rotated(self, path: Path, identity: str) -> tuple[Path, os.stat_result] | None:
        prefix = path.name
        try:
            with os.scandir(path.parent) as entries:
                for index, entry in enumerate(entries):
                    if index >= ROTATED_SCAN_LIMIT:
                        return None
                    if entry.name == prefix or not entry.name.startswith(prefix):
                        continue
                    candidate = path.parent / entry.name
                    try:
                        st = self._check(candidate)
                    except (OSError, FileRefusedError):
                        continue
                    if file_identity(st) == identity:
                        return candidate, st
        except OSError:
            return None
        return None

    def _drain(self, path: Path, item: _Open, to_eof: bool) -> int:
        sent = 0
        limit = self.spec.max_line_bytes
        begin = item.offset
        while (sent < MAX_LINES_PER_CYCLE and item.offset - begin < MAX_BYTES_PER_CYCLE) or to_eof:
            item.handle.seek(item.offset)
            data = item.handle.read(READ_CHUNK)
            if not data:
                break
            newline = data.find(b"\n")
            if newline < 0:
                if len(data) > limit:
                    # Línea gigante sin fin todavía: se salta hasta el siguiente LF.
                    self._skip_line(item)
                    continue
                break  # línea a medio escribir: en la siguiente pasada
            consumed = 0
            while newline >= 0:
                line = data[consumed:newline]
                start = item.offset + consumed
                consumed = newline + 1
                if len(line) > limit:
                    self.counters.add(dropped_oversize=1)
                elif line.strip():
                    if not self.limiter.take():
                        # Sin ficha: se para aquí (contrapresión); la línea se relee luego.
                        item.offset = start
                        return sent
                    if self._emit(path, item, line, start):
                        sent += 1
                newline = data.find(b"\n", consumed)
                if sent >= MAX_LINES_PER_CYCLE and not to_eof:
                    break
            item.offset += consumed
            if len(data) - consumed > limit and data.find(b"\n", consumed) < 0:
                self._skip_line(item)
        return sent

    def _skip_line(self, item: _Open) -> None:
        self.counters.add(dropped_oversize=1)
        while True:
            item.handle.seek(item.offset)
            data = item.handle.read(READ_CHUNK)
            if not data:
                return
            newline = data.find(b"\n")
            if newline >= 0:
                item.offset += newline + 1
                return
            item.offset += len(data)

    def _emit(self, path: Path, item: _Open, line: bytes, offset: int) -> bool:
        text = line.decode("utf-8", errors="replace").replace("\x00", "�")
        record = sanitize(self.spec.format, text, path)
        if record is None:
            self.counters.add(malformed=1)
            return False
        now = self._clock()
        self.counters.add(received=1)
        with self.counters.lock:
            self.counters.last_record_at = now
        self._sink(
            self.spec.name,
            {
                "raw": record,
                "record_id": f"{item.identity}:{offset}",
                "collected_at": datetime.fromtimestamp(now, UTC).isoformat(),
                "transport": "file",
                "file_id": item.identity,
                "offset": offset,
            },
        )
        return True

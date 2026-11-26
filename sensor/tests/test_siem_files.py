"""Lector incremental de ficheros SIEM (Fase 7F.3): rutas permitidas, offsets, rotación,
truncado, límites, saneado por formato e integración con el gestor.

Los registros son SINTÉTICOS (estructura documentada de EVE JSON y de los logs JSON de Zeek);
no validan un Suricata ni un Zeek reales.
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from sentra_sensor.config import ConfigError
from sentra_sensor.siem import files
from sentra_sensor.siem.config import (
    FileInput,
    SiemConfigError,
    SiemServerConfig,
    SyslogInput,
    parse_local_siem,
)
from sentra_sensor.siem.files import FileTailer, sanitize, zeek_log_name
from sentra_sensor.siem.manager import SiemManager

SOURCE = "5f000000-0000-4000-8000-0000000000c3"


def file_input(base: Path, **overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "name": "ids",
        "type": "file",
        "format": "suricata_eve",
        "allowed_dir": str(base),
        "paths": ["eve.json"],
        "start_at": "beginning",
    }
    value.update(overrides)
    return value


def spec(base: Path, **overrides: Any) -> FileInput:
    parsed = parse_local_siem({"inputs": [file_input(base, **overrides)]}).inputs[0]
    assert isinstance(parsed, FileInput)
    return parsed


class Sink:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self.commits = 0

    def __call__(self, name: str, record: dict[str, Any]) -> None:
        self.records.append(record)

    def commit(self, name: str) -> None:
        self.commits += 1

    def raws(self) -> list[dict[str, Any]]:
        return [json.loads(r["raw"]) for r in self.records]


def tailer(base: Path, sink: Sink, **overrides: Any) -> FileTailer:
    return FileTailer(spec(base, **overrides), sink, sink.commit, base.parent / "offsets.json")


def write(path: Path, *lines: str | dict[str, Any], mode: str = "a") -> None:
    with path.open(mode, encoding="utf-8", newline="\n") as handle:
        for line in lines:
            handle.write((line if isinstance(line, str) else json.dumps(line)) + "\n")


@pytest.fixture
def base(tmp_path: Path) -> Path:
    directory = tmp_path / "logs"
    directory.mkdir()
    return directory


# --- configuración -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"paths": ["../secret.json"]}, r"'\.\.'"),
        ({"paths": ["/etc/shadow"]}, "inside allowed_dir"),
        ({"paths": []}, "1 to"),
        ({"allowed_dir": "relative/dir"}, "absolute"),
        ({"format": "pcap"}, "format"),
        ({"start_at": "middle"}, "start_at"),
        ({"max_line_bytes": 10}, "max_line_bytes"),
        ({"command": "tail -f"}, "unknown keys"),
    ],
)
def test_invalid_file_inputs(base: Path, overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(SiemConfigError, match=message):
        parse_local_siem({"inputs": [file_input(base, **overrides)]})


def test_same_file_cannot_feed_two_inputs(base: Path) -> None:
    with pytest.raises(SiemConfigError, match="already read"):
        parse_local_siem({"inputs": [file_input(base), file_input(base, name="other")]})


# --- lectura ---------------------------------------------------------------------------------


def test_start_at_end_skips_history_then_reads_new_lines(base: Path) -> None:
    eve = base / "eve.json"
    write(eve, {"event_type": "flow", "n": 1})
    sink = Sink()
    reader = tailer(base, sink, start_at="end")
    assert reader.poll_once() == 0
    write(eve, {"event_type": "flow", "n": 2})
    assert reader.poll_once() == 1
    assert sink.raws() == [{"event_type": "flow", "n": 2}] and sink.commits == 1
    record = sink.records[0]
    assert record["transport"] == "file" and record["record_id"].endswith(f":{record['offset']}")
    reader.stop()


def test_offsets_survive_restart(base: Path) -> None:
    eve = base / "eve.json"
    write(eve, {"n": 1}, {"n": 2})
    first = Sink()
    reader = tailer(base, first)
    assert reader.poll_once() == 2
    reader.stop()
    write(eve, {"n": 3})
    second = Sink()
    again = tailer(base, second)
    assert again.poll_once() == 1 and second.raws() == [{"n": 3}]
    again.stop()


def test_partial_line_waits_for_newline(base: Path) -> None:
    eve = base / "eve.json"
    eve.write_text('{"n": 1}\n{"n": ', encoding="utf-8")
    sink = Sink()
    reader = tailer(base, sink)
    assert reader.poll_once() == 1
    with eve.open("a", encoding="utf-8") as handle:
        handle.write("2}\n")
    assert reader.poll_once() == 1 and sink.raws()[-1] == {"n": 2}
    reader.stop()


def test_oversize_and_malformed_lines_are_counted(base: Path) -> None:
    eve = base / "eve.json"
    write(eve, json.dumps({"big": "x" * 5000}), "no json", "[1]", {"n": 4})
    sink = Sink()
    reader = tailer(base, sink, max_line_bytes=1024)
    assert reader.poll_once() == 1 and sink.raws() == [{"n": 4}]
    snapshot = reader.counters.snapshot()
    assert snapshot["dropped_oversize"] == 1 and snapshot["malformed"] == 2
    reader.stop()


def test_giant_line_without_newline_is_bounded(base: Path) -> None:
    eve = base / "eve.json"
    eve.write_text("y" * (files.READ_CHUNK + 10), encoding="utf-8")
    sink = Sink()
    reader = tailer(base, sink, max_line_bytes=1024)
    assert reader.poll_once() == 0
    write(eve, "", {"n": 1})
    assert reader.poll_once() == 1 and sink.raws() == [{"n": 1}]
    reader.stop()


# Modo de apertura: True = descriptor abierto entre pasadas (Linux, macOS); False = se cierra
# en cada pasada (Windows, files.KEEP_OPEN). Los dos se prueban en cualquier plataforma: el
# modo False reproduce en Linux el fallo visto en Windows 11 (truncado contado como rotación).
# La confirmación en un Windows físico (NTFS, índice de fichero) queda pendiente.
OPEN_MODES = [pytest.param(True, id="keep_open"), pytest.param(False, id="reopen_each_poll")]


@pytest.fixture(params=OPEN_MODES)
def keep_open(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> bool:
    value = bool(request.param)
    monkeypatch.setattr(files, "KEEP_OPEN", value)
    return value


def test_truncation_restarts_from_the_beginning(base: Path, keep_open: bool) -> None:
    eve = base / "eve.json"
    write(eve, {"n": 1}, {"n": 2})
    sink = Sink()
    reader = tailer(base, sink)
    reader.poll_once()
    write(eve, {"n": 3}, mode="w")
    assert reader.poll_once() == 1 and sink.raws()[-1] == {"n": 3}
    counters = reader.counters.snapshot()
    assert counters["truncations"] == 1 and counters["rotations"] == 0
    reader.stop()


def test_overwrite_in_place_with_more_data_restarts(base: Path, keep_open: bool) -> None:
    """Sobrescrito (misma identidad, tamaño >= offset, otro contenido): sin la huella de los
    primeros bytes se seguiría leyendo desde la mitad de un contenido distinto."""
    eve = base / "eve.json"
    write(eve, {"n": 1}, {"n": 2})
    sink = Sink()
    reader = tailer(base, sink)
    assert reader.poll_once() == 2
    write(eve, {"m": "nuevo-1"}, {"m": "nuevo-2"}, {"m": "nuevo-3"}, mode="w")
    assert reader.poll_once() == 3
    assert sink.raws()[2:] == [{"m": "nuevo-1"}, {"m": "nuevo-2"}, {"m": "nuevo-3"}]
    counters = reader.counters.snapshot()
    assert counters["truncations"] == 1 and counters["rotations"] == 0
    reader.stop()


def test_unchanged_and_appended_files_continue(base: Path, keep_open: bool) -> None:
    """Sin cambios: nada que leer ni contadores; con líneas añadidas: solo las nuevas."""
    eve = base / "eve.json"
    write(eve, {"n": 1})
    sink = Sink()
    reader = tailer(base, sink)
    assert reader.poll_once() == 1
    for _ in range(3):
        assert reader.poll_once() == 0  # sin relecturas
    write(eve, {"n": 2}, {"n": 3})
    assert reader.poll_once() == 2 and [r["n"] for r in sink.raws()] == [1, 2, 3]
    counters = reader.counters.snapshot()
    assert counters["truncations"] == 0 and counters["rotations"] == 0
    reader.stop()


# Modos en los que la PLATAFORMA permite renombrar el fichero mientras el lector trabaja. En
# Windows, un handle abierto con os.open (sin FILE_SHARE_DELETE) impide renombrarlo
# (WinError 32): por eso el lector de Windows usa siempre el modo de reapertura y nunca deja
# un handle abierto entre pasadas. El modo keep_open solo existe en Linux y macOS, así que en
# Windows estas pruebas de rotación se ejecutan solo en el modo que Windows usa de verdad.
ROTATION_MODES = (
    [pytest.param(False, id="reopen_each_poll")] if sys.platform == "win32" else OPEN_MODES
)


@pytest.fixture(params=ROTATION_MODES)
def rotation_mode(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> bool:
    value = bool(request.param)
    monkeypatch.setattr(files, "KEEP_OPEN", value)
    return value


def test_rotation_is_not_counted_as_truncation(base: Path, rotation_mode: bool) -> None:
    """Otro fichero en la misma ruta: rotación, se lee el nuevo desde el principio."""
    eve = base / "eve.json"
    write(eve, {"n": 1})
    sink = Sink()
    reader = tailer(base, sink)
    reader.poll_once()
    eve.rename(base / "eve.json.1")
    write(eve, {"n": 2}, {"n": 3, "pad": "z" * 50})
    assert reader.poll_once() == 2 and [r["n"] for r in sink.raws()] == [1, 2, 3]
    counters = reader.counters.snapshot()
    assert counters["rotations"] == 1 and counters["truncations"] == 0
    reader.stop()


def test_rotation_with_pending_lines_recovers_them(base: Path, rotation_mode: bool) -> None:
    """Líneas escritas después de la última pasada y antes de rotar: con descriptor abierto
    se terminan por él (POSIX); en modo reapertura (Windows) se encuentra el fichero rotado
    por su identidad y se lee lo pendiente. Ni duplicados ni pérdidas."""
    eve = base / "eve.json"
    write(eve, {"n": 1})
    sink = Sink()
    reader = tailer(base, sink)
    assert reader.poll_once() == 1
    if not rotation_mode:
        assert reader._open == {}  # ningún handle entre pasadas: se puede renombrar
    write(eve, {"n": 2}, {"n": 3})  # pendiente, sin leer
    eve.rename(base / "eve.json.1")
    write(eve, {"n": 4})
    assert reader.poll_once() == 3
    assert [r["n"] for r in sink.raws()] == [1, 2, 3, 4]
    counters = reader.counters.snapshot()
    assert counters["rotations"] == 1 and counters["truncations"] == 0
    assert reader.poll_once() == 0  # sin relecturas
    reader.stop()


def test_restart_after_rotation_recovers_pending_lines(base: Path, keep_open: bool) -> None:
    """Sensor parado durante la rotación: al arrancar se lee lo pendiente del rotado y el
    nuevo desde el principio; el offset persistido queda en el nuevo fichero."""
    eve = base / "eve.json"
    write(eve, {"n": 1})
    reader = tailer(base, Sink())
    reader.poll_once()
    reader.stop()
    write(eve, {"n": 2})
    eve.rename(base / "eve.json.1")
    write(eve, {"n": 3})
    sink = Sink()
    again = tailer(base, sink)
    assert again.poll_once() == 2 and [r["n"] for r in sink.raws()] == [2, 3]
    assert again.counters.snapshot()["rotations"] == 1
    again.stop()
    saved = json.loads((base.parent / "offsets.json").read_text(encoding="utf-8"))
    [entry] = saved.values()
    assert entry["identity"] == files.file_identity(os.stat(eve))
    assert entry["offset"] == eve.stat().st_size
    third = tailer(base, Sink())
    assert third.poll_once() == 0  # el reinicio siguiente no repite nada
    third.stop()


def test_rotated_file_moved_away_loses_only_its_pending_lines(
    base: Path, rotation_mode: bool, tmp_path: Path
) -> None:
    """Si el rotado ya no está en el directorio (comprimido, archivado), lo pendiente de
    él no se puede recuperar: el nuevo se lee entero y no hay errores ni bucles."""
    eve = base / "eve.json"
    write(eve, {"n": 1})
    sink = Sink()
    reader = tailer(base, sink)
    reader.poll_once()
    reader.stop()  # suelta el descriptor para poder mover el fichero en cualquier sistema
    reader = tailer(base, sink)
    write(eve, {"n": 2})
    eve.rename(tmp_path / "archivado.json")
    write(eve, {"n": 3})
    assert reader.poll_once() == 1 and [r["n"] for r in sink.raws()] == [1, 3]
    assert reader.counters.snapshot()["rotations"] == 1
    reader.stop()


def test_rotated_sibling_needs_same_identity_and_fingerprint(base: Path, tmp_path: Path) -> None:
    """Un hermano con nombre parecido pero otra identidad no se lee: solo el fichero que se
    estaba leyendo (misma identidad y huella)."""
    eve = base / "eve.json"
    write(eve, {"n": 1})
    reader = tailer(base, Sink())
    reader.poll_once()
    reader.stop()
    write(eve, {"pendiente": True})
    eve.rename(tmp_path / "fuera.json")  # el rotado de verdad sale del directorio
    write(base / "eve.json.bak", {"intruso": True}, {"intruso": True})
    write(eve, {"n": 2})
    sink = Sink()
    again = tailer(base, sink)
    assert again.poll_once() == 1 and sink.raws() == [{"n": 2}]
    again.stop()


def test_reopen_mode_releases_the_handle_even_when_reading_fails(
    base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Modo Windows: si la lectura falla a mitad, el handle se cierra igual (antes quedaba
    abierto e impedía la rotación) y la siguiente pasada continúa sin perder líneas."""
    monkeypatch.setattr(files, "KEEP_OPEN", False)
    eve = base / "eve.json"
    write(eve, {"n": 1})
    sink = Sink()
    reader = tailer(base, sink)
    assert reader.poll_once() == 1
    write(eve, {"n": 2})
    real_drain = reader._drain

    def failing(path: Path, item: Any, to_eof: bool) -> int:
        raise OSError(5, "I/O error")

    monkeypatch.setattr(reader, "_drain", failing)
    assert reader.poll_once() == 0
    assert reader.file_errors == {str(eve): "file_unreadable"} and reader._open == {}
    eve.rename(base / "eve.json.1")  # nada lo bloquea
    write(eve, {"n": 3})
    monkeypatch.setattr(reader, "_drain", real_drain)
    assert reader.poll_once() == 2 and [r["n"] for r in sink.raws()] == [1, 2, 3]
    assert reader.file_errors == {} and reader._open == {}
    counters = reader.counters.snapshot()
    assert counters["rotations"] == 1 and counters["truncations"] == 0
    reader.stop()


def test_truncation_while_stopped_is_a_truncation_not_a_rotation(base: Path) -> None:
    eve = base / "eve.json"
    write(eve, {"n": 1}, {"n": 2})
    reader = tailer(base, Sink())
    reader.poll_once()
    reader.stop()
    write(eve, {"n": 3}, mode="w")
    sink = Sink()
    again = tailer(base, sink)
    assert again.poll_once() == 1 and sink.raws() == [{"n": 3}]
    counters = again.counters.snapshot()
    assert counters["truncations"] == 1 and counters["rotations"] == 0
    again.stop()


def test_overwrite_while_stopped_restarts_and_restart_does_not_duplicate(base: Path) -> None:
    eve = base / "eve.json"
    write(eve, {"n": 1})
    reader = tailer(base, Sink())
    reader.poll_once()
    reader.stop()
    write(eve, {"m": "otro contenido"}, {"m": "y mas"}, mode="w")
    sink = Sink()
    again = tailer(base, sink)
    assert again.poll_once() == 2 and again.counters.snapshot()["truncations"] == 1
    again.stop()
    # Otro reinicio sin cambios: el offset y la huella guardados evitan releer.
    third = tailer(base, Sink())
    assert third.poll_once() == 0 and third.counters.snapshot()["truncations"] == 0
    third.stop()


def test_offsets_without_fingerprint_are_still_honoured(base: Path) -> None:
    """siem-offsets.json de 7F (sin huella) sigue valiendo: se continúa desde el offset."""
    eve = base / "eve.json"
    write(eve, {"n": 1}, {"n": 2})
    reader = tailer(base, Sink())
    reader.poll_once()
    reader.stop()
    offsets_path = base.parent / "offsets.json"
    data = json.loads(offsets_path.read_text(encoding="utf-8"))
    for value in data.values():
        value.pop("head_len"), value.pop("head_sha")
    offsets_path.write_text(json.dumps(data), encoding="utf-8")
    write(eve, {"n": 3})
    sink = Sink()
    again = tailer(base, sink)
    assert again.poll_once() == 1 and sink.raws() == [{"n": 3}]
    again.stop()


@pytest.mark.parametrize("bad", ["x", -5, None, [1], True])
def test_damaged_offsets_are_read_conservatively(base: Path, bad: object) -> None:
    eve = base / "eve.json"
    write(eve, {"n": 1}, {"n": 2})
    reader = tailer(base, Sink())
    reader.poll_once()
    reader.stop()
    offsets_path = base.parent / "offsets.json"
    data = json.loads(offsets_path.read_text(encoding="utf-8"))
    for value in data.values():
        value["offset"], value["head_len"] = bad, bad
    offsets_path.write_text(json.dumps(data), encoding="utf-8")
    sink = Sink()
    again = tailer(base, sink)
    # Offset dañado = 0: se relee (al menos una vez; el servidor deduplica), sin excepción.
    assert again.poll_once() == 2 and [r["n"] for r in sink.raws()] == [1, 2]
    again.stop()


def test_temporarily_unreadable_file_keeps_its_offset(
    base: Path, keep_open: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inaccesible un momento (en Windows, bloqueo de compartición del escritor): se anota
    el código, el offset no se toca y después se sigue sin perder ni repetir líneas."""
    eve = base / "eve.json"
    write(eve, {"n": 1})
    sink = Sink()
    reader = tailer(base, sink)
    assert reader.poll_once() == 1
    reader.stop()  # el modo keep_open reabre: así la apertura pasa por os.open
    reader = tailer(base, sink)
    write(eve, {"n": 2})
    real_open = os.open

    def locked(path: Any, flags: int, *args: Any) -> int:
        if Path(path) == eve:
            raise PermissionError(13, "The process cannot access the file")
        return real_open(path, flags, *args)

    monkeypatch.setattr(os, "open", locked)
    assert reader.poll_once() == 0
    assert reader.file_errors == {str(eve): "file_unreadable"}
    monkeypatch.setattr(os, "open", real_open)
    assert reader.poll_once() == 1 and [r["n"] for r in sink.raws()] == [1, 2]
    assert reader.file_errors == {}
    counters = reader.counters.snapshot()
    assert counters["truncations"] == 0 and counters["rotations"] == 0
    reader.stop()


@pytest.mark.skipif(sys.platform == "win32", reason="Windows cierra el fichero en cada pasada")
def test_rotation_drains_old_file_then_reads_new(base: Path) -> None:
    eve = base / "eve.json"
    write(eve, {"n": 1})
    sink = Sink()
    reader = tailer(base, sink)
    reader.poll_once()
    write(eve, {"n": 2})  # escrito antes de rotar y aún sin leer
    eve.rename(base / "eve.json.1")
    write(eve, {"n": 3})
    assert reader.poll_once() == 2
    assert [r["n"] for r in sink.raws()] == [1, 2, 3]
    assert reader.counters.snapshot()["rotations"] == 1
    reader.stop()


def test_rotation_while_stopped_reads_new_file_from_start(base: Path) -> None:
    eve = base / "eve.json"
    write(eve, {"n": 1})
    reader = tailer(base, Sink())
    reader.poll_once()
    reader.stop()
    eve.rename(base / "eve.json.1")
    write(eve, {"n": 2})
    sink = Sink()
    again = tailer(base, sink)
    assert again.poll_once() == 1 and sink.raws() == [{"n": 2}]
    again.stop()


def test_missing_file_is_reported_not_fatal(base: Path) -> None:
    reader = tailer(base, Sink())
    assert reader.poll_once() == 0
    assert reader.file_errors == {str(base / "eve.json"): "file_missing"}
    assert reader.state != "error"


def _symlink_or_skip(link: Path, target: Path, directory: bool = False) -> None:
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"no se pueden crear enlaces simbólicos aquí ({exc})")


def test_symlinked_file_is_refused(base: Path, tmp_path: Path) -> None:
    secret = tmp_path / "secret.json"
    write(secret, {"password": "x"})
    _symlink_or_skip(base / "eve.json", secret)
    sink = Sink()
    reader = tailer(base, sink)
    assert reader.poll_once() == 0 and sink.records == []
    assert reader.state == "error" and reader.error_code == "symlink_refused"


def test_directory_link_cannot_escape_allowed_dir(base: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    write(outside / "eve.json", {"secret": True})
    _symlink_or_skip(base / "sub", outside, directory=True)
    sink = Sink()
    reader = tailer(base, sink, paths=["sub/eve.json"])
    assert reader.poll_once() == 0 and sink.records == []
    assert reader.error_code == "path_outside_allowed_dir"


def test_rate_limit_applies_backpressure(base: Path) -> None:
    eve = base / "eve.json"
    write(eve, {"n": 1}, {"n": 2}, {"n": 3})
    sink = Sink()
    reader = tailer(base, sink, max_records_per_second=1)
    assert reader.poll_once() == 1
    # Las líneas no leídas quedan para después (nada se descarta).
    reader.limiter.rate = reader.limiter._tokens = 100
    assert reader.poll_once() == 2 and [r["n"] for r in sink.raws()] == [1, 2, 3]
    reader.stop()


# --- saneado ---------------------------------------------------------------------------------


def test_suricata_payloads_are_removed_before_leaving_the_host() -> None:
    line = json.dumps(
        {
            "event_type": "alert",
            "payload": "QUJD",
            "payload_printable": "ABC",
            "packet": "00",
            "http": {"http_request_body": "secreto", "hostname": "x"},
            "alert": {"signature_id": 1, "rule": "alert tcp any any -> any any (...)"},
        }
    )
    clean = sanitize("suricata_eve", line, Path("eve.json"))
    assert clean is not None
    for secret in ("QUJD", "ABC", "secreto", "alert tcp"):
        assert secret not in clean
    assert json.loads(clean)["http"]["hostname"] == "x"


def test_zeek_log_type_comes_from_file_name() -> None:
    clean = sanitize(
        "zeek_json", json.dumps({"uid": "C1"}), Path("/z/conn.2026-11-24-08-00-00.log")
    )
    assert clean is not None and json.loads(clean)["_path"] == "conn"
    kept = sanitize("zeek_json", json.dumps({"_path": "dns"}), Path("/z/conn.log"))
    assert kept is not None and json.loads(kept)["_path"] == "dns"
    assert zeek_log_name(Path("weird name.log")) is None


def test_wazuh_and_json_lines_pass_through() -> None:
    line = '{"rule": {"id": "5710"}, "full_log": "texto"}'
    assert sanitize("wazuh_alerts", line, Path("alerts.json")) == line
    assert sanitize("json_lines", "not json", Path("x.json")) is None


# --- gestor ----------------------------------------------------------------------------------


def test_manager_runs_file_input_and_commits_before_offsets(base: Path, tmp_path: Path) -> None:
    eve = base / "eve.json"
    write(eve, {"event_type": "alert", "n": 1}, {"event_type": "alert", "n": 2})
    local = parse_local_siem({"enabled": True, "inputs": [file_input(base)]})
    batches: list[dict[str, Any]] = []
    offsets = tmp_path / "siem-offsets.json"

    def enqueue(name: str, batch: dict[str, Any]) -> None:
        # El offset aún no se ha guardado cuando el lote llega al spool.
        saved = json.loads(offsets.read_text()) if offsets.exists() else {}
        assert all(v["offset"] == 0 for v in saved.values()) or not saved
        batches.append(batch)

    class ManualTailer(FileTailer):
        # Sin hilo: el test llama a poll_once de forma determinista.
        def start(self) -> None:
            self.state = "running"

    def factory(item: Any, sink: Any) -> FileTailer:
        return ManualTailer(item, sink, manager.flush_input, offsets)

    manager = SiemManager(local, enqueue, receiver_factory=factory)
    server = SiemServerConfig.parse(
        {
            "enabled": True,
            "revision": 1,
            "sources": [
                {"source_id": SOURCE, "input": "ids", "source_type": "suricata_eve", "revision": 1}
            ],
        }
    )
    manager.apply(server)
    reader = manager.receivers["ids"]
    assert isinstance(reader, FileTailer)
    assert reader.poll_once() == 2
    assert len(batches) == 1 and len(batches[0]["records"]) == 2
    saved = json.loads(offsets.read_text())
    assert next(iter(saved.values()))["offset"] == eve.stat().st_size
    health = manager.health()
    assert health["inputs"][0]["name"] == "ids" and str(base) not in json.dumps(health)
    manager.stop()


def test_windows_mode_closes_each_pass_and_detects_rotation(
    base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Modo Windows (el fichero no se deja abierto para no bloquear la rotación del escritor).
    monkeypatch.setattr(files, "KEEP_OPEN", False)
    eve = base / "eve.json"
    write(eve, {"n": 1})
    sink = Sink()
    reader = tailer(base, sink)
    assert reader.poll_once() == 1 and reader._open == {}
    write(eve, {"n": 2})
    assert reader.poll_once() == 1
    eve.rename(base / "eve.json.1")
    write(eve, {"n": 3})
    assert reader.poll_once() == 1 and [r["n"] for r in sink.raws()] == [1, 2, 3]
    assert reader.counters.snapshot()["rotations"] == 1


def test_threaded_reader_delivers_through_manager(base: Path, tmp_path: Path) -> None:
    import time

    eve = base / "eve.json"
    write(eve, {"event_type": "flow", "n": 1})
    local = parse_local_siem({"enabled": True, "inputs": [file_input(base, poll_interval_ms=100)]})
    batches: list[dict[str, Any]] = []
    manager = SiemManager(
        local, lambda _n, b: batches.append(b), offsets_path=tmp_path / "offsets.json"
    )
    manager.apply(
        SiemServerConfig.parse(
            {
                "enabled": True,
                "revision": 1,
                "sources": [
                    {
                        "source_id": SOURCE,
                        "input": "ids",
                        "source_type": "suricata_eve",
                        "revision": 1,
                    }
                ],
            }
        )
    )
    deadline = time.monotonic() + 5
    while not batches and time.monotonic() < deadline:
        time.sleep(0.02)
    manager.stop()
    assert batches and batches[0]["records"][0]["file_id"]


def _example_siem_lines(windows: bool) -> list[str]:
    """Bloque [siem] de sensor.example.toml sin comentar. Las líneas `# clave = valor` son la
    variante Linux/macOS; las `## clave = valor` inmediatamente después, la de Windows."""
    example = Path(__file__).resolve().parents[1] / "sensor.example.toml"
    text = example.read_text(encoding="utf-8")
    block = text[text.index("# [siem]") :].splitlines()
    windows_values = {
        line[3:].split("=", 1)[0].strip(): line[3:]
        for line in block
        if line.startswith("## ") and re.match(r"^## [a-z_]+ = ", line)
    }
    lines = []
    for line in block:
        if line.startswith("# ") and ("=" in line or line.startswith("# [")):
            content = line[2:]
            key = content.split("=", 1)[0].strip()
            lines.append(windows_values.get(key, content) if windows else content)
    return lines


@pytest.mark.parametrize("windows", [False, True], ids=["linux_macos", "windows"])
def test_example_config_siem_block_parses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, windows: bool
) -> None:
    """El ejemplo es válido en las dos plataformas con sus propias rutas (la semántica de
    rutas de cada una se simula con `_windows`)."""
    from sentra_sensor.config import load_config
    from sentra_sensor.siem import config as siem_config

    monkeypatch.setattr(siem_config, "_windows", lambda: windows)
    lines = _example_siem_lines(windows)
    cfg = tmp_path / "sensor.toml"
    cfg.write_text(f'[sensor]\ndata_dir = "{tmp_path.as_posix()}/d"\n\n' + "\n".join(lines) + "\n")
    config = load_config(cfg, {})
    assert config.siem.enabled and [i.name for i in config.siem.inputs] == ["fw-syslog", "suricata"]
    syslog, suricata = config.siem.inputs
    assert isinstance(syslog, SyslogInput) and isinstance(suricata, FileInput)
    assert syslog.protocol == "tls" and syslog.tls_cert and syslog.tls_key
    expected = "C:/" if windows else "/etc/"
    assert str(syslog.tls_cert).replace("\\", "/").startswith(expected)
    assert str(suricata.allowed_dir).replace("\\", "/").startswith("C:/" if windows else "/var/")


@pytest.mark.parametrize("windows", [False, True])
def test_example_paths_of_the_other_platform_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, windows: bool
) -> None:
    """Las rutas Linux del ejemplo no valen en Windows y las de Windows no valen en Linux:
    el error es claro y no se intenta abrir nada."""
    from sentra_sensor.config import load_config
    from sentra_sensor.siem import config as siem_config

    monkeypatch.setattr(siem_config, "_windows", lambda: windows)
    lines = _example_siem_lines(not windows)
    cfg = tmp_path / "sensor.toml"
    cfg.write_text(f'[sensor]\ndata_dir = "{tmp_path.as_posix()}/d"\n\n' + "\n".join(lines) + "\n")
    with pytest.raises(ConfigError, match="tls_cert must be an absolute path"):
        load_config(cfg, {})

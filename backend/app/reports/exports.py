"""Exportaciones tabulares (CSV) y paquete de evidencia (ZIP) de un informe (Fase 5E).

CSV: solo tablas del snapshot con columnas fijas (templates.TABLE_COLUMNS). Contra la
inyección de fórmulas (CSV/formula injection) toda celda de TEXTO que empiece por = + - @,
tabulador o retorno de carro se prefija con un apóstrofo: Excel/LibreOffice la muestran como
texto en vez de ejecutarla. Los números se exportan como números (un -3 sigue siendo -3).

ZIP de evidencia: se construye en memoria con nombres FIJOS decididos aquí (manifest.json,
report.html, report.pdf, snapshot.json, tables/<tabla>.csv). Ninguna ruta viene del cliente
ni de los datos, no hay symlinks ni rutas absolutas, y el manifest lleva el SHA-256 y el
tamaño de cada fichero para verificar el paquete fuera de Sentra. Fechas internas fijas
(hora de corte) para que el ZIP sea reproducible.
"""

import csv
import hashlib
import io
import json
import zipfile
from datetime import datetime
from typing import Any

from app.reports.document import EMPTY, fmt
from app.reports.templates import TABLE_COLUMNS

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def neutralize(value: Any) -> Any:
    """Valor seguro para una celda CSV."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return value
    text = fmt(value) if isinstance(value, list | dict) else str(value)
    if text == EMPTY:
        return ""
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def render_csv(table_name: str, data: dict[str, Any] | None) -> bytes:
    columns = TABLE_COLUMNS[table_name]
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow([key for key, _ in columns])
    for row in (data or {}).get("rows") or []:
        writer.writerow([neutralize(row.get(key)) for key, _ in columns])
    # BOM UTF-8: Excel en Windows abre bien los acentos sin asistente de importación.
    return ("﻿" + buffer.getvalue()).encode("utf-8")


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_bundle(
    snapshot: dict[str, Any],
    html: bytes,
    pdf: bytes,
    tables: tuple[str, ...],
    stamp: datetime,
) -> bytes:
    files: list[tuple[str, bytes]] = [
        ("report.html", html),
        ("report.pdf", pdf),
        (
            "snapshot.json",
            json.dumps(snapshot, sort_keys=True, ensure_ascii=False, indent=1).encode("utf-8"),
        ),
    ]
    for name in tables:
        if name in TABLE_COLUMNS and name in (snapshot.get("tables") or {}):
            files.append((f"tables/{name}.csv", render_csv(name, snapshot["tables"][name])))
    meta = snapshot["meta"]
    manifest = {
        "format": "sentra-evidence-bundle/1",
        "report_id": meta["report_id"],
        "report_type": meta["report_type"],
        "template_version": meta["template_version"],
        "generated_at": meta["generated_at"],
        "cutoff_at": meta["cutoff_at"],
        "classification": meta["classification"],
        "snapshot_sha256": sha256(canonical_json(snapshot)),
        "files": [
            {"name": name, "sha256": sha256(content), "size_bytes": len(content)}
            for name, content in files
        ],
    }
    files.insert(
        0, ("manifest.json", json.dumps(manifest, indent=1, ensure_ascii=False).encode("utf-8"))
    )
    buffer = io.BytesIO()
    date_time = (
        max(stamp.year, 1980),
        stamp.month,
        stamp.day,
        stamp.hour,
        stamp.minute,
        stamp.second,
    )
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for name, content in files:
            info = zipfile.ZipInfo(name, date_time=date_time)
            info.compress_type = zipfile.ZIP_DEFLATED
            # Permisos fijos de fichero normal (0644): nada de symlinks ni ejecutables.
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, content)
    return buffer.getvalue()

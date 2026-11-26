"""Analizadores que se ejecutan en la transacción de cada lote SIEM aceptado (Fase 7F).

El orden importa: primero la atribución a activos (identity), después la correlación con la
evidencia propia de Sentra (NDR y otros eventos) y por último las señales al motor de
detección, que usan los dos anteriores. Si un analizador falla, el lote entero se revierte
y el sensor lo reintenta: no quedan eventos a medio analizar.
"""

from app.siem.correlation import correlation_analyzer
from app.siem.identity import attribution_analyzer
from app.siem.ingest import Analyzer
from app.siem.signals import signal_analyzer


def siem_analyzers() -> tuple[Analyzer, ...]:
    return (attribution_analyzer, correlation_analyzer, signal_analyzer)

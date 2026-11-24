"""Analizadores que se ejecutan sobre cada lote NDR ingerido, en su misma transacción.

7E.1 solo almacenaba. 7E.2 añade las reglas de capa 2 (ARP, puerta de enlace, DHCP) y DNS;
7E.3, las de protocolos y movimiento sobre los flujos del lote (escaneo, servicios en claro,
movimiento lateral); 7E.5, el cruce con Threat Intelligence y
las señales DNS para reglas personalizadas y Sigma;
las fases siguientes añaden aquí sus analizadores, siempre sobre el lote ya validado y
normalizado (app/ndr/ingest.py: IngestedBatch).
"""

from collections.abc import Sequence

from app.ndr.detect_dns import analyze_dns
from app.ndr.detect_l2 import analyze_l2
from app.ndr.detect_net import analyze_flows
from app.ndr.detect_ti import analyze_ti
from app.ndr.ingest import Analyzer
from app.ndr.rule_signals import record_rule_signals


def ndr_analyzers() -> Sequence[Analyzer]:
    return (analyze_l2, analyze_dns, analyze_flows, analyze_ti, record_rule_signals)

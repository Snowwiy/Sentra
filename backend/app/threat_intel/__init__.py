"""Threat Intelligence & Exploitability Context (Fase 5C).

Capa de inteligencia EXTERNA, opcional y offline-first, que enriquece lo que Sentra ya sabe
sin sustituirlo:
- providers.py: adapters independientes (CISA KEV, FIRST EPSS, importación local);
- http.py: cliente HTTP con protección SSRF (destino, redirecciones, DNS, tiempos, tamaño);
- kev.py, epss.py, stix.py, iocfile.py: parsers puros de cada formato (sin base de datos);
- indicators.py: validación y normalización de IOCs;
- store.py: persistencia por lotes con historial de cambios materiales;
- sync.py: sincronización e importación (una por fuente a la vez, transaccional);
- matching.py: coincidencias EXACTAS con datos locales ya existentes;
- context.py: lecturas compartidas por vulnerabilidades, riesgo, incidentes e IA.

Nada de este paquete visita, resuelve ni descarga un indicador, ejecuta patrones STIX,
busca exploits ni actúa sobre activos (bloquear, aislar...). Ver docs/threat-intelligence.md.
"""

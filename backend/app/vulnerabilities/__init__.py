"""Vulnerability & Exposure Management (Fase 5B): lógica pura y motor de evaluación.

Módulos (de más puro a menos):
- versions.py: parseo y comparación segura de versiones; "no comparable" es un resultado;
- normalize.py: normalización conservadora de producto, editor, paquete y SO (sin fuzzy);
- catalog.py: formato de importación sentra-vuln-catalog/1, validación y límites;
- matcher.py: VulnerabilityMatcher (inventario normalizado + candidato -> resultado);
- exposure.py y priority.py: contexto de exposición y prioridad Sentra de un finding;
- sources.py: interfaz VulnerabilitySource para futuras fuentes (hoy solo ficheros locales);
- engine.py: VulnerabilityEngine, la evaluación por lotes con base de datos;
- queue.py: marcar activos pendientes de evaluar desde otras partes de Sentra.

Nada aquí ejecuta contenido del catálogo, abre URLs, contacta con Internet ni con los
activos: es comparación de datos ya presentes en Sentra.
"""

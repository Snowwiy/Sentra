"""Integración SIEM de Sentra (Fase 7F, docs/fase-7f-architecture.md).

Fuente externa → receptor autorizado (sensor o importación) → validación → normalización →
deduplicación → almacenamiento → detección → correlación → presentación. Los conectores
externos son opcionales y están deshabilitados por defecto: los motores propios de Sentra
(detección, NDR, riesgo, incidentes) no dependen de ellos.
"""

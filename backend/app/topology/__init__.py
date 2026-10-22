"""Motor de topología de red (Fase 6D, docs/topology-engine.md).

- builder: derivación PURA de enlaces a partir de filas ya leídas (sin base de datos), para
  poder probar cada regla de forma aislada y determinista.
- service: carga de la evidencia de un site en pocas consultas, reconstrucción con upsert,
  lecturas de la API y `report_topology()` para los informes v2.
"""

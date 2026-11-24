"""NDR pasivo del sensor (Fase 7E): captura autorizada, flujos y metadatos de protocolo.

Desacoplado del discovery y de SNMP: no usa sus jobs ni su spool. Solo se activa si el operador
del host lo habilita en sensor.toml Y un admin lo aprueba en el servidor (ndr/config.py).
"""

# Capacidad que el sensor declara solo si `[ndr] enabled = true` en sensor.toml.
NDR_CAPABILITY = "network.ndr.passive"

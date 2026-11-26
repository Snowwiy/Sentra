"""Receptores SIEM del sensor (Fase 7F): Syslog (7F.2) y lectores de ficheros (7F.3+).

Mismo doble control que NDR: el operador del host declara en sensor.toml qué entradas pueden
existir (puerto, pares permitidos, ficheros) y un admin las habilita en el servidor como
fuentes. El servidor solo envía alias e identificadores de fuente, nunca puertos ni rutas.
El sensor no interpreta el contenido: enmarca, acota, sanea lo imprescindible, guarda en un
spool propio y reenvía por HTTPS. La normalización autoritativa se hace en el servidor.
"""

# Capacidad que el sensor declara solo si `[siem] enabled = true` en sensor.toml.
SIEM_CAPABILITY = "siem.ingest"

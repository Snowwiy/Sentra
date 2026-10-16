# Despliegue de un sensor (Fase 5F)

Guía operativa corta. Detalle del runtime, configuración y servicio en
[`sensor/README.md`](../sensor/README.md); seguridad en [sensor-security.md](sensor-security.md).

## Requisitos

- Un equipo (Linux con systemd o Windows) dentro de la red del site, con Python ≥ 3.12.
- Salida HTTPS hacia el servidor Sentra (el sensor no necesita puertos de entrada). Si el
  servidor usa la CA interna (Fase 4M), copiar su PEM y ponerlo en `ca_bundle`.
- En el servidor: el site creado y sus **redes autorizadas** (lo único que el sensor podrá
  escanear).

## Pasos

1. Sentra → Sites: crear el site y añadir sus redes (por ejemplo `192.168.1.0/24`).
2. Sentra → Sensores → Registrar sensor: elegir el site y crear el token de un solo uso
   (caduca en `SENSOR_ENROLLMENT_TOKEN_TTL_MINUTES`). Copiarlo a un fichero en el equipo del
   sensor; no pegarlo en la línea de comandos.
3. Instalar el sensor:
   - Linux: pasos de la sección "Linux (systemd)" del README (usuario `sentra-sensor` sin
     privilegios, unidad endurecida `sensor/packaging/linux/sentra-sensor.service`), enrolar
     como ese usuario con `--token-stdin` o `--token-file` y arrancar el servicio.
   - Windows: `sensor/packaging/windows/install-sentra-sensor.ps1` como Administrador (servicio
     `SentraSensor` con cuenta virtual, credencial con DPAPI, el servicio enrola en su primer
     arranque y borra el token).
4. Comprobar en Sentra → Sensores que pasa a `online` y declara capacidades.
   En el equipo: `sentra-sensor --config … diagnostics`.
5. Red → Descubrir: elegir el site y el sensor, y una red autorizada del site.
6. Opcional (Fase 6B): para inventario SNMP de switches, instalar el extra `snmp` del sensor
   (`pip install "./sensor[snmp]"` en su entorno), reiniciar el servicio y comprobar que
   declara las capacidades `snmp.*`. Permitir UDP saliente al puerto 161 de los equipos.
   Pasos completos en [snmp-network-intelligence.md](snmp-network-intelligence.md).

## Operación

- Revocar un sensor robado o retirado: Sensores → Revocar (efecto inmediato). Para volver a
  usar el equipo: token nuevo y `enroll --force`.
- Mantenimiento sin borrar nada: Deshabilitar (solo heartbeats) y Habilitar.
- Rotar credencial: Sensores → Rotar credencial; el sensor la cambia en su próximo heartbeat.
- Un sensor `stale` lleva más de `SENSOR_STALE_AFTER_SECONDS` sin contactar: revisar el
  servicio y la conectividad saliente.
- Los datos que el sensor no pudo entregar quedan en su spool (`data_dir`) y se envían al
  volver la conexión. No borrar el spool salvo para descartar esos datos a propósito.

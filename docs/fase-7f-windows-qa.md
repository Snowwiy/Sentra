# Fase 7F: pruebas manuales en Windows y con integraciones reales

**Nada de esto se ha ejecutado todavía.** La Fase 7F se ha probado en la nube (Linux,
PostgreSQL 16) con fixtures sintéticos que siguen la estructura documentada de cada formato.
Ningún conector se ha validado con un Suricata, Zeek, Wazuh, firewall o rsyslog reales, y el
sensor 0.9.0 no se ha ejecutado en Windows.

## 0. Preparación

1. Base de pruebas propia (no `sentra` ni una base con datos a conservar): `alembic upgrade
   head` y `alembic current` = 0059. Probar también `downgrade 0056` y `upgrade head`.
2. Suites completas según CLAUDE.md (backend, sensor, agente, frontend con Node 22 y 24),
   incluidos `mypy app tests` y `mypy --platform win32 .` en el sensor.
3. Servidor y frontend 0.9.0 arrancados; sensor 0.9.0 registrado en un site.

## 1. Fuentes e importación (7F.1)

1. Como viewer: SIEM muestra fuentes y salud; no hay pestaña de eventos ni de búsqueda.
2. Como admin: crear una fuente `sentra_json` de transporte `upload`, deshabilitada; importar
   da error. Habilitarla e importar un fichero propio sintético (una línea JSON por evento).
3. Reimportar el mismo fichero: el lote se reconoce como duplicado y no crea eventos.
4. Comprobar la auditoría (`siem_source_created`, `siem_import`).

## 2. Syslog en el sensor de Windows (7F.2)

1. Declarar `[[siem.inputs]]` TCP en un puerto alto y crear la regla del Firewall de Windows a
   mano (el sensor no la crea).
2. Sin aprobar la fuente en Sentra, el puerto no debe estar abierto (`netstat -ano`).
3. Aprobar: llegan mensajes de `Test-NetConnection` o de un rsyslog de laboratorio.
4. Un par fuera de `allowed_peers` se rechaza y cuenta como rechazado.
5. TLS con un certificado de la CA interna; UDP solo si se declara.
6. Detener el servidor: el spool del sensor crece y se vacía al volver.

## 2b. Correcciones 7F-Windows-Fix1 (pendientes de confirmar en Windows físico)

1. `sentra-sensor` con `tls_cert = "/etc/..."`: error claro de ruta sin unidad; con
   `C:/ProgramData/SentraSensor/...` arranca TLS. Una ruta UNC (`\\servidor\recurso\...`) se rechaza.
2. UDP con `max_message_bytes = 480`: datagramas de 479, 480, 481 y 16 000 bytes; solo los dos
   primeros llegan y `dropped_oversize` sube en 2 (estado de la entrada `degraded` con
   `oversize_records`).
3. Fichero: truncar `eve.json` (`Clear-Content`) con el sensor en marcha: `truncations` sube,
   `rotations` no, y las líneas nuevas llegan una vez. Igual con el servicio parado.
4. Sobrescribir `eve.json` con más contenido (`Set-Content`): se relee desde el principio.
5. Abrir `eve.json` en exclusiva desde PowerShell un momento: `file_unreadable` y después se
   continúa sin perder ni repetir líneas.
6. (Fix2) Con el sensor en marcha, `Rename-Item eve.json eve.json.1` no da error de fichero en
   uso; tras crear un `eve.json` nuevo, `rotations` sube en 1, `truncations` no, y llegan una
   sola vez las líneas escritas en el anterior justo antes de renombrarlo y las del nuevo.

## 3. Ficheros EVE, Zeek y Wazuh (7F.3-7F.5)

1. Suricata real en una red de laboratorio, `eve.json` local del sensor. Comprobar que no se
   guardan payloads y que el offset sobrevive a reinicios del servicio.
2. Rotación en Windows: confirmar el alcance de la pérdida de líneas documentada.
3. Zeek en JSON (`LogAscii::use_json=T`): conn, dns, ssl, notice.
4. Wazuh: `alerts.json` del manager copiado o montado; comprobar campos, MITRE, que el nombre
   del agente solo aparece como pista y que una alerta que repite una detección nativa queda
   como `probable_match` sin incidente nuevo.
5. Con NDR activo (7E) y Suricata viendo el mismo tráfico: enlaces `ndr_flow` y una sola
   detección por hecho.

## 4. Hunting e investigación (7F.6)

1. Búsquedas por IP, CIDR, puerto, texto y tipo; paginación "Cargar más".
2. Ventana de 60 días: 422. Medir tiempos con datos reales.
3. Añadir un evento a un caso, exportar evidencia y comprobar el SHA-256 en PowerShell
   (`Get-FileHash`) sobre el JSON canónico de `events`.
4. Resumen con IA local (si está configurada): no cambia el evento.

## 5. Live SOC (7F.7)

1. Abrir Live SOC detrás de Caddy (`deploy/`): los mensajes llegan sin retraso (sin buffering).
2. Provocar una detección: aparece en segundos.
3. Cerrar sesión en otra pestaña: la página pasa a "Desconectado" con el aviso de sesión.
4. Cortar la red unos minutos: "Reconectando" y recuperación sin duplicados.
5. Abrir 4 pestañas con el mismo usuario y un worker: la cuarta recibe 429.
6. Como viewer: no aparece el canal "Alertas SIEM".

## 6. Rendimiento

`PYTHONPATH=. python ..\qa\perf_siem.py` contra una base de pruebas propia (crea y borra su
propia fuente). Comparar con las cifras de la nube en docs/fase-7f.md.

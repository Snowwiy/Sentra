# Seguridad de los sensores (Fase 5F)

Modelo de amenaza: un sensor vive en una red remota menos controlada que el servidor. Se
asume que puede ser robado, clonado o comprometido. El diseño limita lo que un sensor
comprometido puede hacer: **observar y declarar observaciones de su propio site**, nada más.

## Identidad y credenciales

- Enrolamiento con token de un solo uso (`sentra_se_…`), creado por un admin para UN site,
  con caducidad (`SENSOR_ENROLLMENT_TOKEN_TTL_MINUTES`) y revocable. El servidor solo guarda
  su SHA-256. Se consume de forma atómica (bloqueo de fila): dos enrolamientos simultáneos
  con el mismo token no pueden ganar los dos.
- Token inexistente, caducado, usado, revocado o de un site no activo: siempre el mismo
  401 `sensor_enrollment_invalid` (no revela cuál). Limitado por IP.
- Credencial del sensor (`sentra_sc_…`): aleatoria (`secrets`), devuelta una sola vez,
  guardada en el servidor como SHA-256. El sensor la guarda con permisos `0600` (Linux) o
  DPAPI de la cuenta del servicio (Windows).
- Directorio de datos, credencial (y su temporal de escritura atómica), estado y spool
  SQLite con `-wal`/`-shm` son privados: `0700`/`0600` en POSIX y, en Windows, una DACL de
  NTFS verificada (no los bits de `st_mode`) con solo SYSTEM, Administradores, la cuenta del
  proceso, `NT SERVICE\SentraSensor` y el propietario. Una entrada de Users, Everyone o
  Authenticated Users se corrige con una DACL protegida sin herencia; si no se puede, el
  sensor no escribe (fail-closed). Administradores y SYSTEM se mantienen a propósito: pueden
  tomar posesión de cualquier fichero, así que quitarlos no protege nada y rompe soporte y
  copias.
- Rotación en dos fases: el admin la solicita, el sensor pide una nueva y la antigua sigue
  valiendo hasta el primer uso de la nueva. Así un fallo al guardar no deja al sensor fuera.
- Revocar: 403 `sensor_revoked` inmediato en todo el protocolo y cancelación de sus jobs.
  Deshabilitar: solo heartbeats, sin jobs.

## Autoridad del servidor

- El sensor nunca elige qué escanear. Los jobs los crea el servidor, dirigidos a un sensor
  concreto, y el target está dentro de una red habilitada del site.
- Antes de entregar un job (poll) se vuelve a comprobar que la red sigue autorizada: si un
  admin la quitó, el job falla (`network_not_authorized`) en lugar de ejecutarse.
- Catálogo cerrado de tipos (`discovery_basic`); un tipo desconocido falla
  (`job_type_unknown`). No existe campo de comando: **no hay ejecución remota arbitraria**.
- El `site_id` de un dato lo decide el servidor a partir de la credencial y del job, nunca
  del cuerpo de la petición (los esquemas rechazan claves extra: un `site_id` inyectado es
  422).
- Cada observación debe estar dentro del target del job
  (`sensor_observation_out_of_scope`) y su `observed_at` dentro de la ventana del job con la
  tolerancia de reloj (`sensor_timestamp_invalid`).
- Un sensor solo ve y toca sus propios jobs: un job de otro sensor responde 404 (no se
  revela su existencia).
- La ingestión usa la lógica del servidor (`ResultApplier`) restringida al site del job:
  un sensor del site B no puede crear ni modificar activos del site A, y nunca se reconcilia
  automáticamente entre sites.

## Límites (protección ante un sensor comprometido o defectuoso)

- Tamaño de petición en `/api/v1/sensor/*` (`SENSOR_MAX_REQUEST_KB`, 413).
- Observaciones por lote, puertos por host, lotes por job (422 / 409).
- Rate limiting de enrolamiento (por IP), heartbeat y poll (por sensor), 429.
- Salud del heartbeat: solo claves conocidas y acotadas; lo demás se ignora.

## Auditoría y logs

Se auditan (`audit_events`, sin secretos): creación y revocación de tokens, enrolamiento,
revocación, deshabilitación, habilitación, rotación solicitada y realizada, creación y
cancelación de jobs de sensor, cambios de sites y redes, y movimiento de activos entre
sites. `audit_service` descarta además cualquier clave con `token`, `secret`, `key`,
`hash`, etc. Los logs del servidor y del sensor nunca incluyen la credencial ni el token.

## Transporte

- HTTPS con verificación de certificado siempre. El sensor no tiene opción para desactivarla;
  admite una CA privada (`ca_bundle`). `http://` solo contra loopback (desarrollo).
- Sin puertos de entrada en el sensor.

## Lo que el sensor ejecuta localmente

TCP connect con `asyncio`. `ping` y `arp` del sistema solo si están permitidos, con argv fijo
construido localmente a partir de una IP validada por `ipaddress`, sin shell. Nada de
`eval`/`exec`, binarios ni scripts recibidos.

## Fuera de alcance (explícito)

mTLS, firma de jobs, atestación del sensor, cifrado del spool más allá de los permisos del
sistema de ficheros, auto-actualización del sensor.

# Advanced Network Discovery (Fase 6A)

Discovery avanzado de redes internas autorizadas: perfiles de escaneo, límites verificables
en servidor y sensor, evidencia con procedencia por host e historial de cambios básicos.
El discovery básico (Fase 4D/5F, `discovery_basic`) sigue funcionando igual.

**No es pentesting.** Sin SYN ni stealth scan, sin raw sockets, sin privilegios elevados,
sin fingerprinting de SO, sin UDP genérico y sin ejecutar shell. Desde la Fase 7A los perfiles
`standard` y `deep` leen además, en los puertos que el propio scan encontró abiertos, la
cabecera `Server` y el título web, el sujeto del certificado TLS y los servicios DNS-SD que
el equipo anuncia: una petición por puerto, sin credenciales y con límites fijos (ver
[device-intelligence.md](device-intelligence.md)).

## Métodos

| Método | Cómo | Qué afirma |
|---|---|---|
| ICMP | `ping` del sistema, un eco, argumentos fijos (sin shell) | el host respondió |
| TCP connect | `connect()` normal, cerrado al instante; open / closed (RST) / filtered (timeout) | puerto abierto o RST observados |
| ARP | lectura de la tabla de vecinos del SO (sin enviar ARP) | MAC vista en el segmento local |
| DNS inverso | resolvedor del sistema (PTR) | nombre devuelto por el DNS |
| DNS directo | resolvedor del sistema sobre el nombre PTR | el nombre resuelve (o no) a la misma IP |

La confirmación directa (FCrDNS) **solo compara direcciones**: nunca se sondea lo que
devuelve el DNS, así un registro manipulado no puede llevar el scan fuera del alcance. Sin
respuesta DNS el resultado es `null` (sin conclusión), no `false`.

El RTT sale solo del TCP connect (open o RST, el mínimo observado). `ping` no da RTT
fiable sin parsear su salida, que depende del idioma del SO.

## Perfiles

Los tres usan el mismo motor (`NetworkScanner` en el servidor, `Scanner` en el sensor); solo
cambian los valores.

| Perfil | Puertos | DNS | Timeout TCP | Concurrencia | Sondas/s | Reintentos | Duración |
|---|---|---|---|---|---|---|---|
| `quick` | 5 (`minimal`) | no | 500 ms | 32 | 100 | 0 | 10 min |
| `standard` (por defecto) | 27 (`common`) | PTR + directo, 2048 consultas | 800 ms | 64 | 200 | 1 | 30 min |
| `deep` | 47 (common, windows, printers, web y 20 de inventario) | PTR + directo, 4096 consultas | 1200 ms | 32 | 100 | 1 | 60 min |

Los valores se recortan siempre a los topes del servidor (`GET /discovery/profiles` devuelve
los efectivos). mDNS, NetBIOS y UPnP (`DISCOVERY_IDENTIFY`) solo los usa el servidor local.

## Límites

Dos niveles, y el más restrictivo gana:

- **Topes del servidor**: `DISCOVERY_CONCURRENCY`, `DISCOVERY_MAX_PROBES_PER_SECOND`,
  `DISCOVERY_MAX_HOSTS_PER_NETWORK` y `DISCOVERY_JOB_TIMEOUT_MINUTES` (ya existentes), más
  topes fijos: timeout TCP y DNS 5000 ms, 2 reintentos, 256 puertos, 4096 consultas DNS.
  `DISCOVERY_ICMP=false`, `DISCOVERY_REVERSE_DNS=false` o `DISCOVERY_IDENTIFY=false` también
  desactivan ese método en cualquier perfil.
- **Topes del sensor**: el servidor los envía en la configuración del heartbeat
  (`advanced_max_timeout_ms`, `max_dns_timeout_ms`, `max_tcp_retries`, `max_dns_queries`,
  `advanced_max_ports`, `max_deadline_seconds`) y el sensor rechaza cualquier job que los
  supere, aunque venga del servidor (defensa en profundidad). Un servidor anterior no los
  envía y el sensor rechaza entonces todo `discovery_advanced`.

Reintentos: solo de puertos **sin respuesta** (filtered) en hosts **ya vivos**. La fase de
liveness nunca reintenta, así una red vacía no multiplica las sondas.

Ajustes por job (`limits`, `ports` fuera del perfil): solo con `discovery:tune` (admin). Un
analyst elige perfil y, como mucho, un subconjunto de sus puertos.

## Alcance

Igual que el discovery básico: la red debe estar dentro de las redes autorizadas
(`DISCOVERY_ALLOWED_NETWORKS` en local, redes del site para un sensor), sin exclusiones y
sin redes públicas salvo `DISCOVERY_ALLOW_PUBLIC_NETWORKS`. Además, el número de hosts no
puede superar el `max_hosts` efectivo del job (`discovery_scope_too_large`).

## Sensor

- Tipo de job `discovery_advanced`, esquema versionado (`schema_version: 1`, claves exactas).
  Corrección 6C: `schema_version: 2` añade `identify` y `max_name_queries` (sondas de nombre
  mDNS/NetBIOS/SSDP/UPnP) y solo se envía a sensores 0.5.0 con la capacidad
  `network.discovery.names`; ver [asset-identity-labels.md](asset-identity-labels.md).
  Fase 7A: `schema_version: 3` añade `fingerprint` (huellas DNS-SD, HTTP y TLS) y solo se
  envía a sensores 0.7.0 con `network.discovery.fingerprint`; ver
  [device-intelligence.md](device-intelligence.md).
- Capability requerida `network.discovery.advanced` (sensor 0.2.0). A un sensor 0.1.x nunca
  se le asigna (409 `sensor_not_available`, `details[0].required_capability`); sigue
  recibiendo `discovery_basic`.
- Lotes, spool, idempotencia por `batch_id`, cancelación y resultados parciales: igual que en
  5F. `rtt_ms` y `forward_dns_match` son opcionales y no cambian el digest de un lote básico.

## Evidencia (`discovery_observations`)

Una fila por job y dirección (migración 0033), con site, ejecutor (servidor o sensor),
sensor, activo, métodos, MAC, nombres, puertos abiertos, RTT, confianza y evidencia:

- `observed`: evidencia directa de esta ejecución.
- `inferred`: deducción parcial (pista IANA por número de puerto, puerto que dejó de
  responder sin RST).
- `unknown`: sin evidencia suficiente.

Confianza: `high` con dos o más pruebas de vida independientes (ICMP, TCP, ARP), `medium`
con una, `low` sin respuesta. Nunca se inventa SO, fabricante, modelo ni servicio.

Cambios frente a la observación anterior del mismo activo: `new_host`, `address_changed`
(solo si coincide por MAC en el mismo site), `hostname_changed`, `port_new` (solo si el job
anterior sondeó ese puerto), `port_unresponsive` (observed con RST, inferred con timeout) y
`host_unresponsive`. Un host sin respuesta solo se registra tras un scan **completo**; un
scan cancelado, fallido, con timeout o con lotes perdidos no concluye nada negativo ni
borra nada.

Retención: `DISCOVERY_OBSERVATION_RETENTION_DAYS` (sin valor: se conserva todo), purgada por
`purge-old-data` y la tarea de retención.

## Identidad por site

La identidad de un activo descubierto sigue siendo site + IP (o MAC dentro del site). Dos
sites con la misma red nunca comparten activos ni observaciones.

## API

- `GET /discovery/profiles` (monitoring:read): perfiles efectivos, topes y `can_tune`.
- `POST /console/discovery/jobs`: `profile` (`quick`/`standard`/`deep`), `ports`
  opcionales, `limits` opcionales. Sin `profile` es el discovery básico de siempre.
  Errores 422: `discovery_profile_invalid`, `discovery_ports_invalid`,
  `discovery_limit_exceeded`, `discovery_limit_invalid`, `discovery_scope_too_large`,
  `discovery_options_require_profile`; 403 `discovery_tune_forbidden`. Todo queda auditado
  (perfil, puertos y límites pedidos).
- `GET /discovery/observations` (monitoring:read): filtros `job_id`, `site_id`, `network`
  (CIDR), `sensor_id`, `executor`, `method`, `reachability`, `q`, `latest=true` (última por
  site + IP); paginado en PostgreSQL (`limit` ≤ 200). 422 `discovery_filter_invalid`.
- `DiscoveryJobRead` añade `profile`, `job_type`, `observations_total` y `hosts_unresponsive`.

## UI

Red → Discovery: selector de perfil (con los límites efectivos), puertos, límites editables
solo con `can_tune`, site y sensor (los perfiles avanzados se deshabilitan si el sensor no
declara la capability). Vista del job con observaciones y evidencia; pestaña «Observaciones
de red» con la última observación por IP y filtros en servidor.

## Limitaciones

- Sin SNMP, LLDP, CDP, Wi-Fi ni topología (6B-6E).
- Sin RTT de ICMP; sin base OUI de fabricantes (salvo `DISCOVERY_OUI_FILE` local).
- ARP solo ve el segmento local del ejecutor y solo lo que el SO ya tiene en caché.
- El DNS usa el resolvedor del sistema: su timeout real lo decide el SO (el límite del job
  acota la espera, no la consulta en curso).

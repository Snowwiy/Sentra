# Fase 6D: problemas conocidos y pendientes

Registro de limitaciones aceptadas al cerrar la fase. Ninguna bloquea la publicación; cada una
indica por qué se deja así.

## Pendiente de validar con hardware real

- Archer GX90 (192.168.50.1) con un sensor 0.5.1: el diagnóstico real (probablemente
  `no_response` si el router no ofrece SNMPv3 en la LAN) solo se puede confirmar allí. Las
  pruebas usan un agente SNMPv3 simulado con pysnmp 7.1.
- Switches con LLDP/CDP y FDB reales: el motor de topología solo se ha probado con datos
  sintéticos.
- Informes v2 en el visor PDF de Windows: acentos y transliteración.
- Suites completas en Windows (Python 3.14/3.15) y frontend con Node 24 en el PC.

## Limitaciones aceptadas

- Sin historial temporal de topología: es el objetivo de 6E. Los enlaces ausentes se conservan
  con `present=false` y no se purgan; `topology_builds` crece unas 96 filas por site y día
  con el intervalo por defecto. Su retención se añadirá con 6E, que define qué historia guardar.
- `POST /topology/rebuild` no tiene enfriamiento propio: es solo de admin, se serializa por
  site (409 si hay otra en curso) y está acotado por `TOPOLOGY_MAX_LINKS`.
- Informes v2: la topología se dibuja para un máximo de 3 sites y 60 nodos por site; el resto
  se omite. La topología del informe ignora `include_archived` (los activos archivados nunca
  son nodos de la topología).
- Las detecciones de correlación ya abiertas antes del parche conservan su `occurrence_count`;
  el score de ravenslg no baja hasta que se cierren o caduquen.
- Un sensor 0.5.0 sigue enviando «snmp error: KeyError» ante un fallo interno del colector. El
  servidor lo muestra como `collector_error` sin el nombre de la excepción.
- La auditoría `network_monitoring_paused` usa siempre el actor del programador SNMP; el
  campo `poll_trigger` indica qué consulta provocó la pausa.
- Los rangos de bloqueos consultivos (`_BASE + n`, `THREAT_SOURCE_LOCK_BASE + id`,
  `TOPOLOGY_SITE_LOCK_BASE + site`) solo se solaparían con más de 65 536 fuentes de threat
  intel; no es realista hoy.
- `Content-Disposition` no está en `expose_headers` de CORS: no hace falta (el nombre del
  fichero sale del JSON del informe), pero un despliegue con otro origen no podrá leerlo.
- El chunk principal del frontend supera 500 kB (aviso de Vite); no afecta al funcionamiento.

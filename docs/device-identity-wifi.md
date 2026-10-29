# Identidad de dispositivos y Wi-Fi (Fase 7B.2)

Objetivo: mostrar qué sabe Sentra de cada dispositivo, de dónde lo sacó, con qué confianza y
qué no puede demostrar. Sentra no inventa identidades: si no hay evidencia, lo dice
(`identity_unresolved`).

Código:

- `backend/app/services/identity_rules.py`: reglas puras, compartidas por la tabla y la
  ficha.
- `backend/app/services/device_identity.py`: perfil, candidatos, comparación y
  asociaciones.
- Migración `0049` (`asset_identity_links`).

Fuentes que se combinan (todas existían antes de 7B; ninguna nueva escanea más):

- DHCP: hostnames, leases e historial (`docs/dhcp-identity.md`).
- DNS directo e inverso con confirmación.
- mDNS y DNS-SD.
- SSDP/UPnP.
- HTTP y TLS en los puertos autorizados.
- OUI de MACs universales.
- Agente autenticado.
- Etiqueta y tipo confirmados a mano.
- Clientes Wi-Fi por SNMP o por el propio agente.

## Niveles de identidad, cada uno con su procedencia

`GET /assets/{id}/identity/profile` devuelve el perfil de identidad del activo.

### Nombre

| Origen | Estado |
|---|---|
| `custom_label`, la etiqueta que puso el usuario | Siempre manda |
| Nombre informado por el agente | `confirmed` |
| Nombre publicado por el dispositivo (DHCP, DNS confirmado, mDNS, UPnP) | `probable` |
| Nombre genérico o fuente caducada | `unresolved` |

Las alternativas observadas se listan con su frescura (`fresh`, `stale` o `unknown`).

### Fabricante

El fabricante de la NIC y el del dispositivo son cosas distintas: una NIC Samsung no hace de
un equipo un Samsung (caso `192.168.50.70`).

| Origen | Estado | Motivo |
|---|---|---|
| Lo que anuncia el equipo (UPnP, mDNS, web) | `probable` | `device_announced` |
| Solo el OUI | `probable` | `network_adapter_only` |
| MAC privada | `unresolved` | `random_mac` |

### Tipo

| Origen | Estado |
|---|---|
| Manual | `confirmed` |
| Clasificación con confianza media o alta | `probable` |
| El resto | `unresolved` |

Un puerto solo nunca decide el tipo (regla de 6C).

### Sistema operativo

| Origen | Estado |
|---|---|
| Agente | `confirmed` |
| Huella de red | `probable` |
| Sin evidencia | `unresolved` |

### Estado global (`identity_state`)

También aparece en el listado de activos y en la tabla de Red → Dispositivos.

| Estado | Cuándo |
|---|---|
| `confirmed` | El equipo tiene agente |
| `probable` | MAC universal o virtual. Se añade `stale_sources_only` si todas sus fuentes caducaron |
| `identity_unresolved` | MAC privada sin agente, o sin ningún identificador estable |

## MAC aleatorias

`mac_profile()` clasifica la MAC: `universal`, `local` (localmente administrada, es decir,
privada o aleatoria), `virtual` (prefijos conocidos de hipervisores), `multicast` o `none`.
Para las locales da el cuadrante SLAP (IEEE 802c).

Cómo trata Sentra una MAC privada:

- Una MAC privada no se presenta como identificador permanente. El historial de direcciones
  (`addresses`) se conserva y se muestra como historial.
- Android, iOS y Windows rotan la MAC por red o por tiempo. Sin agente, la identidad entre dos
  MACs privadas es **indeterminable**, y la UI lo dice así.
- No hay fingerprinting encubierto: Sentra no intenta correlacionar MACs rotadas por
  señales de radio, tiempos ni huellas de tráfico.

## Sugerencias sin fusión automática

`GET /assets/{id}/identity/candidates` sugiere posibles coincidencias del MISMO site, con su
evidencia:

| Evidencia | Fuerza |
|---|---|
| Mismo MachineGuid, mismo linaje de agente, asociación manual, MAC informada por el agente del otro registro | fuerte |
| Misma MAC universal, MAC en el historial del otro | media |
| Mismo nombre, misma IP, mismo fabricante, mismo SO | débil |

Las señales débiles solas nunca generan una sugerencia: IP, OUI, SO o parecido de nombres no
bastan (`test_ip_name_or_os_alone_never_suggest_a_match`). Nada se fusiona solo.

### Comparar dos registros (caso 192.168.50.66)

`GET /identity/compare?left=…&right=…` clasifica el par:

| Clasificación | Significado | Acción recomendada |
|---|---|---|
| `same_agent_reinstalled` | Los dos tuvieron agente y comparten identidad de máquina, linaje o MAC | `reconcile`: la reconciliación 5C.2, con sus bloqueos, que conserva el historial |
| `historical_asset` | Uno está archivado y es el pasado del otro | ninguna |
| `reconcilable_identity` | Evidencia fuerte o media | `link_alias`: un admin puede asociarlos |
| `ip_reuse` | Solo coinciden en la IP | ninguna |
| `distinct_records` | Sin evidencia, o sites distintos | ninguna |

`python -m app.cli audit-7b --ip 192.168.50.66` hace la misma comparación sobre todos los
registros que han tenido esa IP.

## Asociación manual con auditoría

Hay dos tipos de asociación:

- **`asset_alias`**: un registro descubierto, por ejemplo con una MAC privada que rotó, es
  alias de un activo conocido. Al asociarlo:
  - el alias se **archiva**, no se borra;
  - su MAC se asigna al destino para el descubrimiento;
  - su historial se conserva.

  Un registro con agente nunca es alias: va por la reconciliación 5C.2.
- **`wlan_client`**: un cliente Wi-Fi se asocia a un activo (`correlation_basis = manual`).
  Un cliente que el propio agente del equipo informa (`agent_self`) no se puede
  sobrescribir.

El flujo tiene tres pasos:

1. `POST /identity/links/preview`: muestra bloqueos, efectos y evidencia. No necesita motivo.
2. `POST /identity/links` con `confirm: true` y un motivo de 3 a 500 caracteres.
3. `POST /identity/links/{id}/revoke` con un motivo: deshace exactamente lo que se hizo. La
   fila se conserva.

Los bloqueos son: `same_asset`, `different_site`, `target_archived`, `alias_has_agent`,
`alias_already_linked`, `client_already_linked` y `client_confirmed_by_agent`.

Asociar y revocar requieren `identity:manage` (solo admin) y quedan en la auditoría. Leer
perfiles, candidatos y asociaciones requiere `monitoring:read`.

## Panel Wi-Fi

Novedades de la API: `GET /network/wlan/clients/{id}` y `GET /network/wlan/clients/{id}/observations`.

En la UI (Wi-Fi → Clientes → Detalle), la ficha del cliente muestra:

- SSID, BSSID, punto de acceso, banda y estándar.
- Estado, presencia, frescura, primera y última vez que se vio.
- La MAC y si es privada.
- El activo asociado y la base de la correlación (agente, MAC, MAC informada por el agente o
  manual).
- El historial de observaciones, con señal y calidad cuando la fuente las da.
- La acción «Asociar a un activo…», con vista previa y motivo.

### TP-Link Archer GX90

No tiene SNMP y no hay ninguna API oficial documentada que Sentra pueda usar. No se ha
inventado compatibilidad. En ese laboratorio:

- Los datos Wi-Fi llegan del agente de cada equipo Windows conectado: su propio enlace, con
  BSSID, SSID, canal, banda y señal.
- La identidad de los demás clientes sale del descubrimiento (DHCP, mDNS, UPnP).

Un adaptador para controladoras con API oficial (Omada, UniFi...) sería un adaptador opcional
nuevo, de solo lectura. Queda fuera de 7B y necesita una decisión de Jesus.

Desconectar, bloquear o modificar redes sigue deshabilitado: no hay integración real.

## Limitaciones

- Dos dispositivos con MAC privada y sin agente no se pueden distinguir de uno solo que
  rotó la MAC. Sentra lo marca como `identity_unresolved`.
- La sugerencia por MAC informada por el agente depende de que el agente vea esa interfaz
  (agente 0.5.0+ en Windows).
- El cuadrante SLAP es orientativo: muchos sistemas operativos no lo respetan.

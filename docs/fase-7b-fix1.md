# Fase 7B-Fix1: correlaciones causales, riesgo v7, identidad y topología honestas

Corrección incremental sobre la 7B final (con la política de autorización de mantenimiento).
No sustituye funciones: corrige lo que la QA de Windows de la 7B dejó a la vista en
`ravenslg`. Servidor y frontend siguen en 0.5.0; agente 0.6.2; sensor sin cambios (0.7.0).
Migración 0050 (encadenada desde 0049). Sin dependencias nuevas ni ajustes nuevos.

La auditoría con causa raíz de cada punto está en `AUDITORIA-7B-FIX1.md` (entrega).

## 1. Servicios por usuario, CORR-002 v5 y PER-001 v3

Causa: Windows crea una instancia de cada servicio por usuario al iniciar sesión
(`WpnUserService_6df11`, `OneSyncSvc_6df11`...). El inventario la veía como servicio nuevo y
CORR-002 la unía a cualquier 4104 cercano: coincidir en el tiempo bastaba.

Clasificación (`backend/app/detection/service_identity.py`, funciones puras):

| Clase | Cuándo |
| --- | --- |
| `installed` | Evento 7045 del SCM |
| `user_service_instance` | Nombre `<plantilla>_<hex>` y plantilla en el mismo inventario |
| `modified` | El ImagePath de un servicio existente cambió (cambio `image_changed`) |
| `discovered` | Apareció en el inventario sin 7045 |

Una instancia por usuario solo queda `verified` si se comprueba todo: bit 0x80
(SERVICE_USERSERVICE_INSTANCE) en `Type`, ejecutable exactamente
`%SystemRoot%\System32\svchost.exe`, mismo grupo `-k` que la plantilla y firma Authenticode
válida de Microsoft. Con agentes anteriores a 0.6.2 queda `probable`. Si algo comprobable no
casa (otro ejecutable, sin el bit, otro grupo, firma inválida o de otro emisor) es `suspicious`:
el nombre de instancia se usa para esconderse. El nombre por sí solo nunca decide.

El agente 0.6.2 (`agent/sentra_agent/service_identity.py`) añade al inventario de servicios
`service_type`, `image` y `image_signature` (estado y firmante). Solo lectura del registro y de
la firma; no modifica servicios.

- PER-001 v3: una instancia `verified` no abre detección (la señal se conserva con su
  clasificación). `probable` abre una detección baja/baja con una clave por plantilla (cada
  sesión cambia el sufijo). `suspicious`, ruta inusual o firma inválida suben a alta. Un
  servicio `modified` es una detección propia (posible secuestro de servicio).
- CORR-002 v5: exige una relación causal demostrable (`causal_links`):
  - `install_event_after_script` (fuerte): 7045 posterior al primer script.
  - `script_started_service_binary` (fuerte): un hijo del PowerShell ejecutó el mismo fichero
    que el servicio.
  - `suspicious_service_after_script` (media): servicio sospechoso visto después del script.
  - `service_modified_after_script` (media): ejecutable cambiado después del script.

  Sin ninguno no hay correlación. La proximidad se muestra en SCR-001 como
  `temporal_context` ("contexto temporal, sin relación causal").
- SCR-001: los 200 bloques 4104 siguen siendo auditables. Dentro del cooldown se agrupan en
  la misma detección y cada bloque añade su fila de evidencia; no se borra ningún evento.
- Ninguna regla se desactiva y no hay listas por nombre.

### Revisión de correlaciones antiguas (sin reconocimiento retroactivo)

Las CORR-002 abiertas con versión < 5 no cambian solas. `POST
/api/v1/detections/correlation-review/preview` re-evalúa cada una con la evidencia guardada y
devuelve un veredicto: `causal`, `temporal_only` o `insufficient_evidence`. `POST .../apply`
(con `confirm: true`, nota opcional y `detections:manage`) anota la revisión en la detección,
resuelve solo las `temporal_only` sin actuación del analista y pide el recálculo del riesgo.
Queda auditado (`correlation_review_applied`) y el historial de riesgo se conserva. UI:
Seguridad → Detecciones, panel "Revisar correlaciones CORR-002 anteriores a la v5".

## 2. Riesgo v7

`FORMULA_VERSION = 7` (`backend/app/risk/`). No se fija ninguna puntuación: el resultado sale de
la evidencia.

- Familia SCR-001: N detecciones parecidas son un grupo con un factor de repetición
  logarítmico y con el mismo tope que las ocurrencias. Ya no son N grupos independientes.
- CORR-002 guarda `script_keys` (hasta 200 claves `script:<sha256|ruta>`), así que absorbe
  todos los SCR-001 de su cadena, no solo los tres últimos.
- Cada aportación lleva `risk_class`: `direct`, `correlated` o `contextual`. El desglose suma
  `by_class` y lista los motivos de absorción (`same_causal_chain`, `same_rule_repetition`,
  `shared_signals`...).
- Exposición (PostgreSQL 5432 y demás): migración 0050 guarda `asset_ports.observed_from`.
  - `self` significa que el discovery del servidor sondeó una IP propia y ese tráfico no
    atraviesa el firewall. Aporta con `exposure_self_vantage_factor` (0,6). No se elimina.
  - `remote` significa accesible desde otro equipo o sensor.
  - `NULL` significa anterior a 0050 y se calcula como en v6.

  La dirección de escucha (`listen_scope`: todas las interfaces, loopback, específica) sale
  del inventario de conexiones del agente. Las reglas del firewall nunca se leen, así que
  `missing: ["firewall_rules"]` lo dice.
- La política de mantenimiento de la 7B no cambia.
- Recálculo: como en v6, el cambio de fórmula no fuerza un recálculo inmediato.
  `python -m app.cli run-risk --all` lo hace al momento y el historial se conserva.

## 3. Identidad de dispositivos

`AssetIdentityProfile` añade `model`, `assigned_name` y `missing`. Cada nivel (nombre asignado,
nombre, fabricante, modelo, tipo, SO) es confirmado, inferido o desconocido, con su fuente.

- El nombre del administrador (`custom_label`) es confirmado con fuente `admin` y siempre gana.
- El fabricante de la tarjeta de red (OUI) se muestra aparte del fabricante del dispositivo.
- Nunca se fusiona por MAC privada ni por IP.
- "Qué falta para identificarlo" enumera los datos ausentes: nombre DHCP, modelo, SO...
- Clasificación: los códigos de modelo Huawei de tablet (`xxx-W09`...) dan tableta. Los
  fabricantes de chips (Realtek, Intel, MediaTek, Broadcom, Qualcomm) ya no se toman como SO.

Archer GX90: no se asume API ni SNMP. La fuente de solo lectura disponible es la lista de
clientes DHCP del router exportada a mano e importada con el formato `generic_csv`
(`ip,mac,hostname`). Ver docs/dhcp-identity.md. No hay integración con endpoints privados.

## 4. Topología

Doce nodos con tres enlaces era lo que había: el grafo solo dibuja relaciones con evidencia.
Cambios:

- Un cliente Wi-Fi con BSSID observado y sin AP inventariado enlaza con un nodo externo
  `bss:<bssid>` ("Wi-Fi <ssid>", relación `wlan_association`). No se inventan enlaces por
  subred hacia la puerta de enlace.
- `TopologyGraph.coverage`: nodos, nodos sin enlaces (por tipo), enlaces por tipo y
  limitaciones (`nodes_without_link_evidence`, `no_physical_link_evidence`,
  `access_point_not_inventoried`). La UI lo muestra como "Cobertura de la topología".

## 5. Duplicados ("Ravenslg Linux" x2)

Causa: el listado global de pares solo comparaba nombre e IP con identificadores del agente.
Dos registros con la misma MAC universal y distinto nombre no aparecían como par. Ahora la MAC
universal cuenta (la privada solo como evidencia baja). Cada candidato trae una hipótesis
(`reinstall`, `re_enrollment`, `agent_identity_change`, `discovered_record`,
`platform_mismatch`, `historical_record`, `unknown`) y sus motivos. La reconciliación sigue
siendo manual con confirmación. No hay borrado ni fusión automática.

## 6. Analyst Console

- `/console?asset=<id>&detection=<id>` abre con el contexto cargado. La detección manda; el
  activo sale de la URL o de la detección.
- Hay botones "Abrir en consola" en las fichas de detección y de activo.
- "Solo herramientas compatibles" filtra el catálogo por el contexto. Los ids de la salida
  (activo, detección, incidente, investigación) enlazan a su ficha si son UUID.
- Sin comandos libres. Mismo motor 7A y mismo RBAC.
- Warning "Received NaN for the children attribute": los valores numéricos de la consola pasan
  por `count()` (NaN o ausente se muestra como "—") y hay un test de regresión. En la nube no
  se reprodujo en el navegador (recorrido con Playwright por consola, activo, detección,
  riesgo, topología, ciclo de vida y dashboard). La causa exacta en el PC de Jesus queda sin
  confirmar: hace falta la pila de componentes del aviso.

## Migración 0050

`20261027_0050_7b_fix1.py`: valor `image_changed` en `change_kind` y columna
`asset_ports.observed_from` (`self`/`remote`/NULL, con CHECK). Sin claves foráneas ni
backfill. El downgrade borra los cambios `image_changed` y reconstruye el enum. Se validó
upgrade → downgrade → upgrade en una base de pruebas con datos (`sentra_test_d`). Siguiente
migración libre: 0051.

## Compatibilidad

Hay que actualizar el servidor antes que el agente 0.6.2. Un servidor 7B ignora los campos
nuevos del inventario. Con agentes anteriores a 0.6.2, las instancias por usuario quedan
`probable` (detección baja), nunca `verified`.

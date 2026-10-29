# Fase 7B.0: auditoría técnica del equipo ravenslg

Auditoría previa a 7B sobre el riesgo 99/100 de `ravenslg`, CORR-002, PER-001, los puertos
8000/5432, los eventos 4104/7045/4688 y el duplicado de `192.168.50.66`. Se hizo sobre el
código real (base Dev `f8ef9d3`, Alembic `0047`) y sobre reconstrucciones con datos
sintéticos en `sentra_test`. **No hubo acceso a la base `sentra` ni al equipo de Jesus**: las
conclusiones sobre su equipo concreto se cierran con las dos herramientas de solo lectura que
añade esta fase (apartado 5), nunca con una suposición.

## 1. Criterio de clasificación

| Veredicto | Cuándo |
|---|---|
| `verified_benign` | TODA la evidencia que dispara la regla casa con UNA operación de mantenimiento aprobada: SHA-256 de referencia + ruta canónica + cuenta + ventana (y servicio con ImagePath exacto). |
| `suspicious_unverified` | Hay datos suficientes y algo no casa (hash distinto, otra ruta, fuera de ventana, otra cuenta) o no hay operación que lo describa. |
| `insufficient_evidence` | Falta un dato para comprobarlo (agente antiguo sin contexto del 4104, 7045 sin cuenta, script no legible). Se dice qué falta y cómo obtenerlo. |
| `confirmed_malicious` | Solo lo declara un analista (restricción CHECK en `detection_attribution_events`). |

El nombre SENTRA nunca clasifica nada: `SentraAgent`, `sentra.exe`, `install-sentra-agent.ps1`
y `powershell.exe` se falsifican sin esfuerzo (`test_attribution.py::test_service_name_spoofing_is_not_verified` y `test_authorized_script_copied_elsewhere_is_not_verified`).

## 2. Hallazgos (causa raíz, con la evidencia en el código)

### H1. El riesgo 99 se alcanzaba contando varias veces UNA operación

Reconstrucción determinista en `backend/tests/test_risk_attribution.py` (activo de
criticidad alta, una instalación del agente y PostgreSQL expuesto en 5432):

| Escenario | Puntuación |
|---|---|
| Fórmula v5 (antes): SCR-001, PER-001 (7045 e inventario, dos ocurrencias), CORR-002 y NET-001 en grupos independientes | **99** |
| Fórmula v6, claves causales, operación sin verificar | 98 |
| Fórmula v6, operación verificada (SCR-001, PER-001 y CORR-002 a 0 puntos con motivo) | **81** (inherente 8, activo 81, sin atribución 98) |

Causas encontradas:

1. **PER-001 doble.** El 7045 del SCM y el inventario de servicios del agente son dos señales
   de la misma instalación. La regla tenía `cooldown 0` y cada señal sumaba una ocurrencia.
   Además el 7045 puede nombrar el servicio por su nombre visible (`Sentra Agent`) y el
   inventario por su clave (`SentraAgent`), así que ni siquiera compartían clave.
2. **CORR-002 doble.** La correlación tomaba la instalación de cualquiera de las dos señales
   y podía abrir dos correlaciones para la misma instalación según el orden de llegada.
3. **Sin claves causales.** SCR-001 (el script), PER-001 (el servicio) y CORR-002 (los dos)
   no compartían señales guardadas y el motor 4I los sumaba como evidencia independiente.
4. **Criticidad alta y NET-001 en 5432.** La criticidad multiplica y el puerto 5432 es
   "sensible" (`app/discovery/ports.py`), así que NET-001 es de severidad alta. Esto **no es
   un error**: un puerto de base de datos expuesto es riesgo aunque el proceso sea legítimo,
   y sigue contando con la operación verificada (por eso queda en 81).

Corrección: reglas PER-001 v2 y CORR-002 v4, fórmula de riesgo v6 (docs/risk-attribution.md).

### H2. PowerShell 7 no se recogía

El agente 0.6.0 solo leía `Microsoft-Windows-PowerShell/Operational`. `pwsh.exe` escribe sus
4104 en `PowerShellCore/Operational`: un script ejecutado con PowerShell 7 no dejaba rastro.
Corregido en el agente **0.6.1** (canal opcional; si PowerShell 7 no está instalado se informa
como no disponible, igual que Defender). El servidor ya aceptaba el canal.

### H3. No existe telemetría 4688 real

`security_4688` figura en el contrato de fuentes de actividad, pero ningún colector del agente
lo produce: los procesos llegan del sondeo `psutil_poll` (agente 0.5.0+). Consecuencias: un
proceso de segundos puede no verse y no hay línea de comandos. La atribución lo trata como
`missing` con el texto de cómo obtenerlo, nunca lo inventa. Activar la auditoría 4688 es una
directiva del equipo: **no se cambió** (requisito de 7B).

### H4. Versión del agente: `.venv` frente a servicio

El servicio `SentraAgent` ejecuta el runtime embebido copiado en
`C:\Program Files\Sentra Agent\runtime` por `install-sentra-agent.ps1`, no el `.venv` del
repositorio. Actualizar el repo no actualiza el servicio. Solo los eventos enviados por un
agente 0.6.0+ traen ruta, SHA-256, PID y SID del 4104; los de 6E (agente 0.5.x) no, y su
veredicto es `insufficient_evidence`. `audit-7b` muestra la versión que declara el agente en
el heartbeat y el colector local la que tiene instalada el servicio.

### H5. Puertos 8000 y 5432

- 8000/TCP: el backend de desarrollo (uvicorn). No es un puerto "sensible": NET-001 baja.
- 5432/TCP: Jesus usa PostgreSQL 18 en **5433**. Un oyente en 5432 es otro proceso (una
  instalación anterior de PostgreSQL u otro servicio). Hasta saber quién escucha, es
  `insufficient_evidence` para la atribución y sigue sumando riesgo como exposición. El
  colector local identifica el proceso, la ruta, el hash, la firma y el servicio.

### H6. Duplicado de 192.168.50.66

Dos registros con la misma IP pueden ser una reinstalación del agente, un activo histórico, la
reutilización de la IP por DHCP o un alias con MAC privada. `GET /identity/compare` (y
`audit-7b --ip 192.168.50.66`) los clasifica con su evidencia (`same_agent_reinstalled`,
`historical_asset`, `ip_reuse`, `reconcilable_identity`, `distinct_records`). La IP sola es
evidencia débil y nunca basta para asociar. Nada se fusiona solo.

## 3. Clasificación de los casos

Sin los datos reales del equipo, el estado por defecto de cada caso es:

| Caso | Veredicto hasta tener evidencia | Qué falta | Cómo obtenerlo sin desactivar controles |
|---|---|---|---|
| SCR-001 de `install-sentra-agent.ps1` (Windows PowerShell) | `suspicious_unverified` sin operación; `insufficient_evidence` si el evento es de un agente < 0.6.0 | Operación aprobada con el SHA-256 de referencia, ruta y cuenta | Registrar la operación en Administración → Mantenimiento con el hash de referencia del servidor |
| 4104 de PowerShell 7 | No hay eventos (H2) | El canal PowerShellCore | Actualizar el servicio a agente 0.6.1 |
| PER-001 `SentraAgent` | Igual que SCR-001; con solo inventario, `insufficient_evidence` | ImagePath y cuenta del 7045 | Revisar el 7045 (canal System); el colector local los lee |
| CORR-002 | Hereda: `verified_benign` solo si script y servicio casan con la misma operación | Lo de SCR-001 y PER-001 | Ídem |
| NET-001 8000 | Exposición (nunca se resuelve sola) | Proceso dueño del puerto | Inventario del agente o colector local |
| NET-001 5432 | `insufficient_evidence` | Quién escucha en 5432 | Colector local (`Get-NetTCPConnection` de solo lectura) |
| 192.168.50.66 | Sin clasificar | Comparación de los dos registros | `python -m app.cli audit-7b --ip 192.168.50.66` |

`init_database.ps1` y los Marshal/InteropServices de los scripts propios ya se explicaron en 7A
(palabras clave administrativas). Explicar no es verificar: siguen necesitando operación.

## 4. Lo que NO se ha podido comprobar

- El contenido real de la base `sentra` de Jesus (no se accede a ella).
- Los eventos reales de su equipo (4104, 7045, 4688) y la versión del servicio instalado.
- Quién escucha en 5432 en su equipo.
- Si los dos registros de 192.168.50.66 comparten MachineGuid, linaje o MAC.
- `scripts/collect_7b_evidence.ps1` no se pudo ejecutar ni analizar en la nube (no hay
  PowerShell disponible): está pendiente de su primera ejecución en Windows.

## 5. Cómo cerrar la auditoría en el equipo real

1. Colector local (PowerShell como administrador, solo lectura):
   `powershell -NoProfile -File .\scripts\collect_7b_evidence.ps1 -Days 30`
   No cambia Defender, firewall, Execution Policy, auditoría, permisos ni servicios. No copia
   el texto de los scripts ni la línea de comandos del 4688.
2. Informe del servidor (solo lectura, transacción READ ONLY). Lee las tablas de 7B, así que
   necesita la base en `0049`: primero en una copia restaurada o en `sentra_test` con datos de
   prueba, y en `sentra` solo después de que Jesus haga la copia de seguridad y migre:
   `python -m app.cli audit-7b --asset ravenslg --ip 192.168.50.66 --days 30 --output audit-7b.json`
3. Con los hashes del colector y los de referencia del servidor, registrar y aprobar la
   operación de la instalación; revisar la vista previa y aplicar solo si todo casa.

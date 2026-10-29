# Fase 7B: guía de QA y validación funcional en Windows

Pasos para validar 7B en el PC de desarrollo (Windows 11, PostgreSQL 18 en 5433, Python
3.15, Node 24). Reglas:

- Las suites y migraciones de prueba van contra `sentra_test`.
- La base `sentra` solo se migra después de hacer y verificar la copia de seguridad.
- No se cambian Defender, el firewall, la Execution Policy, la auditoría, permisos globales ni
  reglas de aislamiento para que algo pase. Si una prueba lo necesitara, se anota como
  bloqueada.

## 1. Aplicar y comprobar

```powershell
cd C:\Users\hexan\Documents\Sentra
git apply --check sentra-fase-7b-crlf.patch   # o la variante LF según core.autocrlf
git apply sentra-fase-7b-crlf.patch
cd backend
.venv\Scripts\python.exe -m pytest
ruff check .; ruff format --check .; mypy app tests; mypy --platform win32 app tests
cd ..\agent;  .venv\Scripts\python.exe -m pytest; ruff check .; mypy .
cd ..\sensor; .venv\Scripts\python.exe -m pytest; ruff check .; mypy .; mypy --platform win32 .
cd ..\frontend; npm ci; npm test; npm run typecheck; npm run lint; npm run build; npm audit
```

Después, en la base operativa:

```powershell
cd ..\backend
.venv\Scripts\python.exe -m app.cli backup                  # docs/backup-restore.md
.venv\Scripts\python.exe -m app.cli verify-backup <copia>.dump
.venv\Scripts\python.exe -m app.cli migration-status        # debe decir 0047 -> 0049
.venv\Scripts\python.exe -m alembic upgrade head
.venv\Scripts\python.exe -m app.cli integrity-check
```

## 2. Auditoría 7B.0 con datos reales

1. PowerShell **como administrador**, sin cambiar nada del sistema:
   `powershell -NoProfile -File .\scripts\collect_7b_evidence.ps1 -Days 30`.
   Es la primera ejecución real del script: no se pudo ejecutar ni analizar en la nube. Si
   falla, anotar el error y la línea.
2. `.venv\Scripts\python.exe -m app.cli audit-7b --asset ravenslg --ip 192.168.50.66 --days 30 --output audit-7b.json`
3. Rellenar la tabla 3 de `docs/fase-7b-auditoria.md` con lo observado:
   - versión del servicio frente a la del `.venv`;
   - quién escucha en 5432;
   - si los 4104 traen ruta y hash;
   - si los dos registros de 192.168.50.66 comparten MachineGuid, linaje o MAC.

## 3. Matriz manual

Resultado de cada caso: **OK**, **FALLO** (con captura o log) o **BLOQUEADO** (con el motivo).

### Eventos y agente

| # | Caso | Pasos | Esperado |
|---|---|---|---|
| W1 | 4104 Windows PowerShell | Ejecutar un `.ps1` propio que dispare un aviso | Evento con ruta, SHA-256, PID y SID; SCR-001 con contexto |
| W2 | 4104 PowerShell 7 | Actualizar el servicio a 0.6.1 y ejecutar un script con `pwsh` | Evento del canal `PowerShellCore/Operational` con el mismo contexto |
| W3 | Sin PowerShell 7 | En un equipo sin pwsh | Canal informado como no disponible, sin errores repetidos |
| W4 | 7045 | Reinstalar el agente con `install-sentra-agent.ps1` | UN PER-001 (7045 e inventario de la misma instalación), UNA CORR-002 |
| W5 | Agente como servicio | `Get-Service SentraAgent`; versión en Agentes | La versión del heartbeat es 0.6.1; la del `.venv` no importa |
| W6 | Atribución legítima | Registrar la operación de la reinstalación con el hash de referencia del servidor; aprobar; vista previa; aplicar | SCR-001, PER-001 y CORR-002 `verified_benign`, cerradas como mantenimiento; el riesgo baja; NET-001 sigue contando |
| W7 | Hash cambiado | Modificar una línea del script autorizado y ejecutarlo dentro de la ventana | `suspicious_unverified` con aviso de posible manipulación |
| W8 | Nombre suplantado | Crear un servicio de prueba llamado `SentraAgent2` con otro ImagePath, y borrarlo después | No se verifica |
| W9 | Fuera de ventana | Ejecutar el script autorizado tras la ventana | No se verifica |
| W10 | Veredicto del analista | Declarar `confirmed_malicious` en una detección de prueba | Historial inmutable; reevaluar no lo cambia; el riesgo sube la confianza, no la severidad |

### Sistema de ficheros y LAN

| # | Caso | Pasos | Esperado |
|---|---|---|---|
| N1 | ACL de NTFS | Revisar con `icacls` los ficheros del agente, del sensor y `REPORT_OUTPUT_DIR` | Sin cambios respecto a 7A |
| N2 | Hash de referencia CRLF | Comparar el hash del colector con el del catálogo del servidor para `install-sentra-agent.ps1` | Iguales si el servidor y el script son el mismo fichero. Si difieren (por ejemplo, finales de línea del paquete), anotarlo: la operación no se verificará |
| L1 | Descubrimiento | Escaneo de la LAN de laboratorio | `192.168.50.70` con fabricante de NIC Samsung pero dispositivo no identificado; `.78` Alexa como IoT probable; `.201` confirmado por agente |
| L2 | MAC privada | Un móvil con MAC privada | `identity_unresolved` e insignia «MAC privada»; sin fusión automática |
| L3 | Duplicado .66 | Red → Dispositivos → panel → candidatos, o `audit-7b --ip` | Clasificación con evidencia; asociar solo si es `reconcilable_identity` |
| L4 | Asociación manual | Asociar el registro de una MAC rotada a su activo con motivo y luego revocar | Alias archivado sin borrar; revocar lo restaura; dos entradas de auditoría |
| L5 | Cambio de IP | Renovar el DHCP de un equipo con agente | Mismo activo, historial de direcciones |
| L6 | Wi-Fi GX90 | Wi-Fi → Clientes → Detalle | Datos del agente (BSSID, canal, banda, señal); ninguna acción sobre el router |

### Interfaz

| # | Caso | Pasos | Esperado |
|---|---|---|---|
| U1 | 1920×1080 y 2560×1440 | Red → Dispositivos | Sin scroll horizontal de página; columnas esenciales visibles |
| U2 | Zoom 200 % | Ídem | La tabla se adapta; nada queda oculto ni recortado sin forma de verlo |
| U3 | Teclado | Tab hasta una fila, flechas, Intro, Escape | Navega filas, abre y cierra el panel, el foco vuelve a la fila |
| U4 | Preferencias | Cambiar columnas, densidad y filtros; recargar | Se conservan; «Quitar filtros» las limpia |
| U5 | Orden por riesgo | Pulsar la cabecera Riesgo y pasar de página | Orden del servidor; los activos sin cálculo al final |
| U6 | Consola | Buscar IP, MAC, hash, regla, `INC-1` y un usuario | Grupos correctos; el viewer no ve usuarios |
| U7 | Consola: acción | `case.link_evidence` desde el catálogo | Vista previa con efectos; nada ocurre hasta «Confirmar y ejecutar» |
| U8 | Añadir al caso | Desde un resultado, con tarea y responsable | Evidencia en el caso; tarea asignada con la evidencia |
| U9 | Mantenimiento | Administración → Mantenimiento con un analista | Lo ve, pero no puede registrar, aprobar ni aplicar |

## 4. Qué entregar de vuelta

- La salida de las suites y comprobaciones del apartado 1.
- `audit-7b.json` y el JSON del colector, **revisados antes de compartirlos**: contienen
  rutas, cuentas y hashes de su equipo, no secretos.
- La matriz rellenada.

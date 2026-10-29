# Fase 7B-Fix1: guía y matriz de QA en Windows

Las pruebas de la nube corren en Linux: nada de esta guía está validado en Windows físico.
Todo lo que sigue es de solo lectura sobre el equipo, salvo aplicar el parche y migrar la base
de desarrollo (que Jesus decide).

## 1. Preparación

1. Parche aplicado sobre la 7B final (MANIFEST.md de la entrega, apartado "Precondiciones").
2. Backend: `.venv\Scripts\python.exe -m alembic upgrade head` (0049 → 0050) contra la base de
   desarrollo, o antes contra una copia. `python -m alembic current` debe decir `0050`.
3. Suites (CLAUDE.md, "Comprobaciones antes de entregar"): backend, agente, sensor y frontend,
   incluido `mypy --platform win32` y `npx -y node@24`.
4. Reiniciar API y frontend. Instalar el agente 0.6.2 (después del servidor).

Referencia anterior: 3.977 pasados, 66 omitidos, 0 fallos. Los tests nuevos están en
TEST-RESULTS.md.

## 2. Comprobación local de servicios por usuario

```powershell
powershell -NoProfile -File .\scripts\qa_7b_fix1_services.ps1
```

El script no se pudo ejecutar ni analizar en la nube porque no hay PowerShell. Si da un error
de sintaxis, envíe la salida. Lo esperado es que `WpnUserService_*`, `OneSyncSvc_*`,
`CDPUserSvc_*`... salgan `verified`. Una `suspicious` debe revisarse a mano (ruta, firma) antes
de descartarla.

## 3. Matriz

| # | Área | Pasos | Esperado | Resultado |
|---|---|---|---|---|
| S1 | Instancia por usuario | Cerrar sesión y volver a entrar con el agente 0.6.2 en marcha | Sin PER-001 ni CORR-002 nuevos por `*_<sufijo>` verificados; la señal aparece en el historial de cambios | |
| S2 | Agente antiguo | Mismo caso con un agente 0.6.1 | PER-001 baja "Instancia de servicio por usuario (probable)", una por plantilla | |
| S3 | Suplantación | NO crear un servicio falso en el PC de desarrollo; usar solo los tests (`test_service_identity_fix1.py`) | Cubierto por tests; sin prueba física | |
| S4 | Instalación real | Instalar o reinstalar SentraAgent con `install-sentra-agent.ps1` | 7045 con PER-001; CORR-002 solo si hay un 4104 sospechoso antes, con `install_event_after_script` | |
| S5 | SCR-001 repetido | Ver la detección SCR-001 de la oleada de 4104 | Una detección, muchas filas de evidencia, "Contexto temporal (sin relación causal)" con los servicios cercanos | |
| S6 | Revisión v4 | Seguridad → Detecciones → "Revisar correlaciones CORR-002 anteriores a la v5" → Vista previa | Veredicto por correlación; aplicar solo con confirmación; auditoría `correlation_review_applied` | |
| R1 | Riesgo v7 | `python -m app.cli run-risk --all` y ficha de ravenslg | `formula_version` 7, "Riesgo por clase", motivos de absorción; sin puntuación fijada | |
| R2 | 5432 | Ficha del servidor, contribución de exposición | "visto solo desde el propio equipo (peso reducido)" si solo lo ve el discovery local; "accesible desde otro equipo" si lo ve un sensor; en la API, `missing: ["firewall_rules"]` | |
| R3 | 5432 desde la LAN | Desde otro equipo: `Test-NetConnection <ip> -Port 5432` (solo lectura) | Anotar si conecta: decide si la exposición es real | |
| I1 | Identidad | Red → Dispositivos → panel de un dispositivo sin agente | Niveles Confirmado/Inferido/Desconocido con fuente; "Qué falta para identificarlo" | |
| I2 | GX90 | Exportar a mano la lista de clientes DHCP del router como `ip,mac,hostname` e importarla (`generic_csv`) | Nombres DHCP en los dispositivos; nada se fusiona por MAC privada | |
| T1 | Topología | Red → Topología | Aviso "Cobertura de la topología" con nodos sin enlace y limitaciones; enlaces Wi-Fi a "Wi-Fi <ssid>" si hay BSSID | |
| D1 | Duplicados | Ciclo de vida → pares, buscar "Ravenslg Linux" | Par listado con hipótesis y motivos; reconciliar solo tras revisar | |
| C1 | Consola | Ficha de detección → "Abrir en consola" | Contexto de detección y activo cargado; "Solo herramientas compatibles" | |
| C2 | Warning NaN | DevTools → Consola, recorrer consola, activo, detección y topología | Sin "Received NaN for the children attribute". Si aparece, copiar la pila de componentes completa | |
| C3 | Responsive | Consola y tabla SOC a 1920, 1366 y zoom 200 % | Sin scroll horizontal de página | |

## 4. Qué devolver

- La salida de las suites, con el número de tests pasados, omitidos y fallidos.
- La matriz rellenada.
- El JSON del script del apartado 2, revisado antes de compartirlo.
- La pila de componentes del warning NaN, si aparece.

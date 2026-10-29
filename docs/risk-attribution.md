# Riesgo sin doble conteo y con atribución (Fase 7B.1, fórmula v6)

Complementa `docs/risk-engine.md` (fórmula 4I y sus versiones) con lo que cambia en 7B.1.
Código: `backend/app/risk/calculator.py`, `FORMULA_VERSION = 6` en `backend/app/risk/config.py`.
Pruebas: `backend/tests/test_risk_attribution.py`.

## El problema (auditoría 7B.0, H1)

Una sola instalación del agente producía estas detecciones:

- SCR-001, por el script.
- PER-001 dos veces, por el 7045 y por el inventario de servicios.
- CORR-002, por la secuencia de los dos.

El motor las sumaba como evidencia independiente. Con un activo de criticidad alta y
PostgreSQL expuesto en 5432, el riesgo llegaba a 99/100.

## Qué cambia

1. **Claves causales.** Cada detección lleva las claves de lo que la causó:
   - `script:<sha256>` o `script:<ruta>` para el script;
   - `service:<nombre>` para la instalación del servicio.

   Dos detecciones que comparten una clave forman un grupo, y en un grupo cuenta la más
   fuerte. Las demás quedan en el ledger con 0 puntos y el motivo. Así PowerShell, servicio,
   persistencia y correlación de UNA operación cuentan una vez.
2. **Una instalación, una ocurrencia.**
   - PER-001 v2: el 7045 y el inventario de la misma instalación son una ocurrencia.
   - CORR-002 v4: la correlación toma la clave de la primera señal y ya no abre dos
     correlaciones.
3. **Mantenimiento verificado.** Una detección `verified_benign` no suma riesgo activo y
   aparece en el ledger con `factor = "attribution"`, 0 puntos y `avoided_points` (lo que
   habría sumado). Las reglas de exposición (NET-001, NET-002) siguen contando aunque el
   proceso esté verificado.
4. **Confirmación del analista.** `confirmed_malicious` sube la confianza a alta. Nunca
   cambia la severidad.
5. **Componentes separados** en `breakdown.components`. No son sumables:
   - `inherent`: exposición y vulnerabilidades, lo que el activo es.
   - `active`: detecciones e inteligencia de amenazas sin verificar, lo que está pasando.
   - `residual`: la puntuación final, tras verificaciones y decisiones del analista.
   - `without_attribution`: lo que daría si nada estuviera verificado.
   - `confidence` y `verified_detections`.
6. **Motivos de reducción** en `breakdown.reductions.verified_benign` (puntos evitados).

Sin veredictos ni claves causales, el resultado es idéntico a v5
(`test_without_verdicts_or_keys_v6_equals_v5`).

## Reconstrucción del caso ravenslg

Activo de criticidad alta, una instalación del agente y NET-001 en 5432:

| Escenario | Puntuación |
|---|---|
| v5: tres grupos más PER-001 doble y NET-001 | 99 |
| v6: claves causales, sin verificar | 98 |
| v6: operación verificada | 81 (inherente 8, activo 81, sin atribución 98) |
| v6: solo la instalación, con veredicto sospechoso | 93 (una detección verdadera conserva su gravedad) |

El 81 viene casi entero de NET-001 en 5432 (puerto de base de datos, severidad alta) sobre un
activo de criticidad alta. Es riesgo real, y desaparece solo cerrando el puerto o cambiando la
criticidad, no verificando el proceso.

## Recálculo y conservación del historial

- Aplicar una operación (`POST /maintenance-operations/{id}/apply`) o dar un veredicto pide
  el recálculo del activo a la cola de riesgo de 4I. No recalcula en la petición.
- Los snapshots (`risk_snapshots`) y el historial de veredictos
  (`detection_attribution_events`) son de solo inserción. Una detección cerrada como
  mantenimiento conserva su evidencia, su veredicto y la nota con la operación.
- El cambio de fórmula no fuerza un recálculo inmediato. Los activos con score > 0 pasan a v6
  en el siguiente decay (15 min como mucho) y el resto en el refresco completo (6 h), o al
  momento con `python -m app.cli run-risk --all`. El primer cálculo v6 puede bajar
  puntuaciones sin que haya cambiado nada en el equipo. La alerta `risk_critical` solo salta
  al cruzar hacia crítico, no al bajar.

## Lo que no hace

- No cierra detecciones por estar en desarrollo ni por el nombre del proceso.
- No baja la severidad de una detección sin operación verificada.
- No agrupa detecciones sin una clave causal común: dos scripts distintos son dos grupos.

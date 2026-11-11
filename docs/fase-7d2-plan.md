# Fase 7D.2: plan (implementado: ver docs/fase-7d2.md)

> Nota (2026-11-09): implementado en 7D.2 con algunas diferencias justificadas en
> docs/fase-7d2.md (cubos de tokens en PostgreSQL en lugar del limitador por filas, heartbeat
> con cubo propio, override de minimatch 11.0.5, pip-audit solo en CI). Se conserva como
> registro del plan original.

Continuación de 7D.1 con los hallazgos H06-H08 del informe del 2026-11-05 y el
endurecimiento de la cadena de suministro. Este documento solo planifica: ningún punto está
hecho. Lo que toca la configuración de GitHub (H08) se entrega como guía y **no se aplica
automáticamente**: lo aplica Jesus a mano si lo aprueba.

Siguiente migración libre: 0052.

## H06: cuotas por agente en la ingesta

Situación actual: solo `POST /agents/register` tiene límite (`AGENT_REGISTER_MAX_PER_MINUTE`,
por IP). Heartbeat, telemetría, inventario, eventos y telemetría de endpoint no tienen
límite. Un agente comprometido o defectuoso puede llenar la base o la cola del motor de
detección.

Propuesta:

1. Cuotas por `agent_id` (no por IP: varios agentes detrás de un NAT no deben compartir
   cuota). Límites separados por endpoint, en peticiones por minuto y en bytes o
   elementos por minuto (eventos, filas de telemetría de endpoint). Ajustes opcionales
   `AGENT_QUOTA_*` fijados en conftest.
2. Implementación con el `Limiter` existente (en memoria, por proceso), que es suficiente
   con un solo proceso de API. Con varios workers, contador en PostgreSQL por ventana
   (sin Redis, por las reglas del proyecto).
3. Al superar la cuota: **429 con `Retry-After`**. El agente ya trata 429 como temporal,
   respeta `Retry-After` y guarda los datos en su buffer local; se verificará que el buffer
   tiene un tope y descarta lo más antiguo con un contador visible, no lo más reciente.
4. Observabilidad: métrica por agente de rechazos por cuota, más un aviso en el dashboard
   cuando un agente pase más de N minutos limitado.
5. Heartbeat sin cuota estricta (solo un límite alto), para que la limitación no marque el
   equipo como offline.
6. Tests: agente ruidoso limitado sin afectar a otro agente; el 429 llega con
   `Retry-After`; el agente no pierde datos dentro del tope de su buffer.

Decisión para Jesus: los valores por defecto de las cuotas (propuesta conservadora basada
en el volumen medido de sus equipos reales).

## H07: minimatch (dependencia de desarrollo del frontend)

`npm audit` (2026-11-07) informa de GHSA-g3hv-75wg-m249 (moderada, denegación de servicio por
amplificación de patrones) en `minimatch` 10.2.6, que llega por `eslint` 10.12.0 y
`typescript-eslint` 8.71.0. Es una dependencia de lint: no está en el bundle del navegador
ni en el servidor. `npm audit fix --force` propone bajar a eslint 9, lo cual es un cambio
incompatible y no se aplicará.

Propuesta:

1. Actualizar `eslint` y `typescript-eslint` a versiones que ya dependan de un `minimatch`
   corregido en cuanto existan. Si no existen todavía, usar `overrides` en `package.json`
   para fijar `minimatch` a la versión corregida, comprobando que lint y typecheck siguen
   pasando.
2. Volver a ejecutar `npm audit` y anotar el resultado en TEST-RESULTS.
3. No cambiar de herramienta de lint.

## H08: protección de ramas en GitHub (solo guía)

No se aplicará nada. Guía exacta para que Jesus decida y lo aplique a mano en
Settings → Branches → Branch protection rules (o Rulesets) del repositorio `Snowwiy/Sentra`:

| Regla | `main` | `Dev` |
|-------|--------|-------|
| Require a pull request before merging | Sí, 0 aprobaciones requeridas si Jesus trabaja solo (1 si hay más personas) | Opcional |
| Require status checks to pass | Sí: los trabajos de `ci.yml` (`backend`, `agent`, `agent-macos`, `sensor` y `frontend`) | Sí |
| Require branches to be up to date before merging | Sí | No |
| Require linear history | Opcional | No |
| Block force pushes | Sí | Sí |
| Restrict deletions | Sí | Sí |
| Do not allow bypassing the above settings | Decisión de Jesus (bloquea también al administrador) | No |

Antes de activarlo: comprobar que los nombres de los checks coinciden exactamente con los
`jobs` de `.github/workflows/ci.yml` en una ejecución reciente.

## CI: dependencias, secretos y acciones

1. **Acciones fijadas por SHA**: `ci.yml` usa `actions/checkout@v4`, `actions/setup-python@v5`
   y `actions/setup-node@v4` por etiqueta. Se sustituirán por el SHA completo del commit de
   esa versión, con la etiqueta en un comentario. Se revisará que el bloque `permissions` del
   workflow siga siendo de solo lectura.
2. **Escaneo de dependencias**: un trabajo que ejecute `npm audit --audit-level=high` en
   `frontend` y `pip-audit` sobre las dependencias fijadas de backend, agente y sensor. Al
   principio solo informa; pasa a bloquear cuando el estado inicial esté limpio. `pip-audit`
   es una dependencia nueva de desarrollo (gratuita): requiere el visto bueno de Jesus.
3. **Escaneo de secretos**: activar el secret scanning y la push protection de GitHub
   (configuración del repositorio, guía para Jesus, no se aplica automáticamente) y un paso
   en CI que busque patrones de tokens de instalación y recuperación de Sentra (`sentra_et_`,
   `sentra_et_rec_`) y claves privadas en el diff. Las credenciales de agente no llevan
   prefijo (`token_urlsafe`); se valorará añadirle uno para que sean detectables.
4. **SBOM**: generar un SBOM CycloneDX del frontend (`npm sbom`) y de cada paquete Python, y
   publicarlo como artefacto del workflow y junto a los paquetes del agente y del sensor.

## Trabajo posterior (fuera de 7D.2)

- MFA para usuarios del dashboard (TOTP), con códigos de recuperación y auditoría.
- Firma de los paquetes del agente y del sensor (Authenticode en Windows, `.deb` firmado,
  `.pkg` firmado y notarizado en macOS) y verificación en el actualizador.
- mTLS opcional entre agentes y servidor (decisión de protocolo del agente: Jesus).
- Auditoría externa de seguridad antes de cualquier despliegue fuera de la red de Jesus.

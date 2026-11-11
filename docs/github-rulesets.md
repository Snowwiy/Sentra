# Protección de `main` en GitHub (Fase 7D.2, H08)

Guía para que Jesus la aplique **a mano** en `Snowwiy/Sentra`. Nada de esto se ha configurado
automáticamente: Claude no escribe en GitHub.

Estado comprobado el 2026-11-09 con la API pública de GitHub (solo lectura):

- el repositorio es **público**: Rulesets, secret scanning y push protection están disponibles
  sin plan de pago;
- `main` **no** está protegida (`protected: false`) y no hay Rulesets (`/rulesets` vacío);
- la última ejecución de CI en `main` (run 42304220562) terminó en verde con estos jobs:
  `backend`, `agent`, `agent-macos (macos-15, arm64)`, `agent-macos (macos-15-intel, x86_64)`,
  `sensor` y `frontend`.

7D.2 añade dos jobs: `supply-chain` y `repo-hygiene`. Sus nombres solo existirán en GitHub
después de la primera ejecución del workflow nuevo: **no los marques como obligatorios hasta
que aparezcan en verde** en un PR (si no, el PR esperará para siempre).

## 1. Ruleset de `main`

Settings → Rules → Rulesets → New ruleset → New branch ruleset.

| Campo | Valor |
|-------|-------|
| Ruleset name | `main-protection` |
| Enforcement status | Active (empezar en **Evaluate** un par de días si se quiere ver el efecto sin bloquear) |
| Bypass list | **Vacía** (ver la política de recuperación más abajo) |
| Target branches | Include default branch (o Include by pattern: `main`) |

Reglas (Branch rules):

| Regla | Valor | Por qué |
|-------|-------|---------|
| Restrict creations | No | Solo afecta a crear la rama |
| Restrict updates | No | El PR es la vía de actualización |
| Restrict deletions | **Sí** | `main` no se puede borrar |
| Require linear history | Opcional (Sí si se usa "Squash" o "Rebase" al fusionar) | Historial legible |
| Require deployments to succeed | No | No hay entornos de despliegue en GitHub |
| Require signed commits | No por ahora | Requiere configurar firma GPG/SSH en el PC de Jesus |
| Require a pull request before merging | **Sí** | Nada llega a `main` sin PR |
| · Required approvals | **0** | Un único desarrollador: GitHub no deja aprobar el PR propio; con 1 nadie podría fusionar sin bypass |
| · Dismiss stale approvals | Sí | Sin efecto con 0, preparado para cuando haya revisores |
| · Require review from Code Owners | No | No hay CODEOWNERS |
| · Require conversation resolution | Sí | Un comentario abierto bloquea la fusión |
| · Allowed merge methods | Merge, Squash (lo que use Jesus hoy: los PR #8-#12 usaron merge commit) | |
| Require status checks to pass | **Sí** | Ver la lista |
| · Require branches to be up to date | **Sí** | Los checks se ejecutan sobre lo que de verdad se fusiona |
| · Do not require status checks on creation | Sí | |
| Block force pushes | **Sí** | Nadie reescribe el historial de `main` |
| Require code scanning results | No | No hay CodeQL configurado (ver "Opcional") |

Checks obligatorios (Add checks → buscar por nombre, origen **GitHub Actions**):

```
backend
agent
agent-macos (macos-15, arm64)
agent-macos (macos-15-intel, x86_64)
sensor
frontend
supply-chain
repo-hygiene
```

Antes de guardar, comprobar en la pestaña Checks de un PR reciente que los ocho nombres
coinciden **exactamente** (mayúsculas, espacios y paréntesis incluidos). Si se cambia el nombre
de un job o de la matriz en `.github/workflows/ci.yml`, hay que cambiarlo aquí también.

Nota sobre macOS: los runners `macos-15` y `macos-15-intel` son los más lentos y los primeros
que GitHub retira. Si GitHub los cambia, el check no llega y bloquea la fusión: actualizar el
workflow y el Ruleset a la vez.

## 2. `Dev` (recomendado, más ligero)

Segundo Ruleset `dev-protection`, target `Dev`: **Restrict deletions** y **Block force pushes**.
Sin PR obligatorio ni checks (Jesus hace push directo a `Dev`; CI se ejecuta igualmente en cada
push a `Dev` desde 7D.2 y avisa por correo si falla).

## 3. Secret scanning y push protection

Settings → Code security → **Secret Protection** (o "Secret scanning"): Enable. Y **Push
protection**: Enable. GitHub rechaza entonces un push que contenga un token con formato
conocido (GitHub, AWS, Slack, OpenAI...) y avisa de los ya presentes en el historial.

Lo complementa `repo-hygiene` (formatos propios de Sentra como `sentra_et_` y ficheros
sensibles). Ninguno de los dos detecta contraseñas sin formato ni las credenciales de agente
(aleatorias sin prefijo).

Opcional en la misma página: **Dependabot alerts** (avisos de vulnerabilidades en
dependencias; no crea PRs si no se activan las "security updates").

## 4. Política de recuperación administrativa

Con la lista de bypass vacía, ni siquiera el administrador puede saltarse el Ruleset por
accidente. Para una emergencia real (CI de GitHub caído, un runner retirado que bloquea todos los
PRs, una corrección urgente):

1. Anotar el motivo (issue o nota en el PR) antes de tocar nada.
2. Settings → Rules → Rulesets → `main-protection` → Enforcement status: **Disabled**
   (o quitar solo el check que falla). No borrar el Ruleset.
3. Hacer la fusión mínima necesaria por PR.
4. Volver a poner **Active** y comprobarlo (sección 5).
5. Revisar el cambio en el historial del Ruleset ("History" en la página del Ruleset) y en el
   registro de seguridad de la cuenta (Settings personal → Security log, filtrando por
   `repository_ruleset`). Comprobar que esos eventos aparecen la primera vez que se haga: el
   detalle disponible depende del tipo de cuenta.

Alternativa más cómoda pero menos estricta: añadir **Repository admin** a la bypass list con
modo **"For pull requests only"**. Permite fusionar un PR con checks en rojo (queda marcado en
el PR como bypass), pero sigue bloqueando el push directo y el force-push. Decisión de Jesus.

Lo que GitHub no permite en un repositorio de cuenta personal: exigir revisión de una segunda
persona sin tener colaboradores, ni reglas por equipo. Control compensatorio: CI obligatorio,
`REVIEW_BEFORE_PUSH.md` de cada fase y el PR como registro.

## 5. Verificación (obligatoria para cerrar H08)

Con el Ruleset activo, desde una copia de trabajo de prueba (no la de desarrollo):

```powershell
git switch -c ruleset-probe origin/main
git commit --allow-empty -m "probe: debe ser rechazado"
git push origin ruleset-probe:main          # esperado: rechazado (GH013, requiere PR)
git push --force origin origin/main~1:main  # esperado: rechazado (force push bloqueado)
git push origin --delete main               # esperado: rechazado (borrado bloqueado)
git switch Dev; git branch -D ruleset-probe
```

Y un PR de prueba con un cambio trivial: el botón de fusión debe quedar deshabilitado hasta que
los ocho checks estén en verde. Anotar el resultado en el TEST-RESULTS de 7D.

## 6. Actualizar las acciones fijadas por SHA

Las acciones de `.github/workflows/ci.yml` están fijadas por SHA completo con la versión en un
comentario. Para actualizar una (p. ej. `actions/checkout`):

1. Elegir la versión en la página de releases oficial
   (`https://github.com/actions/checkout/releases`) y leer sus notas.
2. Obtener el SHA del commit de esa etiqueta:
   `git ls-remote --tags https://github.com/actions/checkout.git "refs/tags/v4.4.0^{}" "refs/tags/v4.4.0"`
   (si aparece la línea con `^{}`, ese es el commit; si no, la etiqueta ya apunta al commit).
3. Sustituir el SHA y el comentario en **todas** las apariciones del workflow.
4. Abrir un PR: el propio CI valida la versión nueva antes de llegar a `main`.

Preferir versiones con al menos dos semanas de antigüedad. Un cambio de versión mayor (v4 → v6)
puede cambiar el runtime de Node de la acción: revisar sus notas.

Opcional: Dependabot puede proponer estas actualizaciones como PRs con el fichero de ejemplo
`docs/examples/dependabot.yml` (copiarlo a `.github/dependabot.yml`). No se incluye activo
porque crearía PRs en el repositorio sin que Jesus lo haya decidido.

## 7. Opcional

- **CodeQL** (Security → Code scanning → Set up → Default): análisis estático de Python y
  TypeScript, gratuito en repositorios públicos. Si se activa, añadir "Require code scanning
  results" al Ruleset tras la primera ejecución.
- **Private vulnerability reporting** (Settings → Code security): canal privado para que
  terceros informen de vulnerabilidades.

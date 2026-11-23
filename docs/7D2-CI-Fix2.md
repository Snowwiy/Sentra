# 7D.2-CI-Fix2: `test_systemd_unit` y avisos de unidades ajenas

Parche incremental sobre `Dev` en `9927558bcb95151cab376f58fc2a0a3c92e419a1` (7D.2 con
7D.2-CI-Fix1). Solo cambia una prueba del agente; el servicio de producción
`agent/packaging/linux/sentra-agent.service` no cambia.

## Síntoma

En el PR #13 todos los jobs pasan salvo `agent` (ubuntu-latest): 648 passed, 7 skipped,
1 failed en `tests/test_linux_packaging.py::test_systemd_unit`. El test ejecuta
`systemd-analyze verify sentra-agent.service` y trataba como error toda línea de stderr salvo
las de "is not executable". El runner devolvió:

```
/usr/lib/systemd/system/xfs_scrub_all.service:26: Support for option CPUAccounting= has been removed and it is ignored
/usr/lib/systemd/system/system-xfs_scrub.slice:15: Support for option CPUAccounting= has been removed and it is ignored
/usr/lib/systemd/system/walinuxagent.service:21: Support for option CPUAccounting= has been removed and it is ignored
```

## Causa

`systemd-analyze verify` carga también las unidades de las que depende la nuestra
(`multi-user.target`, `network-online.target` y lo que arrastran) y avisa de los problemas que
encuentra en ellas. La imagen del runner trae un systemd reciente que ya no admite
`CPUAccounting=`, y tres unidades del sistema (xfs_scrub y el agente de Azure) aún la usan. No es
un defecto de Sentra: `sentra-agent.service` no usa `CPUAccounting=` y `systemd-analyze verify`
no informa de ningún problema propio salvo el ejecutable no instalado, que ya se aceptaba.

## Corrección

El test atribuye cada línea de stderr a su origen por el prefijo que pone systemd:

- `<ruta>:<línea>: ...` (aviso de sintaxis de un fichero concreto): es propio solo si la ruta,
  resuelta, es la del fichero verificado.
- `<unidad>.<tipo>: ...` (aviso semántico de una unidad): es propio solo si la unidad es
  `sentra-agent.service`.
- Cualquier otra línea se trata como propia (falla cerrado): un formato nuevo de systemd hace
  fallar el test, nunca oculta un error.

Los avisos propios hacen fallar el test. El único aceptado es el de siempre (el ejecutable no
existe porque el paquete no está instalado), ahora limitado a comandos bajo
`/opt/sentra-agent/`: un `ExecStart` que apunte a otro sitio fallaría. Los avisos ajenos no
hacen fallar el test, pero se muestran como `UserWarning` en el resumen de pytest para que sigan
visibles.

No depende de la versión de systemd ni de una lista de opciones (no se filtra por
`CPUAccounting`): cualquier aviso de otra unidad, sea el que sea, se distingue igual. Todas las
aserciones anteriores sobre usuario, `ExecStart`, reinicios, `NoNewPrivileges`,
`CapabilityBoundingSet`, `ProtectSystem`, `ReadWritePaths`, `StartLimitBurst`, `ProtectProc` y
`WantedBy` se mantienen sin cambios.

## Pruebas de regresión nuevas

- `test_systemd_verify_output_is_attributed_to_its_unit` (9 casos): las tres líneas reales del
  runner son ajenas; el mismo aviso de `CPUAccounting=` en nuestro fichero es propio; errores
  de sintaxis y claves desconocidas en nuestro fichero, avisos semánticos de
  `sentra-agent.service`, un ejecutable fuera de `/opt/sentra-agent/` y una línea sin
  atribución son propios.
- `test_systemd_verify_still_fails_on_real_errors_in_our_unit`: con `systemd-analyze` real, una
  copia de la unidad con `Restart=sometimes` y una clave desconocida produce errores propios
  (se comprueban por fichero y número de línea, no por el texto, que cambia entre versiones).
- `test_systemd_verify_ignores_warnings_from_other_units`: con `systemd-analyze` real y
  `SYSTEMD_UNIT_PATH`, una `network-online.target` sustituta con una clave desconocida genera
  un aviso ajeno que no hace fallar el test, y la unidad real sigue sin problemas propios. Con
  el filtro anterior esa línea habría hecho fallar el test, igual que en el runner.

## Compatibilidad

El módulo `test_linux_packaging.py` solo se ejecuta en Linux (`pytestmark` existente); en macOS
y Windows sigue omitido. Las pruebas que usan `systemd-analyze` se omiten si no está instalado.
`mypy` pasa con `--platform linux`, `win32` y `darwin`.

# 7D.2-CI-Fix1: corrección de los fallos de CI del PR #13

Parche incremental sobre `Dev` en `2999f6e` (backend, frontend y agente 0.7.1, sensor 0.7.0,
migración 0052). Solo cambia pruebas y una dependencia de desarrollo del agente: el código que
se instala o se despliega (servidor, consola, agente, sensor) no cambia.

## Estado del CI en `2999f6e`

Ejecuciones 43098892045 y 43099133264 del workflow `CI` sobre el PR #13:

| Job | Resultado | Causa |
|-----|-----------|-------|
| `agent-macos (macos-15, arm64)` | fallo | 2 tests TLS (H04/H05), apartado 1 |
| `agent-macos (macos-15-intel, x86_64)` | fallo | los mismos 2 tests |
| `frontend` | fallo en una de las dos ejecuciones | test con carrera, apartado 2 |
| `backend`, `agent`, `sensor`, `supply-chain`, `repo-hygiene` | correcto | sin cambios |

El backend pasó en las dos ejecuciones (ruff, mypy Linux y win32, `alembic upgrade head` +
`alembic check`, pytest), igual que el resto de jobs: no se toca ninguno de esos módulos.

## 1. TLS en macOS: `unable to get local issuer certificate`

### Síntoma

`test_h04_https_with_a_trusted_private_ca_works` y
`test_h05_redirect_from_https_to_http_is_refused` fallan en macOS (arm64 e Intel) con
`SSLCertVerificationError: unable to get local issuer certificate`, aunque el cliente carga la
CA de pruebas con `ca_bundle`. En Linux pasan. El test que espera el rechazo
(`test_h04_untrusted_or_mismatched_certificates_are_rejected`) pasaba en macOS, pero con toda
probabilidad por el motivo equivocado: la CA ya era inutilizable.

### Causa raíz

El fixture `tls_material` generaba la CA y los certificados llamando al binario `openssl` del
PATH. En los runners de macOS ese binario es LibreSSL (`/usr/bin/openssl`), que se comporta
distinto del OpenSSL 3 de Linux en dos puntos:

1. `openssl req -x509` aplica la sección `v3_ca` de la configuración del sistema
   (`/etc/ssl/openssl.cnf`, que ya trae `basicConstraints = critical,CA:true`) y además AÑADE
   lo que llega por `-addext basicConstraints=...`. OpenSSL 3 sustituye la extensión; LibreSSL
   la duplica. La CA queda con dos extensiones `basicConstraints`.
2. `openssl x509 -req` de LibreSSL no añade `subjectKeyIdentifier` ni
   `authorityKeyIdentifier`; OpenSSL 3 sí lo hace por defecto.

El Python de los runners (python.org, OpenSSL 3) trata un certificado con extensiones repetidas
como inválido (RFC 5280, 4.2: una extensión no puede aparecer dos veces), no lo acepta como
emisor durante la construcción de la cadena y la verificación termina con "unable to get local
issuer certificate". El punto 2 habría sido el siguiente fallo: Python 3.13 activa
`VERIFY_X509_STRICT` en `create_default_context()`, que exige AKID en el certificado final
("Missing Authority Key Identifier").

Reproducción en la nube con el OpenSSL 3.5 de Python 3.13 (fuera del repositorio): una CA con
`basicConstraints` duplicada produce exactamente `certificate verify failed: unable to get local
issuer certificate`, y un certificado final sin AKID produce `Missing Authority Key Identifier`.
Con la cadena bien formada, la verificación pasa.

Límite de la comprobación: en la nube no hay macOS ni LibreSSL. El mecanismo (CA con extensión
repetida → "unable to get local issuer certificate") está reproducido con el mismo OpenSSL que
usa Python; que LibreSSL genere esa CA es la explicación coherente con el log y con su
comportamiento conocido, pero solo quedará confirmado cuando los jobs `agent-macos` pasen en
GitHub Actions. La corrección no depende de esa explicación: elimina el binario por completo.

No es un fallo del agente: `tls_context_with()` verifica bien. Es material de prueba mal
formado que solo se generaba así en macOS.

### Corrección

`agent/tests/test_transport_7d1.py` genera ahora la CA y los dos certificados de servidor con
la biblioteca `cryptography`, con cada extensión declarada una sola vez y de forma explícita:

- CA: `BasicConstraints(ca=True, path_length=0)` crítica, `KeyUsage` (keyCertSign, cRLSign)
  crítica, `SubjectKeyIdentifier`.
- Servidor: `BasicConstraints(ca=False)` crítica, `KeyUsage` (digitalSignature) crítica,
  `ExtendedKeyUsage` serverAuth, `SubjectAlternativeName` (`IP:127.0.0.1` para el bueno,
  `DNS:other.example` para el de nombre ajeno), `SubjectKeyIdentifier` y
  `AuthorityKeyIdentifier` enlazado con el SKI de la CA.
- Claves EC P-256 (rápidas en los cuatro sistemas) y validez de dos días con cinco minutos de
  margen hacia atrás por posibles diferencias de reloj.

Así el material es idéntico en Linux, macOS y Windows, no depende del binario ni de su
configuración, y el bloque TLS deja de omitirse en Windows cuando no hay `openssl` instalado.

Nuevo test de regresión `test_tls_material_has_unique_extensions_and_a_linked_chain`: comprueba
que ningún certificado repite extensiones, que la cadena está enlazada por SKI/AKID y que los
certificados finales los firmó la CA.

`cryptography>=50,<51` pasa a ser dependencia de desarrollo del agente (`[dev]`), la misma serie
que ya usan el backend y el extra `snmp` del sensor. El agente instalado no la usa ni la
empaqueta. Alternativa descartada: seguir con el binario y una configuración propia
(`-config`), porque seguiría dependiendo de las diferencias entre LibreSSL y OpenSSL y de que
exista `openssl` en Windows.

### Lo que no cambia

- `agent/sentra_agent/client.py` y el resto del agente: verificación estricta del certificado y
  del nombre, cadena de confianza, rechazo de certificados inválidos, TLS 1.2 mínimo, bloqueo
  de redirecciones (incluida HTTPS → HTTP) y raíces del sistema en macOS.
- Los tests negativos siguen exigiendo `TlsError` sin la CA privada y con un certificado de la
  CA para otro nombre, y que el token nunca llegue al servidor.
- Ningún test se omite ni se marca como fallo esperado.

## 2. Frontend: `Found multiple elements with the text: Cambio de IP`

### Síntoma y causa

`NetworkPage.test.tsx`, test "los cambios de identidad mezclan los tipos de identidad por
fecha". El panel "Cambios de identidad" tiene un selector "Tipo de cambio" cuya opción
`Cambio de IP` existe siempre. La prueba esperaba con `findByText("Cambio de IP")`:

- si las filas aún no habían llegado, encontraba solo la opción, seguía adelante y las
  comprobaciones de las filas podían fallar;
- si ya habían llegado, encontraba la opción y la celda y fallaba con "Found multiple
  elements".

Es una carrera de la prueba, no un fallo de la interfaz, y ocurre con Node 22 y con Node 24
(con el código original falló 3 de 5 ejecuciones en Node 22 y 4 de 5 en Node 24 en la nube).
Es el fallo intermitente de "cambios de identidad" que ya se había observado en 7D.1.

### Corrección

La prueba espera a la celda de la tabla: `findByRole("cell", { name: "Cambio de IP" })`. Solo
hay una, y su aparición garantiza que las filas ya se pintaron. La interfaz no cambia. Con el
cambio, 10 de 10 ejecuciones en Node 22 y 10 de 10 en Node 24.

## 3. Resto de jobs y Windows en CI

- `backend`, `agent` (Linux), `sensor`, `supply-chain` y `repo-hygiene` pasaron en el PR #13: no
  se modifican. El aviso "Node.js 20 is deprecated" de las acciones fijadas no hace fallar
  ningún job; actualizar los SHA es una tarea aparte (docs/github-rulesets.md).
- `supply-chain` audita también los extras del agente: con `cryptography` añadida, `pip-audit`
  sobre los requisitos del agente no encuentra vulnerabilidades.
- Cobertura nativa de Windows en GitHub Actions: no se añade en este parche. Un job
  `agent-windows` nuevo no se ha podido ejecutar nunca en un runner real y podría dejar el PR en
  rojo por motivos ajenos a estos fallos; además el Ruleset de `main` tendría que incluirlo.
  Se propone como tarea propia (agente y sensor en `windows-latest`, primero sin ser
  obligatorio).

## Restricciones respetadas

Sin cambios en migraciones (0051, 0052), versiones, credenciales, configuración privada,
controles H01-H08, sensor SNMP ni código de producción.

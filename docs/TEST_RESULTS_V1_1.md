# Resultados Backend V1.1 — propuesta, 30-10-2026

Entorno: Linux x86_64, Python 3.12.14, Docker 28.4.0, PostgreSQL real **16.15** con
la misma imagen/digest del Database V1 original. No se usó SQLite ni base persistente.
Dependencias de V1 conservadas; versión de aplicación/paquete 0.1.1.

## Ejecuciones verificadas

| Comando/comprobación | Resultado |
|---|---|
| Suite V1 antes de editar | **37 passed**, salida 0; commit 578f74a intacto |
| Etapa de migración/guard | **44 passed**, salida 0; commit 8023bb4 |
| `DATABASE_V1_PATH=/tmp/vuln-track-database python scripts/test_postgres.py -q` | **56 passed**, sin skips/fallos, 21.61 s |
| `python -m pytest -q` sin PostgreSQL | **25 passed, 31 skipped**, salida 0 |
| SQL original `001_integrity.sql` antes de migrar | **55 comprobaciones** (20 positivas/35 rechazos), salida 0 |
| `ruff check .` | All checks passed |
| `python -m pip check` | No broken requirements found |
| `python -m compileall -q app alembic scripts` | Salida 0 |
| `python -m alembic heads` | `0002_asset_owner (head)` |
| Alembic `upgrade`, `check` sobre desechables | Aprobados, sin recreación de tablas |
| `git diff --check` | Sin errores |
| Docker build `vulntrack-backend:v1.1` con CA del proxy montada | Aprobado |
| Runner `--docker-smoke` sobre V1.1 migrado | UID 10001, health/ready/login 200; creación/replay 201; detalle/lista propios 200 |

Suite final: `vulntrack-backend-test-b3b9bb6897b7`.
Smoke de imagen: `vulntrack-backend-test-775115708041`, imagen SHA-256
`81a9624cff73b84ac6bee8b1ce942b17f2d01930a597b3128924e270b66c3df4`. Los comandos Python/Ruff usaron
`.venv/bin/`. Todos los contenedores de pruebas son nuevos con tmpfs; las bases copiadas
para migraciones viven dentro de ese mismo servidor. Se detienen al finalizar y no se
alteran volúmenes persistentes. El runner comprueba hashes de referencias antes de aplicar
SQL y únicamente después añade el grant de hash al login temporal dedicado.

Advertencia observada y no ocultada: Starlette 1.10.0 depreca TestClient con httpx,
aunque las pruebas con httpx 0.28.1 pasan. Revisar transición al actualizar dependencias.
La advertencia Alembic de path_separator se resolvió configurando `path_separator=os`.

## Migración e integridad

- V1 sin versión, reconocimiento 0001, revisión ya 0001 y upgrade a 0002.
- Columna nullable UUID, FK RESTRICT e índice esperado; catálogo y ORM sin drift.
- Mismos IDs/datos/fechas y OID de tabla: sin recreación, sin backfill ni modificaciones
  de seed. Todos los históricos siguen created_by NULL.
- Ejecución repetida no repite DDL. Sin reconocimiento explícito de propuesta, upgrade
  0002 se rechaza conservando V1; revisiones desconocidas o columnas inesperadas se rechazan.
- Stamp ciego a 0002 falla y no deja revisión falsa. Downgrade que perdería propiedad se bloquea.
- Fallo inyectado después de DDL revierte columna/FK/índice y revisión en una transacción.
- SQL equivalente de docs/proposals aplicado en otra copia desechable produce exactamente
  el catálogo V1.1 y conserva históricos; no asigna una revisión Alembic por su cuenta.

## Autorización e idempotencia reales

Ningún test V1.1 sustituye la política ni current_user. Se retiró FixtureAuthorization.
Usuarios de prueba nuevos, Argon2id/JWT, login SQL mínimo y PostgreSQL real:

- Registro autenticado asigna actor como created_by; sin identidad devuelve 401.
- created_by del cliente, incluso null o ID propio, devuelve 422 sin escribir.
- Detalle propio 200; ajeno/sin dueño/inexistente 404; listado y total solo propios,
  paginación vacía/orden estable y filtro SQL por owner comprobado.
- Misma clave/actor/payload: snapshot/Location/201 idénticos. Otro payload: 409.
- B reutiliza clave de A: ámbito independiente y activo propio, nunca snapshot de A;
  consulta directa cruzada denegada. Misma información de inventario no comparte activos.
- Dos peticiones API autenticadas sincronizadas antes de insertar solicitud: misma clave
  crea un solo activo/solicitud/propietario. Claves distintas crean dos; misma clave con
  payload distinto produce 201/409. Se verifica created_by=solicitud.user_id persistido.
- Error antes de commit revierte activo/owner/solicitud; retry con misma clave funciona.
- Pérdida simulada de respuesta tras commit se recupera sin duplicar.
- Revocación explícita de propietario en prueba impide replay antes de revelar conflicto
  o expiración. Usuario desactivado no puede consultar/listar/crear/repetir.
- Un registro idempotente histórico de A sobre un activo sin dueño NO le concede propiedad.
- Expiración no concede acceso cruzado ni reutiliza una fila vencida.
- FK a usuario inexistente y borrado de usuario propietario se rechazan; login runtime no
  puede reasignar owner, borrar activos ni crear tablas. Pool limitado y timeouts V1 pasan.
- Readiness V1.1 devuelve 503 frente a una copia V1 aún sin migrar; health sigue 200.

## Fallos intermedios corregidos

Al mover el fixture de bases legadas faltó importar `text`: una ejecución dejó 48
pruebas aprobadas y 8 errores de preparación. Se corrigió el import y se repitió desde
otro contenedor nuevo: 56 aprobadas. No se relajaron pruebas/checks ni se ocultaron errores.
Instalación editable sin aislamiento falló por ausencia local de setuptools; el mecanismo
normal con aislamiento instaló correctamente 0.1.1 y pip check pasó.

## Limitaciones y evidencias anteriores

V1 permanece documentado en [TEST_RESULTS_V1.md](TEST_RESULTS_V1.md), como evidencia
histórica, no descripción del comportamiento actual. El fallo de mounts del runner
upstream fue documentado allí; este runner usa sus mismos SQL inmutables por stdin.
No se afirma haber repetido persistencia/reinicio del runner original de Database.

No se probó desconexión TCP real durante commit, carga, recuperación de backup, integración
móvil/web ni producción multiworker/TLS remoto. Política de propietario y coordinación
Database requieren aprobación formal. No se tocaron GitHub/credenciales ni se ejecutaron
NVD/ZAP/escaneos. No hay preparación para producción declarada.

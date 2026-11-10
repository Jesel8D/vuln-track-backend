# Resultados reales — 30-10-2026

Entorno Linux x86_64, Python 3.12.14, Docker Engine 28.4.0, Compose 2.40.3.
PostgreSQL real **16.15**, imagen/digest idénticos al Compose de Database V1.
Dependencias instaladas y fijadas en los dos lockfiles. No se usó SQLite.

## Resultado de la suite final

| Comando | Resultado |
|---|---|
| `python -m pytest -q` (sin variables PostgreSQL) | **25 passed, 12 skipped**, salida 0; skips explícitos de integración |
| `DATABASE_V1_PATH=/tmp/vuln-track-database python scripts/test_postgres.py -q` | **37 passed**, salida 0; ninguna omitida ni fallida |
| `ruff check .` | All checks passed |
| `python -m pip check` | No broken requirements found |
| `python -m compileall -q app alembic scripts` | Salida 0 |
| `python -m alembic heads` | `0001_database_v1 (head)` |
| Alembic `upgrade head`, `check`, invocados por test con PostgreSQL temporal | Salida 0, sin operaciones de cambio de esquema V1 |
| `git diff --check` | Sin errores |
| Build Docker con CA de proxy montada como secret | Salida 0 |
| Runner `--docker-smoke` | UID 10001, `/health` 200, `/ready` 200 con PostgreSQL real |

Python/pytest/ruff se ejecutaron desde `.venv/bin/`. Ejecución final completa:
`vulntrack-backend-test-1004426efccd`, **37 passed en 8.18 s**.
Cada runner crea un contenedor nuevo con tmpfs y puerto aleatorio solo en localhost;
se detiene al terminar y no modifica volúmenes persistentes.

Advertencia de dependencias observada: Starlette 1.10.0 depreca TestClient con httpx
frente a httpx2. Las pruebas con httpx 0.28.1 pasan; no se ocultó el aviso ni se añadió
una dependencia extra solo para suprimirlo. Revisar esa transición al actualizar el stack.

## Evidencia cubierta

- Validación de requeridos, tipos estrictos, límites, extras, NFC/null/control/surrogates.
- Configuración insegura rechazada, DB TLS obligatorio en producción.
- Hash Argon2id válido/incorrecto/ausente/malformado/parámetros abusivos, JWT firmado,
  manipulado, vencido, claims obligatorios, issuer/audience y TTL; limiter por cuenta.
- HTTP health y readiness fallida sin DB; errores uniformes, cuerpo grande/chunked,
  JSON inválido y logs de excepción sin el mensaje secreto inyectado.
- Login/me con PostgreSQL y credencial de app mínima; credenciales incorrectas, seed
  inactivo, desactivación y reactivación invalidando JWT previo.
- Verificación de catálogo, PK/FK/tipos/defaults/checks/índices/triggers/funciones;
  baseline y ausencia de drift Alembic. Drift de columna bloquea el verificador.
- Denegación productiva 403/404 de activos. La clase real no permite accesos positivos.
- Registro/detalle/lista API bajo **ámbito sintético de fixtures** y autenticación real;
  paginación con página vacía conservando total; 404 ajeno/inexistente; idempotency key
  con formato/longitud inválidos y payload inválido.
- Dos solicitudes simultáneas a servicio con misma clave, barrera en inserción del
  registro: ambas atraviesan el SELECT de ausencia. Una sola alta/solicitud confirmadas,
  snapshot idéntico. Claves distintas crean dos activos; misma clave en usuarios distintos
  tiene ámbitos separados; payload diferente devuelve conflicto.
- Fallo después de insertar activo y antes de commit: todo revierte; mismo intento se
  recupera. Resultado ya confirmado descartado por el cliente: repetir devuelve snapshot.
- Clave vencida denegada sin crear otro activo; permiso revocado impide replay.
- Integridad referencial y prohibición al login runtime de DELETE/DDL; agotamiento de
  pool limitado por timeout de 1 s en la prueba.

## SQL de referencia verificado

Se aplicaron **sin modificaciones** `001_schema.sql`, `002_privileges.sql`, el seed y
`tests/001_integrity.sql` del commit b493fd1. Comprobaciones contadas sobre el archivo:
**20 assert_true + 35 expect_error = 55**, ejecutadas con ON_ERROR_STOP y salida 0.
La suite original verifica restricciones, privilegios y deja rollback de sus datos.
El grant de lectura de hash del login de pruebas se realiza DESPUÉS de esa suite;
no se concedió al grupo vulntrack_app ni se cambiaron sus pruebas.

El runner original `bash tests/run.sh` se intentó y **falló antes del bootstrap**:
los directorios clonados de referencia tienen permisos que el UID PostgreSQL de su
contenedor no puede leer. Se conservaron los archivos y su seguridad; el runner del
backend transmite el mismo SQL por stdin a psql y usa tmpfs desechable. No se afirma
que se repitieran las pruebas de persistencia/reinicio de aquel runner original.

## Fallos detectados y corregidos

Durante la implementación: conexión prematura al servidor temporal de initdb (se espera
ahora TCP), comparación de representación TIMESTAMPTZ (ambos lados se compilan con
dialecto PostgreSQL), comentarios ORM faltantes (se conservaron los originales),
y archivos de imagen no legibles por UID 10001 (lectura de código estático en Dockerfile).
Se repitieron las verificaciones correspondientes hasta pasar. No se cambiaron checks,
seeds ni pruebas upstream para forzar éxitos. No quedan fallos de pytest o Ruff conocidos.

## Pendiente/no ejecutado

Acceso positivo con una política de permisos productiva, móvil/web reales, desconexión
TCP durante commit, retención/reconciliación operativa, carga, restauración de backup,
TLS remoto y despliegue multiworker. Los ámbitos positivos de fixtures no prueban una
propiedad de activos ausente en Database V1. V1 no está aceptado como completo.
No se ejecutaron escaneos, NVD, ZAP ni cambios remotos en GitHub.

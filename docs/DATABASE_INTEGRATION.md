# Integración con PostgreSQL Database V1

Fuente: rama `feat/postgresql-database-v1`, commit
`b493fd17e9290ca94fa085d49230073ed1837e1a`. `sql/001_schema.sql` SHA-256
`fd2984a80911cd094283d9c9b1f503a7a0db87b921f9169c2a8362a8941b9297`.

Database conserva bootstrap, Compose, seeds y su SQL. Backend mapea UUID, TEXT,
BOOLEAN, TIMESTAMPTZ, SMALLINT y JSONB de las cinco tablas `vulntrack`. No se agregan
columnas. PK compuesta de solicitudes: `(user_id,method,route,idempotency_key)`.
Cinco FKs ON DELETE RESTRICT, UNIQUE username, checks y cinco índices secundarios se
mantienen. No hay cascadas ORM. Timestamps usan defaults/trigger del servidor.
El hash de usuario es deferred y solo se lee en login. El rol app carece de UPDATE/DELETE
de activos; nuestro algoritmo no los necesita.

## Baseline seguro

`database_v1_catalog.json` es una fotografía de catálogo obtenida cargando el SQL
referenciado en PostgreSQL 16.15 desechable. No es bootstrap ni segunda definición de
DDL: cambiarlo no actualiza PostgreSQL. El runner comprueba hashes de las referencias.
Su captura explícita `--catalog` solo sirve para revisión al evolucionar la integración.
No recapturar para esconder drift.

`verify_schema` compara columnas/defaults, checks/PK/FK/UNIQUE, índices, funciones,
triggers y flags RLS con esa fotografía. Además contrasta ORM con tipos/nulabilidad,
PK/FK, checks mediante expresiones EXPLAIN sin ANALYZE y comparación Alembic con
server defaults. Las inspecciones son de lectura; no ejecutan DDL. No certifican
políticas de usuarios ni todas las configuraciones del servidor.

```bash
# Con .env del login API:
python -m app.db.verify_schema
# En una copia restaurada, con URL administrativa mantenida fuera del repositorio:
read -rsp 'URL de mantenimiento: ' MIGRATION_DATABASE_URL; echo
export MIGRATION_DATABASE_URL
alembic upgrade head
alembic check
unset MIGRATION_DATABASE_URL
```

Primero identificar instalación/volumen/versión, backup con `pg_dump -Fc`, restaurar
en una copia nueva y ejecutar SQL de integridad allí. Revisar la correspondencia y
el resultado antes de repetir en la instalación objetivo. No hay `stamp` a ciegas:
la revisión `0001_database_v1` no recrea tablas; env.py verifica **antes** de registrar
la línea base. Alembic solo crea su tabla técnica de versión en public, usando login
de mantenimiento, nunca login API. Modo offline y downgrade de baseline están bloqueados.
Si falta esquema o difiere, la operación se detiene. No reaplicar bootstrap sobre datos.

Este guard corresponde exclusivamente a V1. Para migraciones futuras habrá que extenderlo
por versión de partida/destino, revisar DDL y probar restauraciones. El guard actual
rechaza esquemas V2; no es un mecanismo universal de evolución automática.

## Conexiones

Engine por proceso, QueuePool configurable, pre-ping, recycle, connect_timeout,
statement_timeout, lock_timeout e idle_in_transaction_session_timeout (15 s).
Sesiones se cierran con context managers; escrituras usan begin. La aplicación rechaza
roles administrativos y miembros con uso del rol dueño del esquema en cada nueva
conexión. No loguea parámetros SQL. Pool/locks/timeout se traducen a 503 cuando corresponde.
Los límites se multiplican por número de workers; no desplegar múltiples workers sin
calcular max_connections y una cuota de login compartida.

Readiness comprueba tablas y rol efectivo. No prueba Argon2 ni resolución de permisos,
ni ejecuta el verificador exhaustivo en cada sondeo. Verificación exhaustiva es un
paso explícito de integración/baseline. Puerto Database solo en localhost, nunca público.

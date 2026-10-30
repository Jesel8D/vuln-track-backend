# Database V1 y propuesta Backend V1.1

Referencia intacta: `feat/postgresql-database-v1`, commit
`b493fd17e9290ca94fa085d49230073ed1837e1a`. SQL V1 SHA-256
`fd2984a80911cd094283d9c9b1f503a7a0db87b921f9169c2a8362a8941b9297`.
Context `dev/jesel`, commit `d481061e5ecb53b9a033086481add37f04d8c549`.
D-001/D-002 sin cambios. No se editaron referencias ni instalaciones persistentes.

V1: cinco tablas, cinco FKs restrictivas, UUID/TEXT/BOOLEAN/TIMESTAMPTZ/SMALLINT/JSONB,
PK compuesta de idempotencia, UNIQUE username y checks originales. V1.1 propone una
columna nullable UUID created_by en assets, sexta FK restrictiva a users y un índice
`(created_by,created_at,id)`. Nada más se altera: defaults, triggers, checks, seed y
privilegios del grupo técnico permanecen. No hay backfill ni RLS nueva.

Backend requiere la migración explícita; no se ejecuta create_all/DDL al arrancar.
El dueño técnico administra esquema; API usa login mínimo, SELECT/INSERT de activos,
sin UPDATE/DELETE/DDL. La lectura del hash para login continúa como grant separado
al login dedicado, no al grupo original. Tras migrar, SELECT/INSERT existentes cubren
la nueva columna; no se amplían permisos administrativos.

El catálogo original permanece en database_v1_catalog.json, sin cambios. Se deriva el
delta V1.1 en código para validar ambas versiones sin duplicar el bootstrap de Database.
El guard rechaza revisiones Alembic desconocidas/múltiples, catálogo inesperado y stamps
incompatibles. En head se compara también ORM/defaults/índices/checks. Una comprobación
fallida después del DDL revierte columna, FK, índice y revisión en la misma transacción.

Ver [procedimiento y coordinación](MIGRATIONS.md). Las instalaciones existentes usan
Alembic; el SQL equivalente en docs/proposals es solo material de revisión para Database.
Nunca aplicar ambos mecanismos sobre la misma instalación. El patch de bootstrap y su reconocimiento verificado se prepararon/probaron en V1.2;
siguen pendientes de aprobación y coordinación antes de publicarse. Véase
[contrato de coordinación](DATABASE_V1_1_COORDINATION.md).

Configuración de conexiones: engine por proceso; pool 5+5, pre-ping y recycle;
connect_timeout, statement_timeout, lock_timeout e idle_in_transaction_session_timeout.
Sesiones síncronas/context managers, rollback automático. Roles administrativos y
miembros del rol dueño del esquema se rechazan en nuevas conexiones. Producción exige
verify-full y CA; desarrollo usa localhost. Puerto Database nunca público.

Readiness comprueba rol y columnas esenciales, incluida created_by; V1 sin migrar devuelve
503. No verifica el catálogo completo en cada sondeo ni acredita aprobación del diseño.
El verificador exhaustivo es explícito: `python -m app.db.verify_schema` para V1.1 o
`--revision 0001_database_v1` para lectura V1. No cambia tablas ni baseline.

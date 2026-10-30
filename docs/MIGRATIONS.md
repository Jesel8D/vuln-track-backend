# V1.1: migración de propiedad propuesta

Estado **PROPUESTA**, pendiente de aprobación formal y coordinación con Database antes
de integrar/desplegar. Esta misión permite su ejecución únicamente en PostgreSQL
desechable. No se modificó ninguna instalación persistente ni repositorio externo.

La revisión `0002_asset_owner`, hija de `0001_database_v1`, añade:

- `vulntrack.assets.created_by uuid NULL`, sin default ni UPDATE/backfill.
- FK `assets_created_by_fkey` a `vulntrack.users(id) ON DELETE RESTRICT`.
- Índice `(created_by, created_at, id)` para filtro por propietario, orden y soporte FK.

NULL conserva sin propietario los datos previos; no equivale a un permiso público.
La propiedad no se infiere de solicitudes idempotentes ni análisis históricos. El login
API conserva sus privilegios V1: SELECT/INSERT sobre assets, sin UPDATE/DELETE ni DDL.
No se habilita endpoint de asignación/reasignación de históricos.

## Guard de esquema y revisión

El catálogo de referencia V1 permanece inmutable. El verificador deriva el catálogo
esperado V1.1 añadiendo exclusivamente columna/FK/índice. Compara el esquema real con
la versión instalada y contrasta ORM completo al llegar a V1.1. V1 se verifica contra
el catálogo original, porque el ORM nuevo ya necesita la columna de propietario.

Antes de DDL: reconocer revisión instalada (ninguna, 0001 o 0002), rechazar revisiones
múltiples/desconocidas, verificar el esquema de partida. Una base sin versión solo
puede reconocerse como V1 si su catálogo coincide. `0001` sigue sin recrear tablas.
Antes de confirmar DDL: volver a verificar destino y ORM; fallo revierte cambios y
revisión juntos. Se acotan espera de locks (5 s) y sentencias (60 s).

La migración necesita `-x ownership_proposal=1`: reconocimiento explícito de que se
está ejecutando una propuesta, **no** una aprobación arquitectónica ni permiso para
operar una base persistente. El runner lo usa únicamente contra tmpfs nuevo.

```bash
DATABASE_V1_PATH=../vuln-track-database python scripts/test_postgres.py -q
```

El runner ejecuta primero SQL/privilegios/seed e integridad originales; congela una
copia V1 dentro del mismo servidor desechable y migra la base de pruebas a head. Las
pruebas de migración clonan esa copia y verifican históricos, FK, índices, idempotencia
de ejecución, drift, revisión desconocida, stamp ciego y rollback DDL ante fallo inyectado.

## Instalaciones existentes — procedimiento futuro tras aprobación

1. Aprobar política y DDL; identificar instancia, volumen y revisión actual. Detener
   escrituras y coordinar la versión API; no ejecutar el procedimiento sobre un destino
   cuyo carácter/backup no esté comprobado.
2. Backup, restauración en copia nueva y validación íntegra V1. Verificación de lectura:
   `python -m app.db.verify_schema --revision 0001_database_v1` con URL del login API.
3. Con login de mantenimiento externo, en la copia: `alembic current`, después
   `alembic -x ownership_proposal=1 upgrade head`, `alembic check` y verificador por
   defecto V1.1. Confirmar que los IDs/datos históricos se conservan y created_by es NULL.
4. Ejecutar suite funcional, integridad y revisión de permisos; programar después la
   integración aprobada. No copiar la URL administrativa al proceso API ni al repositorio.
5. No usar `stamp head` para evitar migraciones. Un stamp incorrecto revierte ante la
   verificación de destino; un esquema inesperado bloquea la operación.

Downgrade a V1 está bloqueado porque eliminar la columna perdería propiedad. Un rollback
de operación fallida es transaccional; una reversión de release requiere restauración
aprobada o migración hacia adelante revisada, no DROP de datos de autorización.

## Coordinación de fuentes (D-002)

Backend conserva ORM/Alembic. Database conserva bootstrap/SQL/seed/documentación.
El fragmento [SQL equivalente](proposals/database-v11-ownership.sql) es una propuesta
para comparar estados finales, no otra migración a ejecutar junto a Alembic.

Tras aprobación, preparar en Database una rama revisable que actualice:
`sql/001_schema.sql` (columna/FK/índice para instalaciones nuevas), `docs/SCHEMA.md`,
`docs/PROVISIONAL_DECISIONS.md`, `docs/TEST_RESULTS.md`, diagrama y pruebas SQL. Conservar
seed sin dueños por defecto; extender pruebas de integridad para NULL, FK y RESTRICT.
`002_privileges.sql` no necesita ampliar privilegios para propiedad. Su grant de hash
continúa como decisión separada. No reaplicar 001 sobre volúmenes existentes.

Para evitar divergencia: primero verificar la equivalencia del nuevo bootstrap contra
el mismo catálogo V1.1 y ORM, fijar su commit/digest y coordinar versiones antes de
promoverlo. Hasta diseñar/probar el reconocimiento explícito de un bootstrap V1.1 sin
historial Alembic, este backend **solo admite la ruta bootstrap V1 → migración Alembic**.
Un bootstrap ya V1.1 sin versión se rechaza; no se soluciona con stamp a ciegas. Esto
queda como puerta de la coordinación futura, no se publica un bootstrap incompatible.

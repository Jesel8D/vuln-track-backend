> **Rama MVP-A:** ver [contrato actualizado](MVP_A.md). Incluye versión nullable, CPE e historial y revisión 0003. Las secciones V1 siguientes conservan el antecedente.

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

La preparación V1.2 cierra la puerta técnica para un bootstrap V1.1 sin historial:
[DATABASE_V1_1_COORDINATION.md](DATABASE_V1_1_COORDINATION.md) documenta las dos rutas,
el patch derivado del SQL original y `python -m app.db.adopt_schema --confirm-proposal`.
Esa herramienta solo reconoce un catálogo/ORM V1.1 exacto sin revisión (o ya en 0002),
verifica antes y después y no reemplaza una revisión V1 existente. No es stamp ciego.

Alembic y adopción se serializan con un advisory lock de transacción cooperativo. La
adopción bloquea las tablas durante verificación/reconocimiento. Se rechazan también
triggers deshabilitados; el catálogo original no se reescribe. No sustituye una ventana
de mantenimiento ni protege frente a DDL externo de un administrador hostil. La ruta
V1 existente sigue usando exclusivamente Alembic; nunca ejecutar el ALTER informativo
además del bootstrap o la migración. Ambas rutas se ensayaron en contenedores nuevos.

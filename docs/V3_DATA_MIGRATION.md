# Migración aditiva RC2.4 a RC3

La fuente SQL canónica es `sql/014_v3_device_revisions.sql` de Database. Backend conserva una copia con su SHA-256 en `app/db/v2_source_manifest.json` y la ejecuta mediante `v2_0007_device_revisions` después de `v2_0006_cpe_quarantine`.

Se añaden columnas de versión y generación con valor inicial 1, un registro de revisiones con RLS forzada, un índice de identificación por generación y una instantánea opcional en las consultas. Los UUID y datos anteriores se conservan. Los historiales anteriores a RC3 conservan sus registros disponibles. No se atribuye autor ni motivo a ediciones pasadas que el sistema no registró. La primera edición en RC3 conserva la versión 1 como su estado anterior.

El bootstrap nuevo y la ruta existente cargan los SQL de Database y la cadena Alembic. Ensaya primero sobre la copia independiente de RC3. Los perfiles anteriores conservan su versión y volumen. Para restaurar usa un destino nuevo y verifica los manifiestos y el espacio antes de arrancar. [Arranque](V3_LOCAL_RUN.md) · [Custodia](V3_BACKUP_CUSTODY.md)

La reversión operativa consiste en volver a servir la instalación RC2.4 independiente mientras se conserva el volumen RC3 para investigación y recuperación. La migración bloquea una reversión que eliminaría revisiones. Para llevar datos nuevos a otra versión se requiere un procedimiento explícito que mantenga actor, UUID, generaciones e instantáneas.

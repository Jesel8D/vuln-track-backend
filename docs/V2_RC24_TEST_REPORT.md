# Resultados de pruebas de RC2.4

Ejecuciones nuevas del 22 de noviembre de 2026 sobre los worktrees de RC2.4 y destinos separados.

| Grupo | Resultado |
|---|---|
| Backend | **784 aprobadas por ruta**, existing y new. Una advertencia de deprecación de Starlette por ruta. |
| PostgreSQL | **147 comprobaciones por ruta**. SQL013 añadió cuatro. La prueba de migración inició explícitamente en `v2_0005_cpe_summary` y aplicó `v2_0006_cpe_quarantine`. |
| Frontend | **98 pruebas**, TypeScript, ESLint y build aprobados. |
| Chromium | **12 de 12** en creación y **1 de 1** en sesión existente. Pasaron los cuatro anchos y las comprobaciones axe. |
| Newman | Existing 96 solicitudes y 351 aserciones. New 95 y 346. Contrato persistente 50 y 185. Cero fallos. |
| OpenAPI | 65 operaciones, 92 solicitudes de la colección, 28 cuerpos y 70 ejemplos. El documento ejecutado coincide con el versionado. SHA-256 `f7c9a0c47efbaabd313782d90723406102b17ad9845c8af67b6e06bda5d26174`. |
| CodeQL | CLI ausente en los entornos locales comprobados. Ejecutaron Ruff, ESLint, verificaciones de esquema y pruebas de seguridad de aplicación. |

Las primeras corridas detectaron dos problemas y se repitieron tras corregirlos. La ruta de restore heredada debía comprobar el destino antes de leer el manifiesto. El test de navegador debía aplicar la simulación al abrir el detalle sin recargar una sesión deliberadamente temporal.

## Respaldo y restauración

- La copia de RC2.3 obtuvo una recuperación de WAL desde PGDATA de solo lectura. El contenedor original permaneció detenido. Se cifró el dump y se autenticó el archivo completo antes de restaurarlo.
- El volumen nuevo `vulntrack_v2_rc24_full_restore_ram_pgdata` recuperó los **1 880 952 CPE oficiales y un fixture**. Se compararon los hashes de los datos en 25 tablas privadas que sumaban 231 filas, la huella de catálogo, los recibos, resúmenes y las políticas RLS. Coincidieron todas las comparaciones.
- La restauración que produjo esa evidencia tardó **90,08 s** desde el inicio de la carga transaccional. El PostgreSQL restaurado midió 2 477 702 167 bytes y el volumen usó 3 021 418 496 bytes tras la prueba.
- Tras la comparación, SQL013 y la cuarentena se comprobaron en ese destino. Dos escrituras idempotentes dejaron **1 880 952 CPE**, **una evidencia en cuarentena**, **cero candidatos con ese UUID** y el título con `lang=en`.
- El comando reutilizable recuperó en **1,10 s** el respaldo piloto de **277 349 bytes**, con **13 CPE oficiales, un fixture y 49 políticas**. Los ensayos RAM se detuvieron al terminar.
- La prueba persistente rechazó la carga completa por espacio antes de crear o sustituir la base. Pytest rechazó un archivo alterado y una clave errónea antes de enviar bytes a PostgreSQL.

## Mantenimiento e integridad histórica

El TAR completo de F: pasó la verificación offline de **1 880 953 entradas** en 26,32 s. Las regresiones del importador ejercitaron descarga interrumpida, SHA-256, checkpoints e importación repetida en muestras. No se hizo una reconstrucción masiva adicional desde el TAR.

La prueba de HTTP 429 comprobó un `Retry-After` de 90 s, ausencia de petición antes del plazo y reanudación desde el mismo offset. La actualización de un CPE a deprecado conservó la identificación y el historial. Chromium comprobó el aviso de deprecación con una respuesta fixture controlada. El recorrido en modo fixture incluyó aplicaciones, tecnologías, inventarios, CPE, CVE, hallazgos, revisión y recomendaciones.

## Rendimiento

Se ejecutaron 105 planes con `EXPLAIN (ANALYZE, BUFFERS)` en PostgreSQL 16.15 tras el calentamiento, con cuatro trabajadores, siete patrones y límite de dos segundos por consulta. Se analizaron fabricantes, productos, versiones, deprecados, títulos, UUID y CPE exacto. Todos devolvieron filas. El p50 SQL fue **4,38 ms**, p95 **59,63 ms** y p99 **81,23 ms**. La consulta de producto parcial alcanzó 140,64 ms en la muestra. Los planes usaron índices de prefijo/familia, texto, versión, CPE exacto y PK. La medición de memoria del contenedor fue **2,97 GiB** tras el ensayo, sin crecimiento del swap observado. Los tiempos SQL de esta restauración en RAM y el p95 HTTP previo de RC2.3 corresponden a ensayos distintos.

[Respaldo](V2_RC24_BACKUP_STRATEGY.md) · [Preflight](V2_RC24_STORAGE_REPORT.md) · [Manifiesto](V2_RC24_RELEASE_MANIFEST.md)

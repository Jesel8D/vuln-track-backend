# Regresión y recuperación de RC2.3

La regresión completa corrió desde worktrees nuevos, en volúmenes temporales o en el perfil dedicado `rc2-catalog23`. Las pruebas automatizadas de CVE usaron fixture.

| Grupo | Resultado |
|---|---|
| Backend completo | 781 pruebas aprobadas por ruta, existing y new. Una advertencia de deprecación de Starlette por ruta. |
| SQL | 143 comprobaciones por ruta. Se verificaron índices, permisos de lectura de recibos y resúmenes, y el rechazo de un estado completo prematuro. |
| Frontend | 98 pruebas. TypeScript, ESLint y build aprobaron. |
| Catálogo | 12 pruebas específicas repitieron la regresión tras integrar el resumen en la transacción del último lote. |
| Chromium | 12 de 12 casos pasaron sobre la base ampliada, más 1 de 1 en la sesión existente. Las dos repeticiones de la recuperación selectiva también pasaron. |
| Newman | Existing 93 solicitudes y 336 aserciones. New 92 y 331. Contrato persistente 50 y 185. Cero fallos. |
| OpenAPI | 65 operaciones, 92 solicitudes de la colección, 28 cuerpos y 70 ejemplos. SHA-256 `f7c9a0c47efbaabd313782d90723406102b17ad9845c8af67b6e06bda5d26174`. |

El recorrido multifabricante llenó el fabricante y modelo físicos desde una referencia Dell de parte `h`. En un paso independiente eligió un componente de software Apache, una versión y un CPE. Verificó la procedencia, guardó de forma atómica y recuperó la identidad por el CPE exacto. Los intentos iniciales del caso dirigido ajustaron los selectores para acotar el tipo de dispositivo y la lista de versiones. El flujo fixture registró router, switch y servidor, recorrió la consulta CVE, mantuvo el resultado indeterminado cuando faltaba evidencia y guardó revisión y recomendación. Se probaron 375, 768, 1280 y 1440 px con axe.

El control interactivo de Windows informó un error de ruta al iniciar. El recorrido se reprodujo con Chromium del proyecto, con las solicitudes limitadas a los dos puertos locales. Se inspeccionaron visualmente el candidato, la fuente y la confirmación en 375 y 1440 px. Esa inspección detectó texto escapado en el mensaje de descartes. Se corrigió y se comprobó el texto renderizado.

Las pruebas offline del TAR usaron fragmentos pequeños con entradas capturadas de NVD, incluida una etiqueta japonesa oficial. Comprobaron SHA-256, rutas y enlaces rechazados, reanudación exacta de HTTP Range, checkpoint transaccional e idempotencia. La carga de una muestra se interrumpió después del primer lote confirmado y reanudó desde el índice registrado. La API encontró el mismo UUID por CPE íntegro y por título japonés.

## Recuperación del catálogo selectivo

El perfil se reinició con 407 CPE oficiales y un fixture. Las 13 comprobaciones compararon inventario, CPE confirmado, historial CVE, revisión, recomendación y catálogo. La copia rechazó el JWT del origen. El respaldo privado pesó 323 009 bytes y se restauró en `vulntrack_v2_rc2_catalog23_restore_2d421d3c_pgdata`. El SHA-256 fue `0bb61569af5493db1b0e15e0474b64527ce70da5a8618e1b73449366ac263979`. Se detuvo el servicio restaurado y se conservó el volumen.

Tras la carga del feed se reinició por completo el perfil RC2.3 y se compararon el hash del recibo, sus contadores y los resúmenes de ambos modos. Los valores se conservaron y la API volvió a responder en `/ready`. La restauración separada cubrió los datos de la carga selectiva. Duplicar la base ampliada, producir el respaldo y reservar espacio para WAL no cabían con el margen disponible en C:.

Repetir la importación sobre el TAR local verificado tardó 25,00 s. El recibo, su fecha y el conteo de 1 880 952 CPE oficiales quedaron idénticos.

[Importación y preflight](V2_RC23_FULL_CPE_IMPORT.md) · [Arranque](V2_RC23_LOCAL_RUN.md)

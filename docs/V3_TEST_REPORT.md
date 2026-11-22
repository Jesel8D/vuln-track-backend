# Pruebas de RC3

Ejecuciones nuevas del 22 de noviembre de 2026 sobre el piloto independiente y PostgreSQL desechable.

| Grupo | Resultado |
|---|---|
| Backend | **787 pruebas aprobadas por ruta**, existing y new. Una advertencia de deprecación de Starlette por ruta. |
| Database | **151 comprobaciones SQL por ruta**. Se comprobó la migración desde RC2.4 con un dispositivo, su CPE y su consulta histórica existentes. |
| Frontend | **98 pruebas**, TypeScript, ESLint y compilación aprobados. |
| Chromium | **13 de 13** casos de creación y **1 de 1** de sesión existente después del reinicio. Se probaron 375, 768, 1280 y 1440 px con axe. |
| Newman | Existing y new, **107 solicitudes y 387 aserciones** por ruta. Contrato persistente, **51 solicitudes y 190 aserciones**. Sin fallos. |
| OpenAPI y Postman | **69 operaciones**, 104 solicitudes de colección, 34 cuerpos Pydantic y 80 ejemplos de respuesta positiva. Snapshot idéntico al Swagger servido. SHA-256 `db36a3c337f9ae36b014f327d5c61d9392aac6e8b40d066c6ac8e08587ceb1c8`. |
| Análisis estático | Ruff, TypeScript y ESLint. CodeQL no estaba disponible en la instalación comprobada. |

## Casos funcionales y de seguridad

- Se editaron ubicación, notas y modelo conservando el CPE. El cambio de firmware a `1.0.1.16` abrió revisión y bloqueó una consulta nueva. El CPE anterior y su consulta fixture `1.0.0.33` conservaron hallazgo, revisión y recomendación. El reintento de la consulta anterior devolvió la misma evidencia.
- Se verificaron candidato incompatible, versión nula, confirmación local explícita, protección contra actor suministrado por el cliente y omisión de notas del historial.
- Dos usuarios autorizados escribieron simultáneamente desde la misma versión. PostgreSQL conservó un cambio y una revisión y devolvió 409 al otro. Desde React se comparó el borrador con la revisión guardada. Se comprobó lectura del viewer, rechazo de su escritura, y rechazo de lectura/escritura a otro workspace.
- La migración conservó UUID y generaciones iniciales, sin crear revisiones históricas ficticias. Se comprobó que la aplicación no puede alterar revisiones directamente ni editar sin un motivo.
- Se recorrieron aplicaciones web, tecnologías, recomendaciones y los tres tipos de dispositivo. Una primera comprobación de sesión existente alcanzó la cuota de autenticación. Se repitió tras reiniciar el piloto y aprobó con el limitador activo.

## Custodia y recuperación

Se autenticó el respaldo completo existente de RC2.4 en F:. Su SHA-256 coincide con el manifiesto. Se creó y restauró un respaldo cifrado del piloto RC3 de **296 241 bytes** en un volumen RAM nuevo. Coincidieron los conteos de **7 dispositivos, 3 revisiones, 5 identificaciones, 3 consultas, 3 hallazgos y 2 recomendaciones**. También se restauraron **13 CPE oficiales**, dos fixture y **50 políticas**. La carga tardó 1,17 s. Se comprobó que los conteos del volumen piloto se conservaron tras su reinicio.

La copia física adicional requiere destino autorizado. En C: quedaron aproximadamente 3,18 GB y el presupuesto de restauración persistente completa es de 6,50 GB. El nuevo piloto y el ensayo RAM usaron destinos distintos de los perfiles históricos.

[Contrato](V3_DEVICE_REVISION_CONTRACT.md) · [Manifiesto](V3_RELEASE_MANIFEST.md) · [Custodia](V3_BACKUP_CUSTODY.md)

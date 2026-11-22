# Resultados de RC2.2

Fecha local de ejecución. 21 de noviembre de 2026. Las pruebas usaron PostgreSQL desechable o el volumen nuevo del perfil `rc2-catalog`.

| Área | Resultado |
|---|---|
| Backend completo | 772 aprobadas por ruta, existing y new. Una advertencia de deprecación de Starlette por ruta. |
| Verificación dirigida final | 92 aprobadas por ruta con los cambios finales de normalización, límites y mensajes. |
| SQL | 138 comprobaciones por ruta en las ejecuciones dirigidas finales. Incluyen 4 nuevas de catálogo, privilegios, RLS, índices y valores desconocidos. |
| Frontend | 98 pruebas. TypeScript, ESLint y build aprobados. |
| Chromium | 11 aprobadas en la ejecución final. El alta asistida se probó por teclado y a 375, 768, 1280 y 1440 px, sin desbordamiento ni infracciones detectadas por axe en la vista ejercitada. |
| Newman existing | 95 solicitudes HTTP, 346 aserciones, 0 fallos. |
| Newman new | 99 solicitudes HTTP, 366 aserciones, 0 fallos. |
| Newman guardia persistente | 49 solicitudes HTTP, 180 aserciones, 0 fallos. |
| Contratos | 65 operaciones OpenAPI, 92 solicitudes definidas en Postman, 28 cuerpos y 70 ejemplos de respuesta. OpenAPI SHA-256 `8a742ac67c5afd6fb35dd99e5302a9a3908ba76521e33a9bb1fc9b51befc29ff`. |
| Recuperación | 13 comprobaciones, incluidas dos repeticiones de navegador. Se preservaron el diccionario, la identificación, el historial y las medidas. |

La integración probó reanudación tras HTTP 429, descarte por fabricante fuera del alcance, actualización de deprecación con reemplazo, rechazo de una versión incompatible, idempotencia de alta, conflicto al cambiar un cuerpo con la misma clave y rechazo de identificadores ajenos. También probó un registro pendiente con producto y versión desconocidos. Chromium recorrió el alta Cisco con captura fixture, revisión conservadora del CVE y recomendación manual. El formulario manual y las aplicaciones V2 pasaron sus regresiones.

La primera pasada de Chromium detectó dos fallos de coincidencia por acentos dañados al escribir etiquetas desde PowerShell. La segunda pasó los 11 casos tras corregir el texto UTF-8. Se conservaron los resultados de ambas ejecuciones en el entorno privado.

## Catálogo y recursos medidos

| Modo | Recibidos | Almacenados | Fabricantes | Familias | Descartados |
|---|---:|---:|---:|---:|---:|
| Live oficial | 4 | 4 | 1 | 1 | 0 |
| Captura fixture | 1 | 1 | 1 | 1 | 0 |

El esquema del catálogo, incluidos sus índices, ocupó **172 032 bytes**. Una prueba desechable que repitió la importación fixture obtuvo una sola fila persistente y un RSS máximo del proceso Python de **141 188 KiB**, incluido el arnés. El máximo de descarga por respuesta API es de 2 MiB. El costo del diccionario completo en PostgreSQL queda por medir.

## Restauración

El backup privado comprimido pesó **270 419 bytes** y tiene SHA-256 `b25fd6a6433baccc14fdd944fccfcd7b64b784be731caeadc32545d3d11be4ed`. Se restauró en `vulntrack_v2_rc2_catalog_restore_8d1d8961_pgdata`, que quedó detenido. El perfil fuente sigue disponible. Las pruebas verificaron la identidad y las consultas del dispositivo asistido, los conteos live/fixture y el rechazo del JWT original en la copia. Ambos volúmenes RC2.2 se conservaron.

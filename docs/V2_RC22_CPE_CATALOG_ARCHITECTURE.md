# Catálogo CPE local de RC2.2

RC2.2 incorpora un diccionario de lectura autenticada que funciona desde PostgreSQL. SQL010 agrega `vulntrack_catalog` para productos y recibos de sincronización, y `vulntrack_catalog_private` para los recibos de alta. El origen y el UUID NVD forman la clave del diccionario. Así se preservan las copias live y fixture aunque compartan el mismo UUID. Las tablas de dispositivos, identificaciones e historiales CVE conservan su aislamiento por workspace.

| Entidad | Información | Acceso |
|---|---|---|
| Producto local | CPE 2.3 íntegro, UUID, parte, fabricante, producto, versión, títulos, deprecación, reemplazos, fechas NVD y original JSON | Lectura autenticada. Escritura por el operador de la instalación |
| Páginas y ejecuciones | Alcance, modo, siguiente offset, total NVD, recibidos, almacenados, descartes por causa, fecha y error | Información de estado acotada en la API. Recibos completos en PostgreSQL |
| Dispositivo e identificación | Equipo físico, componente, versión observada, CPE revisado, motivo y procedencia | Roles owner/editor/viewer y FORCE RLS |
| Análisis | CPE y versión exactos utilizados, evidencia y decisión humana | Historial de dispositivo o aplicación con su procedencia |

Las consultas de catálogo normalizan Unicode y mayúsculas donde corresponde, escapan comodines en la búsqueda textual y filtran fabricante, familia y versión con parámetros SQL. Los títulos son etiquetas de búsqueda y presentación. El nombre CPE, su UUID y las fechas oficiales se conservan. Los índices B-tree cubren modo, parte y familia. Un índice trigram indexa el texto de búsqueda. La API limita a 30 filas por respuesta, 90 lecturas por minuto por cuenta y dos segundos de consulta SQL.

La confirmación asistida exige una declaración explícita de observación, motivo, UUID, nombre y fecha NVD esperados. La API revalida la fila local, su procedencia, deprecación, parte, producto y versión. La misma transacción guarda dispositivo, identificación, evidencia, auditoría y recibo idempotente. Si falla la confirmación se revierte el alta. Repetir una solicitud con su clave y cambiar el cuerpo produce 409. Catalogar un producto por sí solo no crea un dispositivo ni cambia una identificación histórica.

Se preservan los campos opcionales del alta antigua y la consulta CVE de RC2. El modo de análisis debe coincidir con la identificación. Las actualizaciones del diccionario conservan la identidad registrada en ejecuciones previas.

[API de productos de NVD](https://nvd.nist.gov/developers/products) · [Diccionario CPE oficial](https://nvd.nist.gov/products/cpe)

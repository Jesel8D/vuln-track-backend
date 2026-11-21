# Arquitectura experimental RC2

La navegación V2 reúne dispositivos y aplicaciones en el workspace. Cada categoría conserva su propio modelo, API, historial y resultados. La integración no mueve filas de RC1 ni importa activos V1. El alcance académico y la política de workspaces requieren ratificación de Jesel y Rudi.

| Modelo | Campos principales | Propiedad y endpoint | CPE, CVE e historial | Compatibilidad y decisión RC2 |
|---|---|---|---|---|
| Asset V1 | Tipo, fabricante, modelo, versión nullable, sitio, inventario y notas | created_by individual, /api/v1/assets | Eventos asset_cpe_identifications. Análisis202 y revisión V1 | Mantener contrato. No montar endpoints V1 dentro del workspace |
| Aplicación V2 | Nombre, descripción, estado, URLs y tecnologías relacionadas | RLS de workspace, /api/v2/workspaces/{id}/applications | PUT CPE por tecnología. Análisis201, snapshots, hallazgos y medidas | Mantener contratos. Agregar procedencia a nuevas ejecuciones |
| Dispositivo RC2 | Tipo, fabricante/modelo físicos, producto/vendor/componente evaluado, versión nullable, ubicación, creador, notas, estado y fechas | Workspace y roles, /api/v2/workspaces/{id}/devices | Identificaciones anexadas, snapshots, ejecuciones y hallazgos propios, revisión y medidas | SQL009 aditivo en esquema separado. No convertir equipos en aplicaciones |
| Workspace V2 | Miembros owner/editor/viewer | Contexto autenticado por transacción, RLS | Limita todas las relaciones RC2 | Reutilizar contexto y roles existentes |
| Catálogo y evaluación | CPE 2.3, NVD 2.0, evidencias y evaluación conservadora | FastAPI usa clientes de origen fijo | Reutilizar resolución, cuotas y evaluación. Preservar AND y rangos | No validar por título o coincidencia automática |

El historial de identificaciones conserva una fila por confirmación y cada ejecución referencia la identificación exacta. Las claves compuestas impiden vincular filas de otro dispositivo o workspace. El catálogo se consulta fuera de la transacción. El actor procede de JWT y los permisos de la membresía persistida. El esquema agregado pertenece a Database. Backend empaqueta la fuente SQL, coordina su aplicación mediante Alembic y conserva los modelos V1 existentes. Los endpoints RC2 usan SQLAlchemy Core como el módulo V2 existente, por lo que no precisan un segundo mapa ORM de las mismas tablas.

Se inspeccionaron las ramas históricas Backend V1 2cb124d, MVP-A 2e12bad, MVP-B 7126a16 y Frontend V1 2643467, MVP-B 7ef0d45. Conservan pruebas de propiedad, eventos CPE, worker y UI de dispositivos con rutas V1. Las rutas y roles V2 justifican un contrato aditivo. Un futuro cliente móvil puede usar la misma API de dispositivos y autenticación, conservar formularios locales sin contraseñas y preservar las claves de idempotencia al reintentar. Su implementación queda pendiente.

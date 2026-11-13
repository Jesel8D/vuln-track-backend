# Matriz real de endpoints y pruebas V2

39 operaciones sobre 30 rutas: 2 de estado, 15 /api/v1 y 22 /api/v2. Se cuentan pares método/ruta, no rutas de documentación. Swagger añade GET /docs, /redoc, /openapi.json y el auxiliar /docs/oauth2-redirect fuera de este inventario de negocio.

Todas las operaciones se invocaron por HTTP con Newman en ambos recorridos de instalación. **38 operaciones alcanzaron una respuesta positiva; POST /api/v2/workspaces reprodujo un 404 existente, sin demostrar creación adicional exitosa**. Las solicitudes de progreso se repiten solo con GET.

Las 61 solicitudes incluyen 41 casos con respuesta 2xx (hay autenticación auxiliar B), 19 negativos y una reproducción del bloqueo de workspace. La carpeta negativa tiene 22 solicitudes porque contiene tres pasos auxiliares B. Hay 39 ejemplos de operación en OpenAPI: 38 positivos y uno del error conocido; los 15 cuerpos de entrada tienen ejemplo, con secretos vacíos. Todos los 61 elementos Postman tienen ejemplo de respuesta sintética independiente.

| Método | Ruta real | Módulo | Solicitud Postman | HTTP esperado en esta revisión | Ejemplo |
|---|---|---|---|---:|---|
| `GET` | `/health` | Estado | Health | 200  | Sí |
| `GET` | `/ready` | Estado | Readiness | 200  | Sí |
| `POST` | `/api/v1/auth/register` | Autenticación | Registrar cuenta única A | 201  | Sí |
| `POST` | `/api/v1/auth/login` | Autenticación | Login A y guardar token | 200  | Sí |
| `GET` | `/api/v1/auth/me` | Autenticación | Identidad A | 200  | Sí |
| `POST` | `/api/v1/assets` | V1 · Activos heredados | Crear activo V1 | 201  | Sí |
| `GET` | `/api/v1/assets` | V1 · Activos heredados | Listar activos V1 | 200  | Sí |
| `GET` | `/api/v1/assets/{asset_id}` | V1 · Activos heredados | Detalle activo V1 | 200  | Sí |
| `GET` | `/api/v1/cpe-candidates` | V1 · Activos heredados | Buscar candidatos CPE V1 | 200  | Sí |
| `POST` | `/api/v1/assets/{asset_id}/cpe-identifications` | V1 · Activos heredados | Identificar CPE del activo V1 | 201  | Sí |
| `GET` | `/api/v1/assets/{asset_id}/cpe-identifications` | V1 · Activos heredados | Historial CPE del activo V1 | 200  | Sí |
| `POST` | `/api/v1/assets/{asset_id}/analyses` | V1 · Activos heredados | Aceptar análisis asíncrono V1 | 202  | Sí |
| `GET` | `/api/v1/assets/{asset_id}/analyses` | V1 · Activos heredados | Historial análisis V1 | 200  | Sí |
| `GET` | `/api/v1/assets/{asset_id}/analyses/{run_id}` | V1 · Activos heredados | Progreso V1 (polling GET limitado) | 200  | Sí |
| `GET` | `/api/v1/assets/{asset_id}/analyses/{run_id}/findings` | V1 · Activos heredados | Resultados V1 | 200  | Sí |
| `GET` | `/api/v1/findings/{finding_id}` | V1 · Activos heredados | Detalle hallazgo V1 | 200  | Sí |
| `PATCH` | `/api/v1/findings/{finding_id}` | V1 · Activos heredados | Revisar hallazgo V1 | 200  | Sí |
| `POST` | `/api/v2/workspaces` | V2 · Workspaces y dashboard | Workspace adicional: bloqueo RLS conocido | 404 **incidencia RLS** | Sí |
| `GET` | `/api/v2/workspaces` | V2 · Workspaces y dashboard | Workspace personal A y membresía | 200  | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}` | V2 · Workspaces y dashboard | Detalle workspace A | 200  | Sí |
| `POST` | `/api/v2/workspaces/{workspace_id}/applications` | V2 · Aplicaciones | Crear aplicación de laboratorio | 201  | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications` | V2 · Aplicaciones | Listar aplicaciones | 200  | Sí |
| `POST` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies` | V2 · Tecnologías y CPE | Registrar tecnología de fixture | 201  | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies` | V2 · Tecnologías y CPE | Listar tecnologías | 200  | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/cpe-candidates` | V2 · Tecnologías y CPE | Buscar candidatos CPE V2 | 200  | Sí |
| `PUT` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies/{technology_id}/cpe` | V2 · Tecnologías y CPE | Confirmar CPE revisado | 200  | Sí |
| `POST` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies/{technology_id}/analyses` | V2 · Análisis e historial | Consultar CVE V2 (POST único) | 201  | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/analyses/{run_id}` | V2 · Análisis e historial | Estado V2 (solo GET) | 200  | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/analyses` | V2 · Análisis e historial | Historial V2 (solo GET) | 200  | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/analyses/{run_id}/findings` | V2 · Hallazgos | Resultados y hallazgos V2 | 200  | Sí |
| `PATCH` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/findings/{finding_id}` | V2 · Hallazgos | Revisar hallazgo del fixture | 200  | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/findings/{finding_id}/recommendations` | V2 · Recomendaciones | Listar recomendaciones | 200  | Sí |
| `POST` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/findings/{finding_id}/recommendations` | V2 · Recomendaciones | Crear recomendación de prueba | 201  | Sí |
| `PATCH` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/recommendations/{recommendation_id}` | V2 · Recomendaciones | Actualizar recomendación | 200  | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/dashboard` | V2 · Workspaces y dashboard | Dashboard | 200  | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/targets` | V2 · Destinos autorizados | Listar destinos de aplicación | 200  | Sí |
| `POST` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/targets` | V2 · Destinos autorizados | Registrar destino local sin escanear | 201  | Sí |
| `PATCH` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/targets/{target_id}/authorization` | V2 · Destinos autorizados | Rechazar autorización de prueba | 200  | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/targets` | V2 · Destinos autorizados | Listar destinos del workspace | 200  | Sí |

## Capacidades sin endpoint

- Membresías: el directorio GET /api/v2/workspaces devuelve rol propio; el alta crea owner. No hay CRUD público de miembros/invitaciones.
- Auditoría: hay escrituras internas audit_events; no existe endpoint público de lectura/administración.
- ZAP: no existe endpoint ni contrato habilitado. El negativo envía un cuerpo no admitido a análisis V1 y exige 422; nunca solicita un escaneo.
- V2 no expone GET individual de aplicación/tecnología/target ni DELETE generales. Se usan las listas reales.
- V1 activos y sus identificaciones/cola conservan el modelo de propietario individual, no se reinterpretan como aplicaciones V2.

## Paginación y estados

- Activos V1, identificaciones, análisis V1/V2 y hallazgos: limit 1–100 (20 por defecto), offset 0–1 000 000; respuesta con page.
- Candidatos CPE: limit 1–20 (10 por defecto), offset 0–10 000.
- Destinos de workspace: limit 1–1000 (100 por defecto), offset 0–1 000 000.
- Aplicaciones, tecnologías, destinos de aplicación y recomendaciones: listas acotadas a 100, sin inventar parámetros de paginación. Directorio de workspaces: sin paginación ni LIMIT explícito en la función SQL.
- Análisis: queued/running/completed/failed; coverage complete/partial, y puede ser null antes de finalizar. V2 procesa una página máxima de 100 en POST 201; V1 acepta 202 con Location y worker.
- No crear otro POST para consultar avance. El polling V1 repite el mismo GET, hasta 29 repeticiones adicionales; un estado fallido o agotar el presupuesto falla la prueba.

Las respuestas V2 y health/ready conservan sus esquemas de salida permisivos originales (22 operaciones); se agregan ejemplos, no modelos de respuesta que filtren/cambien JSON. Las otras 17 tienen response_model existente. Los ejemplos no sustituyen la validación estricta pendiente para salidas sin modelo.

# Matriz de API V2 estabilizada

39 operaciones en 30 rutas: 2 estado, 15 V1, 22 V2. **Las 39 alcanzaron respuestas positivas** con fixtures originales sobre PostgreSQL real. Hay 61 solicitudes: 42 casos positivos (incluida preparación B) y 19 negativos; la carpeta 10 tiene 22 solicitudes por sus tres preparaciones. El modo persistente omite la carpeta 10 completa y conserva los datos; la suite temporal ejecuta todo.

15 esquemas de request tienen ejemplo (password vacío requiere sustitución local), y 39 operaciones ejemplo de respuesta positiva. Los 61 elementos Postman incluyen respuesta sintética sanitizada. Swagger agrega sus rutas de documentación fuera del inventario de negocio.

| Método | Ruta | Solicitud Postman | HTTP positivo | Ejemplo |
|---|---|---|---:|---|
| `GET` | `/health` | Health | 200 | Sí |
| `GET` | `/ready` | Readiness | 200 | Sí |
| `POST` | `/api/v1/auth/register` | Registrar cuenta única A | 201 | Sí |
| `POST` | `/api/v1/auth/login` | Login A y guardar token | 200 | Sí |
| `GET` | `/api/v1/auth/me` | Identidad A | 200 | Sí |
| `POST` | `/api/v1/assets` | Crear activo V1 | 201 | Sí |
| `GET` | `/api/v1/assets` | Listar activos V1 | 200 | Sí |
| `GET` | `/api/v1/assets/{asset_id}` | Detalle activo V1 | 200 | Sí |
| `GET` | `/api/v1/cpe-candidates` | Buscar candidatos CPE V1 | 200 | Sí |
| `POST` | `/api/v1/assets/{asset_id}/cpe-identifications` | Identificar CPE del activo V1 | 201 | Sí |
| `GET` | `/api/v1/assets/{asset_id}/cpe-identifications` | Historial CPE del activo V1 | 200 | Sí |
| `POST` | `/api/v1/assets/{asset_id}/analyses` | Aceptar análisis asíncrono V1 | 202 | Sí |
| `GET` | `/api/v1/assets/{asset_id}/analyses` | Historial análisis V1 | 200 | Sí |
| `GET` | `/api/v1/assets/{asset_id}/analyses/{run_id}` | Progreso V1 (polling GET limitado) | 200 | Sí |
| `GET` | `/api/v1/assets/{asset_id}/analyses/{run_id}/findings` | Resultados V1 | 200 | Sí |
| `GET` | `/api/v1/findings/{finding_id}` | Detalle hallazgo V1 | 200 | Sí |
| `PATCH` | `/api/v1/findings/{finding_id}` | Revisar hallazgo V1 | 200 | Sí |
| `POST` | `/api/v2/workspaces` | Crear workspace adicional idempotente | 201 | Sí |
| `GET` | `/api/v2/workspaces` | Workspace personal A y membresía | 200 | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}` | Detalle workspace A | 200 | Sí |
| `POST` | `/api/v2/workspaces/{workspace_id}/applications` | Crear aplicación de laboratorio | 201 | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications` | Listar aplicaciones | 200 | Sí |
| `POST` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies` | Registrar tecnología de fixture | 201 | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies` | Listar tecnologías | 200 | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/cpe-candidates` | Buscar candidatos CPE V2 | 200 | Sí |
| `PUT` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies/{technology_id}/cpe` | Confirmar CPE revisado | 200 | Sí |
| `POST` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies/{technology_id}/analyses` | Consultar CVE V2 (POST único) | 201 | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/analyses/{run_id}` | Estado V2 (solo GET) | 200 | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/analyses` | Historial V2 (solo GET) | 200 | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/analyses/{run_id}/findings` | Resultados y hallazgos V2 | 200 | Sí |
| `PATCH` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/findings/{finding_id}` | Revisar hallazgo del fixture | 200 | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/findings/{finding_id}/recommendations` | Listar recomendaciones | 200 | Sí |
| `POST` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/findings/{finding_id}/recommendations` | Crear recomendación de prueba | 201 | Sí |
| `PATCH` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/recommendations/{recommendation_id}` | Actualizar recomendación | 200 | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/dashboard` | Dashboard | 200 | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/targets` | Listar destinos de aplicación | 200 | Sí |
| `POST` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/targets` | Registrar destino local sin escanear | 201 | Sí |
| `PATCH` | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/targets/{target_id}/authorization` | Rechazar autorización de prueba | 200 | Sí |
| `GET` | `/api/v2/workspaces/{workspace_id}/targets` | Listar destinos del workspace | 200 | Sí |

No se inventan endpoints de miembros/invitaciones, lectura de auditoría, ZAP, GET individuales de aplicación/tecnología/target ni DELETE generales. Las membresías se consultan en el directorio y se crean en onboarding; audit_events son internos. Los activos V1 tienen propiedad individual, sin reinterpretarlos como aplicaciones V2.

Paginación real: activos/identificaciones/análisis/hallazgos usan limit 1–100 y offset 0–1000000; CPE limit 1–20 y offset 0–10000; destinos de workspace limit 1–1000 y offset 0–1000000. Aplicaciones/tecnologías/destinos de aplicación/recomendaciones se acotan a 100 sin parámetros inventados. El directorio de workspaces no tiene LIMIT explícito en SQL.

Análisis: queued/running/completed/failed; coverage null antes de finalizar, luego complete/partial. V2 procesa una página máxima de 100 en POST 201; V1 acepta 202 y worker. Polling usa el mismo GET, nunca crea POST nuevos. TITLE_TRUNCATED describe un resumen de presentación, no pérdida de la descripción original conservada en evidence.

17 operaciones conservan response_model y 22 sus salidas permisivas originales; los ejemplos no introducen filtrado nuevo. El baseline de parámetros/modelos/autenticación sigue idéntico a6331564.

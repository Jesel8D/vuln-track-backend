# Orden, variables y escenarios

## Recorrido positivo de fixtures

1. Health/readiness.
2. Registro A con username nuevo, login y captura de JWT; me comprueba user_id.
3. Directorio de workspaces y captura del personal owner; detalle. El POST adicional reproduce el bloqueo RLS conocido y no sustituye workspace_id.
4. Crear/listar aplicación; dashboard.
5. Crear destino loopback, listar, rechazar su autorización y listar por workspace. No escanear ni inventar aprobación.
6. Crear/listar tecnología, buscar candidatos y comprobar UUID + binding + deprecated del fixture previamente documentado. Confirmar ese CPE con expected_selected_cpe null.
7. POST CVE V2 una vez con Idempotency-Key; capturar analysis_id. Consultar estado e historial con GET y comprobar una sola ejecución.
8. Hallazgos: capturar finding_id/updated_at; revisar como potential en el fixture OR. Crear/listar recomendación, capturar recommendation_id/updated_at y cambiarla a in_progress. No se marca falsamente como corregida.
9. V1 separado: registrar activo, capturar asset_id, confirmar identificación, aceptar análisis 202 y capturar asset_analysis_id. Polling GET acotado, historial con total uno, hallazgos y revisión con su contrato V1 (reason/evidence).
10. Preparar identidad B y ejecutar negativos. Nunca asumir permisos SQL ni manipular el contexto HMAC.

Los positivos V2 usan fixture OR y descripción corta simulados. La revisión undetermined, el AND original y el título original tienen reproducciones separadas de fallo. Los GET de historial no relanzan consultas; Idempotency-Key se guarda por intención para poder reconciliar el mismo POST. Repetir manualmente el creador de clave inicia otra intención; para un retry conservar la clave ya capturada y no regenerarla.

## Variables

| Variable | Origen o configuración |
|---|---|
| base_url | Entorno: http://127.0.0.1:8000, o puerto impreso por helper |
| password | Valor local privado; automático en memoria con run.py |
| username / username_b | UUID nuevos por recorrido; no sobrescribir con variables de entorno homónimas |
| access_token / access_token_b | Login A/B; colección hereda Bearer A y negativos B lo sustituyen |
| user_id | Registro A |
| workspace_id / foreign_workspace_id | Directorios personales A/B, no primer candidato de una búsqueda CPE |
| application_id | POST aplicación |
| technology_id | POST tecnología |
| cpe_name_id / confirmed_cpe | UUID/binding fijo verificado solo en fixture; revisión manual en live |
| analysis_id | POST análisis V2 |
| finding_id / finding_updated_at | GET hallazgos V2; timestamp conservado para el negativo concurrente |
| recommendation_id / recommendation_updated_at | POST recomendación |
| target_id / target_updated_at / target_original_updated_at | Alta y revisión del destino, control optimista |
| asset_id / identification_id | Contratos heredados V1 independientes |
| asset_analysis_id / asset_finding_id / asset_finding_updated_at | Cola y hallazgos V1, no sustituyen IDs V2 |
| workspace_key / asset_key / identification_key / analysis_key / asset_analysis_key | UUID de idempotencia por intención |
| poll_count | Contador acotado de GET de progreso V1 |
| expired_token | Solo valor local privado; runner genera firmado y vencido |
| disabled_base_url | Segunda API del helper con registro deshabilitado |
| disposable_confirmed | false por defecto; confirmar solo el entorno efímero identificado |
| nvd_mode / allow_live_nvd / cpe_confirmed_manually | fixture o habilitación consciente de revisión live |

No crear variables de entorno con los nombres de IDs/tokens automáticos: el alcance entorno podría ocultar los valores capturados de colección. La contraseña no es una variable de colección versionada. Las variables auxiliares se crean al usarlas y no son entidades nuevas.

## Negativos ejecutables

La carpeta 10 tiene 22 solicitudes: tres preparan B y 19 son negativas. El error de workspace adicional se reproduce en carpeta 03.

- Sin token, token inválido, token realmente expirado firmado y usuario inexistente: 401. El expirado requiere su variable o se omite explícitamente en Postman manual.
- Duplicado: 409 REGISTRATION_UNAVAILABLE, sin exponer cuenta existente.
- Username inválido y autoconcesión is_admin: 422.
- Workspace B visto por A y aplicación A vista por B: 404 RESOURCE_NOT_FOUND desde el establecimiento de contexto/RLS. Activo A visto por B: 404 ASSET_NOT_FOUND.
- Análisis inexistente: 404 ANALYSIS_NOT_FOUND; UUID, paginación y tecnología inválidos: 422.
- Timestamp obsoleto de autorización de destino o revisión de hallazgo: 409 específico. Es concurrencia optimista reproducible; las carreras HTTP simultáneas de altas las cubre la regresión backend existente.
- Misma clave de activo con otro cuerpo: 409 IDEMPOTENCY_CONFLICT.
- Cuerpo ZAP ajeno al contrato V1: 422, sin lanzar análisis.
- Registro deshabilitado en la segunda API: 503 REGISTRATION_DISABLED y Retry-After. Si disabled_base_url está vacío se omite en Postman manual; el runner sí lo ejecuta.

Ningún caso debe ejecutarse contra una base persistente. Los ejemplos preparados no constituyen autorización para probar servidores ajenos.

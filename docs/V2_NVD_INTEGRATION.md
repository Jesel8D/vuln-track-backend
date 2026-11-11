# Integración NVD para Database V2

## Flujo

1. Un usuario autenticado con rol `owner` o `editor` solicita candidatos para una aplicación de su workspace.
2. El backend consulta exclusivamente el Products/CPE API de NVD mediante origen fijo HTTPS, sin URL controlable por el usuario.
3. El usuario selecciona un `cpeNameId`; el backend lo resuelve de nuevo en NVD, rechaza entradas deprecadas y verifica que la versión concuerde con la tecnología antes de persistir la selección como `user_confirmed`.
4. Una consulta CVE requiere ese CPE confirmado. Se crea una ejecución con clave idempotente y snapshot; la llamada externa se realiza sin una transacción SQL abierta.
5. Se guarda la página validada, evidencia NVD limitada, cobertura (`complete` solo cuando los resultados caben en el presupuesto de 100; de otro modo `partial`) y timestamp de fuente. Los errores quedan tipados y la ejecución terminal no se reescribe.

## Rutas V2 disponibles

- `GET/POST /api/v2/workspaces/{workspace_id}/applications/{application_id}/targets` consulta y registra URLs de aplicación en estado inicialmente pendiente.
- `GET /api/v2/workspaces/{workspace_id}/targets?limit=&offset=` lista destinos del workspace con su aplicación y autorización efectiva.
- `PATCH /api/v2/workspaces/{workspace_id}/applications/{application_id}/targets/{target_id}/authorization` registra una declaración de autorización con referencia y vencimiento de hasta 365 días. Esto no habilita escaneos: ZAP permanece deshabilitado.
- `GET /api/v2/workspaces/{workspace_id}/applications/{application_id}/analyses?limit=&offset=` lista las consultas NVD de una aplicación, paginadas y ordenadas de más recientes a más antiguas. Incluye producto, versión, estado, cobertura, conteos, avisos y marcas de tiempo.
- `GET /api/v2/workspaces/{workspace_id}/applications/{application_id}/analyses/{run_id}` devuelve el estado de una consulta.
- `GET /api/v2/workspaces/{workspace_id}/applications/{application_id}/analyses/{run_id}/findings` devuelve hallazgos paginados.
- `PATCH /api/v2/workspaces/{workspace_id}/applications/{application_id}/findings/{finding_id}` registra una sola revisión humana de un hallazgo abierto y terminado. Exige `expected_updated_at`, limita el resultado a `potential`, `undetermined` o `not_applicable`, y agrega un evento de auditoría; la base impide reescribir la evidencia fuente.
- `GET/POST /api/v2/workspaces/{workspace_id}/applications/{application_id}/findings/{finding_id}/recommendations` consulta y agrega medidas manuales. El alta limita cada hallazgo a 50 medidas y solo acepta enlaces fuente HTTPS sin credenciales.
- `PATCH /api/v2/workspaces/{workspace_id}/applications/{application_id}/recommendations/{recommendation_id}` actualiza el estado con `expected_updated_at`; `fixed` guarda automáticamente la fecha de finalización.

El historial y las medidas usan el mismo contexto HMAC, RLS y autorización del workspace. La revisión y actualización de medidas requieren rol de escritura y usan control optimista de concurrencia. Los eventos de alta, revisión y cambio de estado se guardan en auditoría.

## Aislamiento de workspace

`app/db/workspace_context.py` firma `v1|user|workspace|expires|nonce` con HMAC-SHA256 y ejecuta `vulntrack.establish_context` parametrizado dentro de cada transacción V2. El vencimiento es a 30 segundos, por debajo del máximo SQL de 60; se usa un nonce aleatorio nuevo. La transacción termina al salir del contexto, para que `SET LOCAL` no se filtre a una conexión reutilizada. Los roles de escritura se comprueban con `has_workspace_role` y RLS vuelve a filtrar las filas.

`WORKSPACE_HMAC_KEY` debe ser exactamente el secreto provisionado desde `vulntrack_private.context_keys`, en hexadecimal minúsculo de 64 caracteres. Es una variable de entorno secreta, no un valor de cliente. La API no expone firma arbitraria. Aún se debe proteger el canal de provisioning y coordinar rotación; la política SQL actual permite replay de una firma válida durante su vigencia, por lo que TLS de PostgreSQL, logs sin parámetros y transacciones breves son obligatorios.

El primer workspace se crea con `establish_new_workspace_context`, que exige firma HMAC y usuario activo antes de permitir insertar workspace+owner en una transacción. `GET /api/v2/workspaces` usa una firma con dominio separado (`v1-directory|...`) y una función `SECURITY DEFINER` que devuelve únicamente membresías del usuario firmado. La clave no queda expuesta al proceso SQL de la API.

## Seguridad NVD y límites

- CPE y CVE se obtienen del host oficial de servicios NVD; no hay parámetro de URL, redirects, referencias externas ni proxy controlado por usuario.
- Requests externos tienen timeout, límites de cuerpo y validación de esquema. La cuota es por proceso/usuario y no sirve para despliegues con múltiples réplicas sin un limitador compartido.
- Solo se consulta una página de hasta 100 CVE por solicitud en esta iteración. Resultados restantes significan cobertura parcial; nunca se deduce ausencia de riesgo.
- Una coincidencia automática se etiqueta `potential` o `undetermined`; se conserva el snapshot/evaluador para revisión. Si el snapshot supera el presupuesto, se guarda la huella del registro fuente, se omiten partes grandes y la aplicabilidad se degrada a `undetermined`. El backend no afirma explotación.
- No hay análisis automático de URLs, dispositivos, código fuente o redes.
- ZAP Baseline no está habilitado. Antes de integrarlo hace falta autorización vigente por target y controles SSRF en resolución inicial, cada redirección y cada conexión; excluir loopback, RFC1918, IPv6 local/link-local y endpoints de metadatos; limitar tiempo, tamaño, concurrencia y salida de red; aislar el proceso. Active Scan y explotación quedan fuera de alcance.

## Migración y verificación pendiente

Instalaciones limpias ejecutan `sql/005_v2_nvd_evidence.sql` después de V2. Instalaciones existentes requieren backup/restauración de ensayo y aplicar una sola vez. La suite V2 se extendió con restricciones de idempotencia, grants de progreso, protección de snapshot y evidencia; no se declara aprobada hasta ejecutarla con PostgreSQL en clúster desechable. Las pruebas de backend también requieren el lock de dependencias instalado y una base de ensayo para cobertura end-to-end.

# VulnTrack Backend

Backend de la plataforma VulnTrack.

Consulta el [contexto y limitaciones del MVP](../vuln-track-database/docs/PROJECT_CONTEXT_AND_LIMITATIONS.md) y la [revisión de seguridad de Database V1](../vuln-track-database/docs/SECURITY_REVIEW.md) antes de implementar endpoints o configurar credenciales de base de datos.

## Integración de Database V2 pendiente

Cada request autenticado que opere sobre un workspace deberá abrir una transacción, firmar con HMAC-SHA256 el payload UTF-8 `v1|{user_uuid}|{workspace_uuid}|{expires_epoch}|{nonce_uuid}` y llamar mediante parámetros a `vulntrack.establish_context(user, workspace, expires_epoch, nonce, signature)` antes de consultar tablas. `expires_epoch` debe quedar dentro de los próximos 60 segundos; la firma se envía como 64 caracteres hexadecimales minúsculos. La transacción debe concluir antes de devolver la conexión al pool, porque el contexto se guarda localmente.

La clave HMAC se provisiona fuera de Git desde `vulntrack_private.context_keys` al gestor de secretos del backend. No aceptar estos valores del cliente, no exponer un endpoint que firme identidades arbitrarias y no registrar la clave ni la firma. La API aún no implementa esta integración; sin ella, RLS deniega el acceso V2.

## Propósito

Proporcionar la API REST para gestionar usuarios, activos y evaluaciones de vulnerabilidades.

## Estado

Repositorio inicializado. La implementación de Backend V1 se encuentra pendiente.

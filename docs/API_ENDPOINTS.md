# API V1.1 propuesta: activos propios

Contrato adaptado de ASSET_CONTRACT_PROPOSAL, pendiente de aprobación formal.
La decisión de propiedad no se promueve a APROBADA por estar implementada/probada.

| Método | Ruta | Identidad | Respuesta |
|---|---|---|---|
| GET | /health | No | 200 proceso HTTP |
| GET | /ready | No | 200 dependencias/esquema; 503 si falta created_by |
| POST | /api/v1/auth/login | Credenciales | JWT temporal; 401 genérico si falla |
| GET | /api/v1/auth/me | Bearer activo | Identidad sin hash |
| POST | /api/v1/assets | Bearer activo + Idempotency-Key | 201 propio; replay 201; conflicto 409 |
| GET | /api/v1/assets | Bearer activo | 200 items y total exclusivamente propios |
| GET | /api/v1/assets/{id} | Bearer activo | 200 propio; 404 ajeno/sin dueño/inexistente |

Entrada: device_type (1–80), manufacturer/model/version/site_label (1–120), texto
estricto obligatorio. inventory_label (1–120) y notes (1–1000), opcionales null.
NFC/strip, controles/surrogates rechazados; opcional vacío no es null. Versiones texto,
sin semver obligatorio. Cuerpo ≤8192 bytes, incluidos cuerpos chunked.

Campos extra prohibidos: `created_by`, `owner_id`, IDs o fechas del cliente se rechazan.
El backend asigna created_by exclusivamente desde current_user. Salida: campos del
activo más id/created_at servidor; no incluye owner, hashes ni secretos. No se cambia
el formato de snapshots V1 ni la versión de la huella canónica.

Listado: limit=20 (1–100), offset=0 (0–1000000), orden `(created_at,id)`. Respuesta
`{items:[...],page:{limit,offset,total}}`, con filtro SQL `created_by = usuario` aplicado
antes de paginar y contar. Una página vacía conserva el total autorizado, nunca el global.
No existen filtros adicionales ni endpoints PATCH/DELETE/admin/asignación histórica.

Errores: `{error:{code,message,request_id}}`. 401 con WWW-Authenticate Bearer; 404 no
revela existencia ajena; 409 payload distinto/expiración; 413 tamaño; 422 validación/JSON;
429 cuota login; 500 fallo inesperado; 503 dependencia/pool/locks/esquema no preparado.
No se serializa el contenido rechazado ni información de propietario.
V1.3 agrega preflight CORS OPTIONS en middleware, sin endpoint de negocio nuevo:
200 JSON status ok o 400 CORS_PREFLIGHT_DENIED; perfil explícito en CORS.md. X-Request-ID es
generado por servidor; respuestas no-store/nosniff. OpenAPI en /docs y /openapi.json.

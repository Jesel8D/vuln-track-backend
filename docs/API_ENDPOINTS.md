# API V1 provisional

Contrato adaptado de ASSET_CONTRACT_PROPOSAL, no promovido a decisión aprobada en Context.
Tabla de rutas y ejemplos en README; esquemas ejecutables en `/openapi.json` y `/docs`.

Activo: device_type (1–80), manufacturer/model/version/site_label (1–120), todos texto
estricto obligatorio. inventory_label (1–120) y notes (1–1000), opcionales null.
Normalización NFC/strip, controles y surrogates rechazados; opcional vacío no es null.
Campos extra prohibidos. Versiones no se convierten a números ni se exige semver.
No se aceptan IDs/propietarios del cliente ni URLs de escaneo. Respuesta incluye UUID
y created_at servidor; no incluye updated_at, hashes ni información de usuarios.

Listado preparado: limit=20 (1–100), offset=0 (0–1000000), orden created_at,id;
`items` y `page` con limit/offset/total del conjunto autorizado. Sin filtros adicionales.
Detalle ausente o fuera de ámbito: 404. Actualmente ningún activo tiene ámbito autorizado.

Errores uniformes:

```json
{"error":{"code":"VALIDATION_ERROR","message":"Solicitud inválida","request_id":"UUID-servidor"}}
```

401 incluye WWW-Authenticate Bearer; 403 política pendiente; 404 recurso no visible;
409 colisión/expiración idempotente; 413 cuerpo >8192 bytes; 422 validación/JSON malformado;
429 cuota login; 500 fallo interno/persistencia; 503 dependencia/pool/lock/consulta no disponible.
Se usa 422 para JSON y parámetros inválidos de manera uniforme con FastAPI, elección
provisional distinta del 400 ilustrado en algunos borradores. Sin detalles de entrada en errores.
Todas las respuestas reciben X-Request-ID, no-store y nosniff; no se confía en correlación
aportada por cliente. No se implementan PATCH, DELETE, scans ni endpoints externos.

# Contrato real para React y React Native — preparación V1.3

API implementada V1.1, estado de propiedad **PROPUESTA**, pendiente de aprobación e
integración coordinada. Este documento no implementa clientes ni agrega endpoints.
OpenAPI ejecutable: `/openapi.json`; explorador `/docs`. Ejemplos sintéticos, sin secretos
reales. Los bloques JSON se validan automáticamente contra los modelos reales.

Base de desarrollo local: `http://127.0.0.1:8000`, prefijo funcional `/api/v1`.
Configurar la URL pública en el cliente, sin incrustar secretos. Ejemplo de configuración
React/Vite: `VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1`. React Native usará el mecanismo
de configuración acordado por su proyecto; si adopta Expo, un ejemplo público es
`EXPO_PUBLIC_API_BASE_URL=https://api.dev.example.edu/api/v1`. No se crean esos proyectos
en esta misión. No duplicar /api/v1 al concatenar rutas; cambiar la URL base no cambia el
Origin de la página ni configura automáticamente el backend.
Uso remoto requiere HTTPS y una API correctamente autorizada/configurada. El navegador
nunca se conecta a PostgreSQL. En un teléfono físico localhost es el propio teléfono:
acordar URL HTTPS accesible de la API; no publicar PostgreSQL ni abrir interfaces a ciegas.

## Login: POST /api/v1/auth/login

Enviar JSON UTF-8, `Content-Type: application/json`, preferentemente `Accept: application/json`.
Username ASCII minúsculas, 1–80 caracteres, primer carácter alfanumérico, resto
`a-z0-9_.-`. El servidor no transforma mayúsculas. Password entre 1 y 256 caracteres
en login; altas operativas separadas exigen 12–256. Campos extra rechazados.

```json
{"username":"operador_local","password":"VALOR_INTRODUCIDO_POR_EL_USUARIO"}
```

Respuesta 200 (valor de token ilustrativo, no utilizable):

```json
{"access_token":"JWT_DEVUELTO_POR_EL_SERVIDOR","token_type":"bearer","expires_in":900}
```

El cliente toma expires_in de la respuesta, no lo fija en su código: configurable entre
60 y 900 segundos, defecto 900. Credenciales incorrectas, usuario ausente/inactivo o hash
inutilizable: 401 genérico. No distinguir cuentas existentes. Limitador por cuenta/origen
por proceso; 429 con Retry-After. No registrar cuerpo, contraseña ni token.
El seed `demo_operator` está inactivo y sin contraseña: nunca es una cuenta de acceso.

## Identidad: GET /api/v1/auth/me

Enviar `Authorization: Bearer <access_token>`. Respuesta 200:

```json
{"id":"00000000-0000-4000-8000-000000000010","username":"operador_local"}
```

No usar ese ID para autorizar acciones en el cliente ni enviarlo como propietario.
Servidor verifica firma, expiración y usuario activo/versión en cada solicitud. Ausencia,
token inválido/vencido o identidad revocada: 401 con `WWW-Authenticate: Bearer`.
No existen refresh, logout servidor, registro público, recuperación ni administración API.

## Registro: POST /api/v1/assets

Bearer obligatorio y `Idempotency-Key` UUID canónica de 36 caracteres, por ejemplo
`b3000000-0000-4000-8000-000000000001`. Generar una clave aleatoria por operación lógica,
conservarla con el formulario y actor originales y reutilizarla solo en sus reintentos.

```json
{"device_type":"router","manufacturer":"Marca ejemplo","model":"Modelo A","version":"1.2","site_label":"SITIO-1","inventory_label":null,"notes":null}
```

Respuesta 201 con `Location: /api/v1/assets/8b1b17ef-097f-49fd-ac45-221bb697867c`:

```json
{"device_type":"router","manufacturer":"Marca ejemplo","model":"Modelo A","version":"1.2","site_label":"SITIO-1","inventory_label":null,"notes":null,"id":"8b1b17ef-097f-49fd-ac45-221bb697867c","created_at":"2026-10-30T12:00:00Z"}
```

Servidor asigna created_by desde identidad; no aparece en entrada/salida. Enviar
created_by (incluso propio o null), owner_id, id o created_at produce 422. No incluir
URLs de análisis, contraseñas de dispositivos ni secretos de clientes.

| Campo | Regla del código |
|---|---|
| device_type | texto obligatorio, 1–80 caracteres |
| manufacturer, model, version, site_label | texto obligatorio, 1–120 |
| inventory_label | null/ausente o texto 1–120 |
| notes | null/ausente o texto 1–1000, solo no sensible |

NFC y recorte de extremos antes de validar longitud; controles y surrogates rechazados.
Opcional vacío no equivale a null. No convertir version a número ni exigir semver.
Campos desconocidos rechazados. Cuerpo máximo por defecto 8192 bytes, distinto de límites
en caracteres. Registrar inventario no autoriza escaneo ni confirma vulnerabilidades.

## Detalle: GET /api/v1/assets/{asset_id}

Bearer, UUID de activo; respuesta 200 con exactamente la misma forma que el registro.
Solo propio. Ajeno, histórico sin dueño o inexistente: 404 idéntico; no inferir existencia.
Un UUID mal formado produce 422 con identidad válida. No hay PATCH/DELETE/asignación.

## Listado: GET /api/v1/assets?limit=20&offset=0

Bearer. limit entero 1–100 (defecto 20), offset 0–1000000 (defecto 0). Sin filtros
adicionales. Orden ascendente estable `(created_at,id)`; offset puede cambiar de contenido
si se insertan activos entre páginas, no promete snapshot entre peticiones.

```json
{"items":[{"device_type":"router","manufacturer":"Marca ejemplo","model":"Modelo A","version":"1.2","site_label":"SITIO-1","inventory_label":null,"notes":null,"id":"8b1b17ef-097f-49fd-ac45-221bb697867c","created_at":"2026-10-30T12:00:00Z"}],"page":{"limit":20,"offset":0,"total":1}}
```

Solo filas y total propios; una página vacía conserva el total autorizado. Un usuario sin
activos recibe items vacío/total 0. No completar con datos de caché de otra identidad.

## Errores y recuperación

Forma uniforme, sin cuerpo rechazado ni datos internos; correlación en X-Request-ID:

```json
{"error":{"code":"VALIDATION_ERROR","message":"Solicitud inválida","request_id":"c3000000-0000-4000-8000-000000000001"}}
```

| HTTP | Interpretación y conducta del cliente |
|---|---|
| 401 | Reautenticar; no bucle infinito. Conservar intento ligado al mismo actor |
| 404 | No disponible/no visible; no intentar descubrir propietario |
| 409 IDEMPOTENCY_CONFLICT | Misma clave con datos distintos; revisar operación, no retry automático |
| 409 IDEMPOTENCY_EXPIRED | Reconciliación manual: no regenerar clave y reenviar silenciosamente |
| 409 RETRY_REQUEST | Resultado concurrente no recuperable en ese intento; mismo actor/clave/cuerpo |
| 413 | Reducir cuerpo; no repetirlo sin cambio |
| 422 | Corregir datos; JSON malformado y query inválida también usan 422 |
| 429 | Respetar Retry-After; no saturar login |
| 500 | Resultado de escritura puede ser incierto; conservar intento y evitar otra clave |
| 503 | DB/pool/lock/esquema no disponible; respetar Retry-After, retry acotado del mismo intento |

No hay un 403 de política pendiente en el flujo actual de propietario; no asumir uno
como contrato universal de rechazo. Otras rutas/métodos no implementados usan el error HTTP
uniforme. `/health` comprueba HTTP, `/ready` dependencias/columnas esenciales (503 si V1
no fue migrado), no acreditan aprobación del diseño ni validan todo el catálogo.

## Flujo idempotente y estado del cliente

1. Autenticar, consultar me, preparar formulario sin secretos; generar clave una sola vez.
2. Enviar registro y solo mostrar éxito confirmado tras 201. Replay devuelve el mismo
   cuerpo/201/Location dentro de la ventana válida.
3. Timeout/red/resultado desconocido: conservar cuerpo normalizado, clave y actor; retry
   limitado con backoff. Editar el formulario define otra operación, pero primero resolver
   un envío anterior incierto para evitar duplicados.
4. Misma clave/payload/actor no duplica; distinto payload da conflicto. B reutilizando la
   clave de A tiene otro ámbito y puede crear un activo nuevo propio: nunca transferir
   automáticamente intentos pendientes al cambiar de usuario.
5. Ventana técnica actual 24 h desde inserción, aún PROPUESTA. Ante vencimiento o reloj
   incierto, parar retry automático y reconciliar con una persona. No hay endpoint de
   reconciliación ni búsqueda por clave. Guardar otra clave no resuelve un resultado incierto.

## Seguridad y diferencias web/móvil

Bearer en cabecera, nunca URL. React: mantener token en memoria si es viable; no asumir
que localStorage/IndexedDB son almacenes seguros frente a XSS. React Native: almacenamiento
seguro de plataforma para tokens si deben persistir, no AsyncStorage ni logs. Formulario
y notas también requieren protección/retención si se conservan localmente; no se ha
implementado persistencia offline ni se promete supervivencia al cierre de la app.

Cerrar sesión hoy significa borrar token/cache local, sin revocación individual servidor.
JWT robado puede seguir válido hasta expirar, cambiar usuario o rotar secreto. No hay
cookie de sesión, refresh ni expiración por inactividad implementada. No inventar esos
flujos al integrar. Si se eligen cookies se debe diseñar CSRF/transporte separadamente.

V1.3 implementa CORS configurable, **cerrado por defecto**. Para Vite local, establecer
en el backend `CORS_ORIGINS=["http://localhost:5173"]` (sin barra final). Añadir el origen
127.0.0.1 solo si se utiliza. Producción admite únicamente orígenes HTTPS explícitos,
sin localhost/loopback ni comodines. Leer [CORS.md](CORS.md) para el perfil completo.

El navegador puede hacer preflight OPTIONS sin token: 200 JSON `{"status":"ok"}` si
origen/método/cabeceras están permitidos, o 400 con CORS_PREFLIGHT_DENIED si no. Se permiten
GET/POST y cabeceras Authorization, Content-Type, Idempotency-Key, Accept más safelisted
estándar. Location, X-Request-ID, Retry-After y WWW-Authenticate quedan expuestas.
Usar Bearer explícito con `credentials: "omit"`, no cookies/include. La API rechaza una
configuración con CORS_ALLOW_CREDENTIALS=true. Un OPTIONS ordinario no es login ni ruta nueva.

CORS no es autenticación: un origen permitido no concede recursos de terceros y un
cliente nativo sin Origin no queda bloqueado por CORS. Un origen no listado no recibe
Allow-Origin, pero un HTTP real autenticado puede procesarse igualmente; no asumir un
403 como control de red. Las respuestas 401/413/500/503 de orígenes permitidos conservan
CORS para que el cliente pueda distinguir fallos. No registrar tokens al depurarlos.

Todas las respuestas son no-store/nosniff. Evitar cachés entre usuarios, telemetría con
secretos y renderizado HTML de notas no confiables. Consultar
[revisión JWT y revocación propuesta](JWT_SECURITY_REVIEW.md): sin refresh ni revocación
individual implementados, tampoco hay una ruta de logout que el cliente deba inventar.

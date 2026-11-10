# CORS explícito — Backend V1.3

CORS permite que un navegador lea respuestas desde ciertos orígenes. **No autentica**
usuarios ni sustituye autorización por activo, TLS o límites de red. Un cliente nativo
normalmente no envía Origin ni aplica CORS: sigue necesitando Bearer válido y activo.
No se agregaron rutas de negocio ni cookies/sesiones nuevas.

## Configuración por entorno

```dotenv
# Cerrado por defecto; lista JSON, no CSV:
CORS_ORIGINS=[]
CORS_ALLOW_CREDENTIALS=false
CORS_MAX_AGE=600
```

Desarrollo React/Vite, en `.env` privado del backend, solo si esos orígenes se usan:

```dotenv
ENVIRONMENT=development
CORS_ORIGINS=["http://localhost:5173","http://127.0.0.1:5173"]
CORS_ALLOW_CREDENTIALS=false
CORS_MAX_AGE=600
```

localhost y 127.0.0.1, HTTP y HTTPS o puertos distintos son orígenes diferentes. El
origen es **el de la página React**, no la URL base de la API. No añadir /api/v1 ni
barra final, path, query, fragmento, credenciales o patrones. Se exige forma canónica
ASCII, host minúsculo, sin puerto predeterminado explícito (80/443); usar punycode si
se necesita un dominio internacional. IPv6 requiere corchetes y forma comprimida.

Ejemplo de producción (dominio ilustrativo, no habilitado por defecto):

```dotenv
ENVIRONMENT=production
CORS_ORIGINS=["https://portal.example.edu"]
CORS_ALLOW_CREDENTIALS=false
```

Producción exige HTTPS y excluye localhost/loopback, incluidos IPv4 mapeados en IPv6.
También se mantienen las exigencias TLS verify-full de PostgreSQL. Lista vacía es válida
para despliegues sin clientes web externos. Máximo 20 orígenes, sin duplicados;
max_age entre 0 y 3600 segundos. Comodines, null, URLs ambiguas o inválidas se rechazan
en todos los entornos. `CORS_ALLOW_CREDENTIALS=true` se rechaza: esta API usa Bearer
explícito y no tiene soporte de cookies cross-origin. No existe opción regex ni allow-all.
No usar model_copy como sustituto de validación al construir Settings en integraciones.

## Métodos y cabeceras

- Métodos de negocio permitidos por preflight: **GET y POST**. OPTIONS se maneja en el
  middleware, sin añadir un endpoint ni consultar PostgreSQL. No se habilitan PUT/PATCH/DELETE.
- Cabeceras explícitas: **Accept, Content-Type, Authorization, Idempotency-Key**. Starlette
  añade las cabeceras safelisted estándar de CORS (Accept-Language/Content-Language, etc.).
  La comparación de nombres no distingue mayúsculas. No se permite X-User-ID.
- Cabeceras de respuesta expuestas al navegador: **Location, X-Request-ID, Retry-After,
  WWW-Authenticate**. Cache-Control y Content-Type ya son safelisted.
- Access-Control-Allow-Credentials no se emite. Nunca se refleja un origen arbitrario;
  Access-Control-Allow-Origin contiene un origen exacto configurado y se añade Vary: Origin.

Preflight válido: OPTIONS con Origin, Access-Control-Request-Method y, si corresponde,
Access-Control-Request-Headers. Devuelve 200 JSON `{"status":"ok"}` y permisos acotados.
Origen/método/cabeceras no permitidos: 400 JSON con `error.code=CORS_PREFLIGHT_DENIED`,
mensaje genérico y request_id, sin reflejar valores introducidos. No requiere token,
no ejecuta login y no valida disponibilidad de la ruta: el método real puede dar 404/405.
OPTIONS sin Access-Control-Request-Method es una petición ordinaria y suele devolver
405 para estas rutas. No debe usarse como comprobación de autenticación.

Ejemplo reproducible sin tokens (servicio local arrancado con el perfil Vite):

```bash
curl -i -X OPTIONS http://127.0.0.1:8000/api/v1/assets \
  -H 'Origin: http://localhost:5173' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: Authorization,Content-Type,Idempotency-Key'
```

## Respuestas y fronteras de seguridad

El middleware CORS envuelve el límite de cuerpo y el manejo seguro de excepciones;
respuestas 401/422/413/500/503 para un origen permitido conservan CORS, correlación y
JSON. Preflight genera su propio X-Request-ID y no-store/nosniff. Un origen no listado
no recibe Allow-Origin; un navegador no podrá leer la respuesta. Eso **no** implica
que toda petición HTTP real con ese Origin devuelva 403: si posee Bearer válido puede
ser procesada por la API, como cualquier cliente no navegador. Sin Bearer sigue siendo
401; usuario B sigue recibiendo 404 al consultar A, aunque el origen esté permitido.

Los permisos CORS no delimitan rutas, propietarios ni sesiones. No ampliar allow_methods
o allow_headers solo para silenciar errores del cliente; revisar cambios de contrato.
En el cliente web usar cabecera Bearer explícita y `credentials: "omit"`; no introducir
cookies/CSRF o refresh imaginarios. Reverse proxy debe preservar Vary y las cabeceras,
y evitar políticas CORS contradictorias. Probar la combinación final en el navegador;
no se ha desplegado infraestructura TLS ni una aplicación React en esta misión.

Pruebas: preflight permitido/denegado, configuración insegura, errores y cabeceras,
flujo autenticado web, aislamiento de usuarios, retry concurrente web/nativo y HTTP real
Docker. Ver resultados exactos en TEST_RESULTS.md.

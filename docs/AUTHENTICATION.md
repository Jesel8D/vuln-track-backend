# Identidad mínima

Actualización V2: [registro HTTP opt-in](SELF_SERVICE_REGISTRATION.md), reutilizando
este hashing/JWT, con contraseñas de **15–128** caracteres para altas públicas y
workspace personal atómico. El rango12–256 siguiente corresponde al helper de
mantenimiento histórico. No se necesita aprovisionar cada cuenta normal por SQL.

Implementado y probado con PostgreSQL: login JSON, Argon2id (64 MiB, t=3, p=1,
sal individual), comparación mediante argon2-cffi; hash dummy para usuario ausente,
usuario activo obligatorio y respuesta 401 genérica. No se trata el CHECK SQL de hash
como verificación criptográfica. Se acotan parámetros aceptados del hash para evitar
consumo arbitrario. Contraseñas nuevas de 12–256 caracteres; login hasta 256.

El esquema permite hashes seguros, pero `vulntrack_app` no puede leerlos. La integración
local requiere un login dedicado y `GRANT SELECT(password_hash)` **solo a ese login**
(ver README); no se cambió `002_privileges.sql`. El test concede ese permiso únicamente
en su base temporal, después de ejecutar la suite de privilegios original.

Aprovisionamiento explícito de una cuenta nueva de desarrollo:

```bash
read -rsp 'URL de mantenimiento: ' MIGRATION_DATABASE_URL; echo
export MIGRATION_DATABASE_URL
python scripts/provision_user.py operador_local
unset MIGRATION_DATABASE_URL
```

La contraseña se pide dos veces sin eco; solo su hash se inserta. No se modifican
cuentas existentes, no hay contraseña predeterminada y se rechaza `demo_operator`.
El secreto de mantenimiento no debe estar en `.env` del proceso API. La operación debe
hacerse solo por un responsable autorizado, contra la base identificada. Altas masivas,
recuperación y administración de usuarios quedan fuera de alcance.

Tokens Bearer JWT HS256 con secreto aleatorio externo ≥32 bytes. Se validan firma,
algoritmo fijo, issuer, audience escalar estricta, exp/iat/nbf enteros coherentes, sub UUID,
jti y versión de usuario.
TTL máximo 15 minutos, sin refresh. Cada acceso consulta active y updated_at; cualquier
cambio de usuario mediante el trigger V1 invalida los tokens anteriores, incluida una
baja seguida de reactivación. Rotar TOKEN_SECRET revoca todos. No registrar tokens.

**Limitación explícita:** no existe revocación individual ni logout servidor; un JWT
robado sigue válido hasta expirar, cambiar usuario o rotar el secreto. La propuesta
principal de Context prefiere sesiones opacas revocables, pero V1 no tiene tabla de
sesiones. JWT es una alternativa provisional, compatible sin nuevo DDL. No se anuncian
las expiraciones por inactividad ni cookies/CSRF de aquella propuesta como implementadas.
Web debe revisar almacenamiento/CSRF antes de adoptar un transporte; móvil requiere
almacenamiento seguro de plataforma. HTTPS obligatorio antes de uso remoto.

Limiter local con bloqueo de threads, cuota por cuenta y origen, claves HMAC y memoria
acotada. No confía en X-Forwarded-For; no sustituye un control compartido para múltiples
réplicas. Puede denegar temporalmente cuentas atacadas: revisar política de abuso.

## Autorización propuesta V1.1: propiedad individual

Estado **PROPUESTA**, pendiente de aprobación formal antes de integración. En esta rama,
la API verifica primero JWT, usuario activo y versión de identidad; después usa su UUID
como propietario, nunca un dato del cuerpo o cabecera de identidad libre.

`AssetAuthorization` filtra `assets.created_by = user.id` en PostgreSQL. Crear/listar
requiere una identidad UUID validada por la dependencia de autenticación; los usuarios
activos pueden crear sus propios activos. No hay administrador, rol global ni bypass.
El listado y su total comparten el filtro y snapshot. Detalle ajeno, sin dueño o ausente
produce el mismo 404. No hay actualización/eliminación/asignación de propiedad en la API.
`created_by` no forma parte del esquema de entrada ni de salida: extra=forbid rechaza
cualquier intento de enviarlo, incluso null o el ID propio.

La columna nullable conserva los históricos sin dueño. Ni idempotency.user_id ni el
iniciador de un análisis acreditan propiedad. Solo una futura asignación explícita,
autorizada y auditada podría vincular históricos: no se preparó un endpoint ni se hizo
backfill. Usuario inactivo no puede crear, consultar, listar ni recuperar un replay.

Las pruebas de V1.1 utilizan login real, hashes reales, JWT y la política entregada,
sobre PostgreSQL desechable. Se retiró FixtureAuthorization: ninguna prueba positiva
de V1.1 sustituye la política ni la dependencia de autenticación. La confianza en el
login SQL es una frontera técnica: no se añade RLS ni se permite acceso SQL de clientes.
La decisión de propiedad y el despliegue siguen sujetos a aprobación, aunque funcionen
y estén probados en esta propuesta. Ver MIGRATIONS y OPEN_DECISIONS.

V1.3 mantiene este mecanismo y agrega CORS explícito sin cookies. Ver
[CORS](CORS.md), [contrato web/móvil](FRONTEND_MOBILE_INTEGRATION.md) y
[revisión JWT/propuesta de revocación individual](JWT_SECURITY_REVIEW.md). Esta última
es documentación de evolución pendiente, no otra sesión, tabla o endpoint implementado.

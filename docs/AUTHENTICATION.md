# Identidad mínima

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
algoritmo fijo, issuer, audience, exp, iat, nbf, sub UUID, jti y versión de usuario.
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

## Autorización: bloqueo real

Database V1 carece de `assets.created_by`, roles de negocio, ACL o grants por objeto.
La existencia de `asset_registration_requests.user_id` identifica un intento, **no un
permiso de acceso**. Tampoco `analysis_runs.initiated_by` acredita propiedad del activo.
Por ello AssetAuthorization deniega crear/listar y genera filtro SQL false para detalle.
Nadie autenticado puede enumerar ni leer activos ajenos; tampoco hay activos permitidos
hasta implementar un modelo aprobado. No se inventaron columnas, tenants ni administrador
permanente. La API no ofrece modificación/eliminación.

Los tests positivos usan FixtureAuthorization solo en `tests/`, con un marcador
sintético de fixtures, sin sustituir autenticación: login/hash/JWT/PostgreSQL son reales.
No se distribuye esa clase en la imagen. Esto prueba los componentes independientes,
no acredita permisos operativos del producto. Véase OPEN_DECISIONS antes de habilitar.

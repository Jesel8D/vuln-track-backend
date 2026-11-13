# Registro público controlado de usuarios V2

Implementación para revisión, 2026-11-13. No constituye aprobación global del
modelo V2, producción ni del reemplazo del inventario de dispositivos.

## Base inspeccionada

Se recuperaron los cuatro repositorios oficiales mediante Git y `fetch origin`.
Backend `rudi` = `c1feca473fe8c553f0eac26d71a8651aaa0f2f26`; Database `rudi` =
`6fa928105d9157fbd78b66a17f8b86f9353857e0`; Frontend `rudi` =
`6cbdb0bc7424635d8d594467b413c303f91aa75a`; Context `rudi` =
`05195760ab8c08e6b74a3ad6ae01268a4e9d4386`.
Ramas nuevas: `feat/v2-self-service-registration`,
`feat/v2-registration-database` y `feat/v2-registration-web`. Context es solo lectura.
Las referencias anteriores y `main` se conservan; no hay merge ni push.

El login existente usaba `users` de Database V1 y `scripts/provision_user.py`,
con URL de mantenimiento y `getpass`. No existía registro HTTP. El seed
`demo_operator` continúa inactivo y sin contraseña; no se modifica ni activa.
No existe correo, verificación de correo, administrador global ni columna de rol
en `users`. Los roles `owner/editor/viewer` pertenecen a una membresía concreta.

## Contrato y transacción

`POST /api/v1/auth/register` es público **solo si `REGISTRATION_ENABLED=true`**.
Campos exclusivos: `username` y `password`; extras se rechazan con 422.
Usuario ASCII de 3–80 caracteres `[a-z0-9][a-z0-9_.-]*`, normalizado con trim y
minúsculas. El login mantiene su contrato histórico, incluido el rango 1–80 para
cuentas ya existentes; debe usarse el nombre canónico devuelto al registrar.

```json
{"username":"nuevo_usuario","password":"Una frase privada de ejemplo 7319!"}
```

La contraseña del ejemplo no es una cuenta ni una credencial operativa. Elegir una
frase privada diferente. Se admiten 15–128 caracteres, incluidos espacios y Unicode
visible. No se recorta ni normaliza la contraseña. Se rechazan controles,
caracteres no asignados/sustitutos, contraseñas triviales, patrones periódicos y
un conjunto local pequeño de contraseñas comunes. Esa lista no es un catálogo
exhaustivo de contraseñas filtradas. No se exige una composición artificial de símbolos.

Respuesta confirmada **201**:

```json
{"id":"4c0e7cc6-2c5c-4d9f-af45-115f9d7fb1c1","username":"nuevo_usuario"}
```

La respuesta no contiene password, hash, JWT ni roles. No inicia sesión automáticamente.
Después: `POST /api/v1/auth/login` → Bearer → `GET /api/v1/auth/me` →
`GET /api/v2/workspaces`. El directorio firmado devuelve el workspace personal.
La API vigente de aplicaciones/tecnologías se utiliza con ese ID autorizado.

Algoritmo en `RegistrationService`:

1. Admisión limitada por conexión cliente y globalmente; hasta dos hashes de registro simultáneos.
2. Argon2id vigente (64 MiB, tres iteraciones, un hilo), antes de abrir transacción.
3. Una sesión/transacción inserta `users` con UUID generado en servidor y `active=true`.
4. `users_username_key` arbitra duplicados y carreras; no hay SELECT previo vulnerable a carreras.
5. Se instala el contexto HMAC bootstrap existente sobre **esa misma transacción**.
6. Se insertan workspace `Personal de <username>`, membresía propia `owner` y evento
   append-only `account.registered`, sin payload ni secretos.
7. Se comprueban FKs y guards diferidos; se confirman todas las filas juntas.

Un fallo revierte cuenta, workspace, membresía y auditoría. Reintentar el mismo
usuario después de un commit devuelve 409; no crea otro workspace ni cambia la
contraseña existente. Ante respuesta perdida, intentar primero login. No se
introduce otra tabla idempotente ni se permite cambiar la cuenta mediante registro.
La unicidad es permanente, sin ventana de expiración. El 409 usa el mismo código
para cuenta activa, inactiva y reintento; no devuelve identidad existente ni causa
detallada. La diferencia 201/409 revela disponibilidad del username; no se promete
ocultar ese hecho. No hay endpoint de consulta de disponibilidad.

## Errores y configuración

| HTTP | Código | Comportamiento |
|---|---|---|
| 422 | `VALIDATION_ERROR` | Revisar campos/política; no se reflejan valores introducidos. |
| 409 | `REGISTRATION_UNAVAILABLE` | Otro username o login si pudo completarse un intento anterior. |
| 429 | `REGISTRATION_RATE_LIMIT` | `Retry-After: 60`; no hay reintentos automáticos. |
| 503 | `REGISTRATION_DISABLED` | Operador no habilitó este servicio. |
| 503 | `REGISTRATION_BUSY` | Dos hashes en curso; `Retry-After: 3`. |
| 503 | `REGISTRATION_NOT_READY` | Falta permiso de inscripción; ninguna cuenta creada. |
| 503 | `DATABASE_CONTEXT_INVALID` | HMAC no válido; transacción revertida. |

Todos usan el envelope `{error:{code,message,request_id}}` y no-store.

```dotenv
REGISTRATION_ENABLED=true
REGISTRATION_ATTEMPTS_PER_MINUTE=3
REGISTRATION_TOTAL_PER_MINUTE=20
CORS_ORIGINS=["http://127.0.0.1:5173"]
```

También se requieren `DATABASE_URL`, `TOKEN_SECRET` y `WORKSPACE_HMAC_KEY` privados.
El registro se deshabilita por defecto y exige HMAC válido en configuración.
El limitador usa una ventana de 60 segundos, almacenamiento acotado y HMAC de la IP
del socket; no guarda IPs/usuarios en claro ni confía en X-Forwarded-For.
El launcher usa `--no-proxy-headers --no-access-log`. Detrás de un proxy debe
configurarse y probarse explícitamente la confianza de origen; nunca aceptar
cabeceras de cualquier cliente. Varias réplicas necesitan un limitador compartido
en el perímetro; las cuotas actuales son por proceso y se reinician al arrancar.
No hay CAPTCHA, verificación de persona ni servicio de email.

## PostgreSQL y D-002

**Sin cambios de tablas, columnas, ORM ni nueva revisión Alembic.** La revisión
actual sigue siendo `0004_mvp_cve`. Database administra el nuevo script de
privilegios `sql/006_self_service_registration.sql` y su inclusión en bootstrap.
Crea el grupo opt-in `vulntrack_registration` NOLOGIN, sin administración ni BYPASSRLS;
concede solo INSERT de `id,username,password_hash,active` en `users`.
No otorga UPDATE/DELETE de usuarios, lectura de hashes, elección de timestamps,
administración de roles ni acceso a la clave HMAC. El grupo existente `vulntrack_app`
no recibe esta nueva membresía automáticamente.

Un operador concede `GRANT vulntrack_registration TO <login_api_dedicado>` **una
vez por instalación**, además de los permisos previos de login. Esto elimina la
intervención por cuenta, no la administración segura de la infraestructura.
El login API nunca es el operador de mantenimiento.

V2 tenía tablas fuera del ORM heredado: el verificador anterior rechazaba el
bootstrap V2 y `alembic check` proponía eliminar esas tablas. Ahora se verifica
el delta V2 completo contra `v2_additions_catalog.json`, obtenido de PostgreSQL16.15
aplicando los SQL004/005 originales fijados en `v2_source_manifest.json`:
10 tablas, 112 columnas, 95 restricciones, 32 índices, 12 triggers, 13 funciones
y 29 políticas. Solo después de esa comprobación se compara el ORM heredado.
Un objeto desconocido, FK/trigger/política modificada o RLS deshabilitado bloquea
la operación. Alembic no administra ni elimina las tablas V2 que aún usa SQL textual.
No se cambia un snapshot histórico para aceptar diferencias arbitrarias.

Instalación existente compatible: V1/MVP-B → Alembic0004 verificado → SQL004 →
SQL005 → SQL006. Si V2 ya está aplicado, el verificador permite reconocerlo antes
de actualizar únicamente las tablas heredadas. Instalación nueva: bootstrap
Database001/002/004/005/006 → Alembic0001..0004 **con validación previa del catálogo**.
Ninguna ruta usa stamp ciego ni `create_all`. Los seeds se ejecutan antes de
Alembic MVP-B: sus guards de evidencia rechazan reinsertar ejecuciones terminales,
incluso con ON CONFLICT. No se altera el seed para ocultar esa incompatibilidad.
Ver la guía coordinada del repositorio Database.

`/ready` comprueba el perfil heredado y, si HMAC está configurado, las dependencias
V2. Si el registro está habilitado, comprueba además sus permisos de INSERT.
No sustituye la verificación integral del catálogo ni demuestra por sí solo que la
clave configurada coincida con la de PostgreSQL; una firma errónea falla sin crear cuentas.

## Aislamiento y límites

Los IDs de cuenta/workspace y el rol owner se generan exclusivamente en servidor.
No hay `is_admin`, `is_superuser`, `verified_email` ni workspace elegible en el input.
`SET LOCAL` y las funciones firmadas existentes siguen controlando cada transacción
V2; commit/rollback limpian el contexto antes de reutilizar conexiones. RLS no se
deshabilita. Se comprueba conexión única reutilizada, consulta SQL sin filtro,
firma inválida, contexto manipulado/expirado y usuarios A/B reales registrados por HTTP.
El usuario normal conserva autorización por activo en V1 y membresía en V2.

JWT continúa HS256 estricto, firma/issuer/audience/tiempos y usuario activo/versión
validados por petición; máximo 900s. No hay refresh ni revocación individual.
Logout React elimina memoria/cachés, no revoca un JWT ya emitido. No se almacenan
tokens/contraseñas en localStorage, sessionStorage, URLs ni logs.

Registro de URL no acredita permiso para escanear. No se incorpora tráfico de red
a destinos, ZAP, Nmap, escaneo anónimo ni una integración NVD nueva. El botón ZAP
existente continúa deshabilitado. Las pruebas no consultan NVD real.

## Reproducción

Con los tres repositorios hermanos recuperados y las dependencias del backend instaladas:

```bash
python -m scripts.test_v2_registration --installation existing --full
python -m scripts.test_v2_registration --installation new
python -m pytest -q tests/unit
ruff check .
python -m pip check
alembic heads
```

Los runners crean exclusivamente PostgreSQL nuevo con tmpfs, credenciales aleatorias
y puerto efímero localhost; nunca aceptan una URL de base existente. Detienen solo
su contenedor y no utilizan volúmenes persistentes. Para navegador, desde Frontend:

```bash
../vuln-track-backend/.venv/bin/python scripts/v2_registration_stack.py --api-port 8000 --web-port 5173
```

Abrir `http://127.0.0.1:5173/crear-cuenta`, crear usuario y frase propia, abrir login,
iniciar sesión, comprobar workspace personal y estado vacío, registrar aplicación,
añadir tecnología y cerrar sesión. **Este launcher es desechable: Ctrl+C descarta
datos.** En una instalación persistente administrada, las cuentas y el historial
residen en PostgreSQL; no se borran por logout. No se ha operado una base persistente
en esta misión. Ver `SELF_SERVICE_REGISTRATION_RESULTS.md` para evidencia y omisiones.

## Decisiones pendientes y demo

El modelo workspace/aplicaciones, su convivencia con dispositivos, cuotas de
cuentas/activos y gobierno de destinos siguen pendientes de decisión global.
Context contiene D-003 aprobada en JSON/documento específico, aunque su README
aún dice “solo D-001 y D-002”; no se reescribe esa contradicción aquí.
Faltan recuperación/cambio de contraseña, verificación de correo si se incorpora,
retención/eliminación de cuentas, defensa distribuida contra abuso, gestión/rotación
operativa de HMAC, carga, backups/restauración y despliegue HTTPS/CSP revisados.

Modo anónimo: **evaluación, no activación**. Es viable una demo futura con fixtures
públicos rotulados y estado local separado, sin endpoints privados, escrituras,
workspaces reales, NVD en vivo ni ejecución de análisis. Registro autenticado sigue
siendo el flujo normal para guardar recursos e historial.

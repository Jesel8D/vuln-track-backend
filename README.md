# VulnTrack Backend V1 — entrega para revisión

API modular FastAPI para el flujo móvil → backend → PostgreSQL. Compatible con
Database V1 `b493fd1`, sin recrear sus tablas. **V1 todavía no está completo**:
el esquema no contiene propiedad ni ACL de activos. Por seguridad, la política
operativa deniega creación/listado (403) y detalle (404). El servicio transaccional
subyacente se implementó y probó con ámbitos sintéticos explícitos; eso no constituye
una política de permisos del producto. No hay un interruptor para desactivar esa barrera.

Implementados: configuración validada, SQLAlchemy/Psycopg síncronos, modelos de las
cinco tablas, login Argon2id/JWT, identidad activa y revocación por cambio de usuario,
errores uniformes, límite de cuerpo, rate limit de login, health/readiness, servicio
de activos paginado, idempotencia concurrente y baseline Alembic verificado.

## Requisitos e instalación

Ubuntu/Kubuntu, Python **3.12**, Docker Engine y Compose para Database V1/pruebas.
Versiones exactas en `requirements.lock` y `requirements-dev.lock`; probadas:
FastAPI 0.162.0, Pydantic 2.14.2, pydantic-settings 2.16.2, SQLAlchemy 2.0.55,
Psycopg 3.3.6, Alembic 1.20.1, Argon2-cffi 25.1.0, PyJWT 2.15.1,
pytest 9.2.0, httpx 0.28.1 y Ruff 0.17.3. Se resolvieron versiones disponibles
compatibles con Python 3.12 y se fijaron también sus dependencias transitivas.

```bash
git clone https://github.com/Jesel8D/vuln-track-backend
cd vuln-track-backend
# Seleccionar la rama/commit entregado cuando esté publicado; esta misión no hizo push.
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps -e .
cp .env.example .env
chmod 600 .env
python -c 'import secrets; print(secrets.token_urlsafe(48))'
# Editar .env: usar ese secreto como TOKEN_SECRET y configurar DATABASE_URL.
```

El comando genera un secreto operativo nuevo localmente: no compartirlo, copiarlo al
repositorio ni usarlo como contraseña de dispositivo. `.env.example` contiene solo
marcadores; su TOKEN_SECRET no supera la validación intencionadamente.

## PostgreSQL local y arranque

Mantener los repositorios como directorios hermanos. Database es propietario de
Compose/bootstrap/seed; este backend no copia su infraestructura.

```bash
cd ..
git clone --single-branch --branch feat/postgresql-database-v1 \
  https://github.com/Jesel8D/vuln-track-database
cd vuln-track-database
cp .env.example .env
chmod 600 .env
# Editar .env: reemplazar la contraseña pública de ejemplo ANTES del primer arranque.
docker compose --env-file .env -p vulntrack-dev up -d --wait postgres
docker compose --env-file .env -p vulntrack-dev exec postgres \
  sh -c 'exec psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
```

En esa sesión administrativa, provisionar explícitamente el login API (no reutilizar
el dueño). Revisar este permiso de autenticación adicional: Database V1 excluye hashes
por defecto y el login local necesita verificarlos. No cambia columnas ni el grupo original.

```sql
CREATE ROLE vulntrack_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password vulntrack_api
GRANT vulntrack_app TO vulntrack_api;
GRANT SELECT (password_hash) ON vulntrack.users TO vulntrack_api;
\q
```

Configurar `DATABASE_URL` de `.env` con ese login, contraseña codificada para URL,
host `127.0.0.1`, puerto `55432`, base `vulntrack`. No usar `postgres` ni
`vulntrack_owner`. La conexión rechaza también roles administrativos y dueños del esquema.

```bash
cd ../vuln-track-backend
source .venv/bin/activate
python -m app.db.verify_schema
uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 \
  --no-proxy-headers --no-access-log
# Otra terminal:
curl --fail http://127.0.0.1:8000/health
curl --fail http://127.0.0.1:8000/ready
```

`/health` comprueba HTTP; `/ready` comprueba rol no administrativo y lectura de tablas
esenciales. Readiness no significa que la autorización del producto esté resuelta.
Para detener: Ctrl+C y `docker compose --env-file .env -p vulntrack-dev stop postgres`
desde Database. No usar `down -v`. Un volumen existente no se reinicializa al cambiar `.env`.

Para crear **una cuenta nueva** local mediante mantenimiento, ver
[autenticación](docs/AUTHENTICATION.md). El seed se conserva inactivo y sin contraseña.

## Variables

| Variable | Valor/límite |
|---|---|
| `DATABASE_URL` | Obligatoria, `postgresql+psycopg://…`; secreto |
| `TOKEN_SECRET` | Obligatorio, mínimo 32 bytes, aleatorio; secreto |
| `ENVIRONMENT` | `development`, `test`, `production` |
| `TOKEN_TTL_SECONDS` | 900; rango 60–900 |
| `DB_POOL_SIZE`, `DB_MAX_OVERFLOW` | 5, 5; conexiones por proceso |
| `DB_POOL_TIMEOUT`, `DB_POOL_RECYCLE` | 30 s, 1800 s |
| `DB_POOL_PRE_PING` | true |
| `DB_CONNECT_TIMEOUT` | 5 s |
| `DB_STATEMENT_TIMEOUT_MS`, `DB_LOCK_TIMEOUT_MS` | 10000, 3000 |
| `MAX_BODY_BYTES` | 8192; incluye cuerpos sin Content-Length |
| `LOGIN_ATTEMPTS_PER_MINUTE` | 10 por cuenta y origen, por proceso |
| `MIGRATION_DATABASE_URL` | Solo herramientas administrativas, nunca proceso API |

Producción exige `sslmode=verify-full&sslrootcert=/ruta/ca.pem` en la URL. Desarrollo
local usa el enlace localhost de Database sin TLS. La API requiere HTTPS mediante
terminación TLS correctamente operada antes de uso remoto. No hay CORS abierto ni
confianza automática en cabeceras de proxy. Limitar conexiones/tiempos HTTP en el proxy.

## API y ejemplos

| Método | Ruta | Autenticación | Estado operativo |
|---|---|---|---|
| GET | `/health` | No | Implementado |
| GET | `/ready` | No | Implementado, PostgreSQL real |
| POST | `/api/v1/auth/login` | Usuario/contraseña | Requiere cuenta nueva y grant del hash |
| GET | `/api/v1/auth/me` | Bearer | Implementado |
| POST | `/api/v1/assets` | Bearer + Idempotency-Key UUID | 403: política pendiente |
| GET | `/api/v1/assets` | Bearer | 403: política pendiente |
| GET | `/api/v1/assets/{asset_id}` | Bearer | 404: ningún activo visible |

OpenAPI en `/docs`. Login JSON: `{"username":"operador_local","password":"…"}`;
respuesta `access_token`, `token_type: bearer`, `expires_in: 900`. No incluir tokens en
URLs o logs. Usar un cliente seguro para enviar contraseñas; evitar argumentos de shell
que queden en el historial. No hay logout ni refresh; ver las limitaciones de revocación.

Con un token guardado **localmente** en `VULNTRACK_TOKEN`:

```bash
curl -H "Authorization: Bearer $VULNTRACK_TOKEN" http://127.0.0.1:8000/api/v1/auth/me
curl -H "Authorization: Bearer $VULNTRACK_TOKEN" \
  'http://127.0.0.1:8000/api/v1/assets?limit=20&offset=0'
curl -X POST http://127.0.0.1:8000/api/v1/assets \
  -H "Authorization: Bearer $VULNTRACK_TOKEN" \
  -H "Idempotency-Key: $(python -c 'import uuid; print(uuid.uuid4())')" \
  -H 'Content-Type: application/json' \
  --data '{"device_type":"router","manufacturer":"Ejemplo","model":"A","version":"1.2","site_label":"LAB"}'
```

Los dos comandos de activos devuelven actualmente 403. No se ofrece un ejemplo que
finja creación autorizada. Tras aprobar e implementar una política, el servicio está
preparado para 201 con `Location`, detalle 200 y listado `{items,page:{limit,offset,total}}`.
Conservar formulario y la misma clave ante resultado incierto, no generar otra en cada
reintento. Ver [idempotencia](docs/IDEMPOTENCY.md) antes de integrar clientes.

## Pruebas

```bash
source .venv/bin/activate
python -m pytest -q                         # Independientes; PostgreSQL se omite explícitamente
ruff check .
python -m pip check
DATABASE_V1_PATH=../vuln-track-database python scripts/test_postgres.py -q
```

El runner crea un contenedor **nuevo** PostgreSQL 16.15 con datos tmpfs desechables,
contraseña aleatoria, puerto solo localhost y login API mínimo. Verifica hashes de
los SQL de referencia, aplica esquema/privilegios/seed y ejecuta integridad y pytest.
Nunca acepta una URL persistente como destino del runner. Al terminar detiene solo
su contenedor; tmpfs se pierde. No borra volúmenes existentes ni cambia referencias.
Los contenedores detenidos quedan identificados por `vulntrack-backend-test-*`.

```bash
docker build -t vulntrack-backend:v1 .
DATABASE_V1_PATH=../vuln-track-database python scripts/test_postgres.py --docker-smoke
```

En Codex Cloud, el build se verificó con
`docker build --secret id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt -t vulntrack-backend:v1 .`.
El certificado solo se monta durante instalación; nunca se deshabilita TLS.

Para ejecutar la imagen junto al Compose local: copiar `.env` a `.env.docker` (ignorado),
cambiar **solo el host/puerto DB** a `postgres:5432` y arrancar:

```bash
docker run -d --name vulntrack-api --network vulntrack-dev_default \
  --env-file .env.docker -p 127.0.0.1:8000:8000 vulntrack-backend:v1
docker stop vulntrack-api
```

## Arquitectura, seguridad y límites

`app/api`: rutas/dependencias; `core`: configuración, hashes/tokens, límites/errores;
`db`: engine/sesiones y verificación; `models`: SQLAlchemy V1;
`schemas`: Pydantic; `services`: transacción y política cerrada. Sesiones síncronas
por operación, engine compartido por proceso, escrituras atómicas y rollback automático.
No se agregaron capas vacías de repositorios ni `create_all()`.

**No habilitados:** propiedad/ACL, gestión avanzada de cuentas, sesiones opacas,
revocación individual de JWT, escaneos, NVD, ZAP, frontend y móvil. Registrar un router
no autoriza escanearlo. Notas solo no sensibles: validarlas no detecta secretos.
La limitación de login es local al proceso; hace falta una cuota compartida en el borde
antes de múltiples réplicas. No se ha certificado preparación para producción.

- [Arquitectura y decisiones](docs/ARCHITECTURE.md)
- [Integración/baseline de Database](docs/DATABASE_INTEGRATION.md)
- [Endpoints](docs/API_ENDPOINTS.md)
- [Identidad y operación](docs/AUTHENTICATION.md)
- [Idempotencia y concurrencia](docs/IDEMPOTENCY.md)
- [Resultados reales](docs/TEST_RESULTS.md)
- [Decisiones pendientes](docs/OPEN_DECISIONS.md)
- [Fuentes inspeccionadas](docs/INSPECTION.md)

# VulnTrack Backend

Registro público V2 opt-in y workspace personal transaccional preparados para
revisión: [contrato y ejecución](docs/SELF_SERVICE_REGISTRATION.md),
[compatibilidad MVP/V2](docs/MVP_V2_COMPATIBILITY.md) y
[resultados reales](docs/SELF_SERVICE_REGISTRATION_RESULTS.md).
Requiere SQL006 de Database y el permiso específico del login API; no cambia
tablas ni añade roles administrativos globales. No habilita ZAP.

API FastAPI para autenticar usuarios, consultar NVD y guardar resultados en PostgreSQL. La rama `rudi` conserva los flujos históricos V1/MVP-A/B y añade endpoints NVD para el modelo de aplicaciones V2. Los resultados nuevos usan `workspaces`, `applications`, `technologies`, `application_analysis_runs` y `application_findings`; cada operación V2 instala el contexto HMAC por transacción y PostgreSQL aplica RLS.

## Configuración

Requiere Python 3.12 y PostgreSQL 16. Instala el entorno y prepara `.env` desde `.env.example`. Usa un login de API de privilegios mínimos; nunca uses `postgres` ni `vulntrack_owner`. Configura:

- `DATABASE_URL`: conexión SQLAlchemy/psycopg al PostgreSQL preparado con V1, V2, `005_v2_nvd_evidence.sql` y migraciones Alembic del backend.
- `TOKEN_SECRET`: secreto aleatorio de al menos 32 bytes para JWT.
- `WORKSPACE_HMAC_KEY`: 64 caracteres hexadecimales minúsculos correspondientes a la clave de `vulntrack_private.context_keys`. Provisionar desde el operador al gestor de secretos, fuera de Git. La clave nunca se registra ni acepta desde el cliente.
- `NVD_API_KEY`: opcional; solo la usa el backend. No se necesita para los endpoints.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps -e .
cp .env.example .env
# Editar .env usando valores secretos locales.
uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000
```

Los esquemas existentes requieren migración explícita después de backup. No usar `create_all()` ni ejecutar migraciones contra datos persistentes sin restaurar y validar primero una copia. Los tests de PostgreSQL crean su propio entorno desechable.

## API NVD V2

Requiere JWT Bearer. Las búsquedas usan el servicio fijo HTTPS de NVD; el cliente no puede enviar una URL de destino.

| Método | Ruta | Uso |
|---|---|---|
| GET | `/api/v2/workspaces` | Listar solo los workspaces del usuario autenticado mediante función firmada de directorio. |
| POST | `/api/v2/workspaces` | Crear primer workspace con `Idempotency-Key` UUID; la API también crea la membresía `owner` en la misma transacción. |
| GET | `/api/v2/workspaces/{workspace_id}` | Consultar un workspace al que pertenece el usuario. |
| POST / GET | `/api/v2/workspaces/{workspace_id}/applications` | Crear y listar aplicaciones web del workspace. |
| POST / GET | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies` | Registrar/listar tecnologías y versiones para una aplicación. |
| GET | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/cpe-candidates?query=...` | Buscar candidatos en el diccionario NVD. |
| PUT | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies/{technology_id}/cpe` | Resolver por ID en NVD y guardar CPE solo tras confirmación del usuario. Requiere `expected_selected_cpe` para control de concurrencia. |
| POST | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies/{technology_id}/analyses` | Consultar CVE para tecnología confirmada; requiere `Idempotency-Key` UUID. Devuelve estado, cobertura, conteos y timestamp de NVD. |
| GET | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/analyses/{run_id}` | Consultar estado, cobertura y fallos tipados. |
| GET | `/api/v2/workspaces/{workspace_id}/applications/{application_id}/analyses/{run_id}/findings` | Listar hallazgos persistidos con paginación. |

Una consulta recupera como máximo 100 CVE por solicitud. Si NVD informa más resultados, la cobertura queda `partial` y se almacena `PAGE_BUDGET_REACHED`; nunca se presenta como consulta exhaustiva. La evidencia original se conserva de forma acotada. La regla `cpe-conservative-1` puede marcar una coincidencia `potential` o `undetermined`; solo una revisión humana puede concluir aplicabilidad. La búsqueda usa el [Products API oficial de NVD](https://nvd.nist.gov/developers/products) y los CVE usan el [Vulnerabilities API 2.0](https://nvd.nist.gov/developers/vulnerabilities).

## Escaneo web y límites

NVD no escanea URLs ni descubre por sí solo las tecnologías instaladas. Este backend busca CVE asociados a un CPE previamente confirmado. El escaneo pasivo ZAP aún no está conectado. Antes de habilitarlo se requieren autorización vigente del destino, verificación DNS en cada conexión/redirección, bloqueo de loopback/red privada/link-local/metadatos, límites de recursos y aislamiento del ejecutor. No se ejecuta Active Scan, explotación, reparación automática ni escaneo de repositorios.

Las peticiones NVD salen con un cliente de origen fijo, sin seguir redirecciones, con timeout, límite de cuerpo y validación de esquema. Las cuotas locales limitan frecuencia; una instalación con múltiples réplicas necesita una cuota compartida antes de escalar. Un estado `complete` describe páginas recuperadas, no ausencia de riesgo ni exhaustividad del catálogo. Ver [contrato, límites y seguridad V2](docs/V2_NVD_INTEGRATION.md).

## Pruebas y estado

```bash
python -m pytest -q
ruff check .
python -m pip check
```

La suite existente documenta verificaciones previas para V1/MVP-A/B. La integración nueva con V2 requiere ejecutar las pruebas SQL V2 extendidas y pruebas de API contra una base desechable con la migración `005`; no se afirma certificación de producción. Consulta `docs/MVP_A.md`, `docs/MVP_B.md`, `docs/MVP_B_RESULTS.md`, `docs/INTEGRATION_SECURITY_REVIEW.md` y `../vuln-track-database/docs/DATABASE_V2_PLAN.md`.

## Colección y documentación reproducible de API V2

En la rama `test/v2-api-collection`, consultar [api-tests/v2/README.md](api-tests/v2/README.md): OpenAPI versionado, Postman v2.1, entornos sin secretos, runner PostgreSQL desechable y matriz de endpoints. Se distinguen los contratos de activos V1 y aplicaciones V2, y se documentan los defectos existentes sin cambiar funcionalidades ni RLS.

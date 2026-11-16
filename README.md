# VulnTrack Backend

RC1: [integración y resultados actuales](docs/V2_RC1_INTEGRATION_REPORT.md),
[matriz de requisitos](docs/V2_RC1_REQUIREMENTS_MATRIX.md),
[demostración de 13 minutos](docs/V2_RC1_DEMO_GUIDE.md) y
[ejecución aislada/backup/restore](docs/V2_RC1_LOCAL_RUN.md).
Usar `release/v2-rc1-integration` con Frontend `release/v2-rc1-web` y Database
`a562e638dfe5b7e8d07eec0e8046e6998f8a2802`. Candidato local con NVD fixture;
verify, egreso público y ZAP bloqueados. No actualiza la instalación personal.

Fase 2C: [gateway obligatorio y seguridad de egreso](docs/V2_PHASE2C_EGRESS_SECURITY.md),
[resultados y regresiones](docs/V2_PHASE2C_LAB_RESULTS.md) y
[laboratorio reproducible](laboratory/phase2c/README.md).
El nuevo laboratorio demuestra filtros IPv4/IPv6 y fallos seguros con destinos
propios. **Egreso público BLOQUEADO; verify sigue en 503 y ZAP deshabilitado.**
No cambia API, SQL ni Frontend, ni despliega sobre la instalación personal.

Fase 2B: [persistencia, RLS y límites](docs/V2_SECURITY_ANALYSIS_PHASE2B.md),
[contrato HTTP](docs/V2_VERIFICATION_API.md) y
[actualización/reversión](docs/V2_PHASE2B_LOCAL_UPGRADE.md).
SQL008 coordina Database/ORM/Alembic sin cambiar el head legado. La API puede
emitir/consultar/revocar; la verificación remota responde 503 y ZAP sigue bloqueado.
Usar Frontend `feat/v2-security-analysis-web-phase2b` y Database
`feat/v2-security-verification-database`. No hay despliegue personal automático.

Fase 2A: [componentes, pruebas y límites](docs/V2_SECURITY_ANALYSIS_PHASE2A.md),
[actualización y rollback](docs/V2_PHASE1_LOCAL_UPGRADE.md),
[checklist independiente previo a ZAP](docs/V2_ZAP_READINESS_CHECKLIST.md) y
[laboratorio sin salida externa](laboratory/phase2a/README.md).
El transporte y los desafíos se prueban localmente; la verificación remota en
servicio y ZAP siguen bloqueados. Revisar con Frontend
`feat/v2-security-analysis-web-phase2a`, sin despliegue sobre el volumen personal.
El [informe Fase 1](docs/V2_SECURITY_ANALYSIS_PHASE1.md) conserva su alcance histórico.

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

## Estabilización y desarrollo persistente V2

En `feat/v2-stabilization`, usar la [guía de instalación persistente](docs/V2_PERSISTENT_DEVELOPMENT.md) y el [informe de pruebas/correcciones](docs/V2_STABILIZATION_REPORT.md). El volumen dedicado conserva datos entre reinicios; las suites temporales siguen aisladas. La rama Database coordinada incluye SQL007, sin integración con MVP-B.

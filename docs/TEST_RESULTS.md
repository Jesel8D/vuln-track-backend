# Evidencia de integración V1.2 — 30-10-2026

Estado **PROPUESTA**, no aprobación de propiedad ni preparación de producción.
Linux x86_64, Python 3.12.14, Docker 28.4.0 y PostgreSQL real **16.15** con digest
idéntico a Database V1. API/paquete siguen 0.1.1; V1.2 prepara coordinación y herramientas,
no añade endpoints, dependencias ni una nueva revisión de esquema. No se utilizó SQLite.

## Resultados exactos

Python y Ruff se ejecutaron desde `.venv/bin/`. Referencia original Database b493fd1.

| Ejecución | Aprobadas | Fallidas | Omitidas | Excluidas |
|---|---:|---:|---:|---:|
| Suite anterior V1.1, antes de cambios | 56 | 0 | 0 | 0 |
| Completa V1 original → migración, `scripts/test_postgres.py -q` | **71** | **0** | **0** | **0** |
| Bootstrap propuesto nuevo → adopción verificada, `--bootstrap-v11 -q` | **26** | **0** | **0** | **1** |
| pytest sin variables PostgreSQL | **29** | **0** | **42** | **0** |

Las 26 pruebas de bootstrap nuevo son un subconjunto repetido en otra instalación,
no 26 pruebas distintas adicionales. La única excluida allí comprueba readiness de V1
sin migrar y sí se ejecuta en la suite completa. Los 42 skips del comando sin PostgreSQL
son explícitos; el runner completo ejecuta todas, sin modificar asserts originales.

Suite final completa: `vulntrack-backend-test-c78d22b41a27`, **71 passed en 27.05 s**.
Ruta nueva verificada con `vulntrack-backend-test-7d8fa2087968`, **26 passed, 1 deselected**.
El seed original se aplica dos veces en la ruta nueva; preserva activos NULL, usuario
inactivo sin hash, dos análisis y un hallazgo. El catálogo/ORM final es idéntico al de
V1 actualizado por Alembic.

## Comandos reproducibles (únicamente desechables)

```bash
source .venv/bin/activate
python -m pytest -q
ruff check .
python -m pip check
python -m compileall -q app alembic scripts
python -m alembic heads
python scripts/database_proposal.py --database-v1 ../vuln-track-database
DATABASE_V1_PATH=../vuln-track-database python scripts/test_postgres.py -q
DATABASE_V1_PATH=../vuln-track-database python scripts/test_postgres.py --bootstrap-v11 -q
```

Ruff: All checks passed. pip check: No broken requirements found. Compileall: salida 0.
Alembic heads: `0002_asset_owner (head)`. No se cambió main ni ninguna revisión existente.
El materializador verifica SHA-256 de fuente/patch/salida y no modifica Database.
Manifest/source/patch desconocidos se rechazan; no hay un bootstrap paralelo autoritativo.

La ruta original ejecuta **55 aserciones SQL originales** (20 positivas/35 negativas)
antes de migrar, sin modificar el archivo. La ruta propuesta tiene seis FKs: aquel SQL
espera cinco y no se presenta como suite V1.1. Se verifica en su lugar el catálogo exacto,
ORM y pruebas API comunes. Database deberá versionar sus pruebas nuevas tras aprobación.

## Docker y HTTP real

```bash
docker build --secret id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt \
  -t vulntrack-backend:v1.2 .
DATABASE_V1_PATH=../vuln-track-database python scripts/test_postgres.py --docker-smoke
DATABASE_V1_PATH=../vuln-track-database python scripts/test_postgres.py --bootstrap-v11 --docker-smoke
```

Build salida 0, imagen SHA-256
`3c567346dfb35222fc706efc5773e01bb6096e6ee11f5ad6d858209f4475658b`.
Los dos smoke terminaron con salida 0: UID 10001, health/ready/login 200,
creación/replay 201, detalle/listado propios 200 sobre HTTP real.
Proyectos: `vulntrack-backend-test-e8c7694917d6` (migración) y
`vulntrack-backend-test-9a8e4b81d225` (bootstrap nuevo).
CA solo montada durante build; no se deshabilita TLS ni se incorpora al repositorio.

## Cobertura nueva que aporta evidencia

- Patch mínimo aplicado a copia de SQL original fijado; manifiesto verificable.
- Instalación vacía con 001 propuesto, 002/seed originales intactos; reconocimiento
  Alembic solo tras comprobar esquema/ORM. Después `alembic check` y upgrade son repetibles.
- Adopción de V1 o revisión 0001 rechazada; nunca reetiqueta una migración pendiente.
- Falta de índice o trigger deshabilitado bloquea reconocimiento sin dejar versión falsa.
- Fallo después del registro de versión revierte ese registro; datos de negocio intactos.
- Lock compartido entre Alembic/adopción y timeout seguro en dos conexiones.
- Catálogo esperado añade verificación de tgenabled: pg_get_triggerdef no detectaba ese
  drift en V1.1. Snapshot original conservado, sin reescribir sus datos.
- Ejemplos JSON de clientes validados contra modelos reales; rutas/header idempotente y
  rechazo de owner comprobados en OpenAPI; respuestas/headers/redacción probados.
- Ambas rutas repiten login/activos/autorización/paginación/idempotencia/concurrencia reales,
  sin políticas o dependencias de identidad sustituidas. No se habilita CORS para pasar tests.

## Incidencias, avisos y límites

Una ejecución inicial se detuvo con **1 error de colección** por dos módulos de test con
el mismo nombre en carpetas sin paquete. Se añadieron __init__.py para nombres inequívocos;
la suite completa posterior pasó. No se borraron cachés ni se omitieron pruebas para ocultarlo.
Permanece **1 aviso** Starlette/TestClient sobre futura transición de httpx; no afecta resultados
ni se suprimió. No quedan fallos conocidos de pytest/Ruff en la entrega.

No se prueba aquí un backup/restauración de producción, capacidad, múltiples plataformas,
TLS remoto, clientes React/React Native reales ni corte TCP durante commit. El SQL de
bootstrap nuevo se ensaya en clúster dedicado vacío; el rol global del bootstrap original
no es idempotente sobre otro clúster que ya lo contenga. Eso no se oculta ni se debilita.

Todos los servidores son nuevos, tmpfs, password aleatorio y puertos solo localhost;
se detienen al finalizar. No se tocaron datos persistentes, repos externos, credenciales
GitHub, frontend/móvil, NVD ni ZAP. Las propuestas siguen pendientes de aprobación.
Evidencia anterior: [V1](TEST_RESULTS_V1.md) y [V1.1](TEST_RESULTS_V1_1.md).

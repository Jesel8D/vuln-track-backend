# Evidencia MVP-A — 2026-11-08 (America/Mexico_City)

## Recuperación y entorno

Ubicación real: `/home/mz/Desktop/VulnTrack`. HOME=/home/mz y XDG Desktop en
/home/mz/Desktop. VUlnTrack no existía; VulnTrack estaba vacío. No se movió ni
sobrescribió contenido preexistente. SSH autenticó Jesel8D y los cuatro origins
son los repositorios oficiales git@github.com:Jesel8D/vuln-track-{backend,database,
context,frontend}.git (context en context-general-ia). Referencias remotas
consultadas antes de clonar; sin divergencia respecto a históricos solicitados:

| Repositorio | Base recuperada | Commit |
|---|---|---|
| Backend | feat/backend-v1-assets | 2cb124d7cc41e22a62a305760826240f9208c257 |
| Database | feat/postgresql-database-v1 | b493fd17e9290ca94fa085d49230073ed1837e1a |
| Context | docs/mvp-context-consolidation | caa7ef13b0e2b24848991e32b3c0ee3fc59139c7 |
| Frontend | sin commits ni ramas remotas | no HEAD |

Ubuntu24.04.5, Git2.43.0, Python3.12.3 y uv disponibles. Entorno .venv creado
con lockfiles existentes, sin instalaciones Python globales. Docker29.1.3 y
Compose2.40.3 disponibles; PostgreSQL local16.15 detectado pero no utilizado.
Pruebas exclusivamente contra PostgreSQL16.15 Alpine fijado por digest, nombres
aleatorios propios, tmpfs y puerto efímero solo localhost cuando fue necesario.
No se creó .env con secretos operativos ni una base de desarrollo persistente.

Faltaba Buildx para el Dockerfile con secrets de BuildKit. Se descargó Buildx
v0.38.2 del repositorio oficial docker/buildx en configuración temporal bajo
/tmp/vulntrack-docker-buildx-config. Sin cambiar Git/Docker/configuración global.
Build completado con `docker --config /tmp/vulntrack-docker-buildx-config buildx
build --load -t vulntrack-backend:mvp-a .`. No se cambió el Dockerfile original.

Contraparte Database ensayada y comprometida: `80db7fd411f49f648263f275b412384bc49f7ed8`, rama
`feat/mvp-cpe-database`. El manifiesto MVP-A fija sus artefactos SQL exactos.

## Resultados ejecutados

| Verificación | Resultado observado |
|---|---|
| Suite original antes de cambios | 122 passed; SQL V1 correcto |
| Suite final V1 con datos → Alembic head | **194 passed**, 51.77s |
| Suite final bootstrap MVP-A → adopción verificada | **194 passed**, 51.65s |
| SQL V1 original sobre PostgreSQL16.15 | Todas las comprobaciones correctas en ambos runners |
| SQL CPE en ambas rutas | Propiedad, permisos, nulabilidad, historial y restricciones correctos |
| Entrypoint Database real, tmpfs y network none | Correcto; seed repetible y conteos V1 preservados |
| Imagen API, UID10001, servicio HTTP real | health/ready, login, creación/replay/detalle/listado y CORS correctos |
| Ruff app/alembic/scripts/tests | Correcto |
| uv pip check | Dependencias compatibles |
| Revisión sintáctica shell | Correcta |
| Cliente NVD real, resolución UUID oficial | Correcto, no deprecado |

Las dos ejecuciones de194 son la misma suite sobre instalaciones independientes,
**no388 tests únicos**. El caso anterior que exigía version obligatoria se adaptó
al nuevo contrato autorizado; se conservó la regresión de campos requeridos y se
añadieron omisión/null, valores inválidos, lectura histórica y huella de registro.
No se ocultaron fallos para obtener estos resultados. Hubo iteraciones de desarrollo
fallidas (fixture de búsqueda no disponible, preflight de adopción con tabla ausente),
corregidas antes de las ejecuciones finales.

Advertencia existente: Starlette emite deprecación de TestClient/httpx y recomienda
httpx2. No se actualizó el stack fuera del alcance. No invalida los194 casos.

## Cobertura nueva

- Búsqueda con un candidato, varios, vacío y página posterior; metadatos/UUID/CPE,
  JSON/tamaño inválidos, fallo HTTP, conexión, timeout, redirect, parámetros
  codificados y destino HTTPS fijo, key solo header, límites por actor y globales.
- Registro con null/omisión, idempotencia y huella antigua conservada; lectura
  de string histórico unknown sin convertirlo ni aceptar ese string en registros nuevos.
- Confirmación, revisión, reconfirmación y reemplazo por otro UUID oficial; estados,
  snapshots, versión/componente, motivo y expected_current_id.
- Acceso ajeno/inexistente/sin dueño y sin autenticación: rechazo antes de NVD/replay.
- Carreras reales de dos conexiones: claves distintas (un409), misma clave/cuerpo
  (mismo evento) y misma clave/cuerpos distintos (IDEMPOTENCY_CONFLICT).
- Unicidad parcial de actual, FK de historial, permisos e inmutabilidad; cierre
  huérfano rechazado y rollback de cierre ante fallo de inserción.
- V1 y0002 con datos→0003; conservación de OID/inventario/resultados; flags explícitos,
  drift, guard deshabilitado, índice ausente, adopción incorrecta y rollback DDL/marcador.
- Catálogos SQL/ORM y `alembic check` sin diferencias.

Los tests deshabilitan HTTPTransport real y usan MockTransport; no dependen de NVD.
Dos fixtures reales por UUID tienen procedencia en tests/fixtures/README.md. Una
consulta de captura de búsqueda general agotó timeout y no se usó como evidencia.
No se probó la presencia real de un producto en un dispositivo ni se hizo escaneo.

## Seguridad, publicación y límites

Cambios solamente en feat/mvp-cpe-backend y feat/mvp-cpe-database, a partir de
las bases indicadas. Main, rudi, audit y Context quedan sin cambios/merges/rebase.
No se aplica V2/004. Revisión de diff, archivos preparados, secretos detectables y
git diff --check antes de commits. Publicación autorizada por push normal; hashes
exactos locales/remotos se entregan en el informe del chat (evita autorreferencia
imposible del commit que contiene este documento).

Ratificación de Rudi y revisión conjunta PENDIENTES. No habilita producción.
API operativa, sin aplicación frontend/móvil: Frontend continúa vacío. Cuota NVD
local exige una instancia/worker; cuota compartida y confirmación de límites
oficiales vigentes pendientes antes de escalar. Start Here no devolvió contenido
legible. Parser/versión conservadores pueden rechazar equivalencias legítimas.
Selección NVD y confirmación humana no demuestran presencia ni aplicabilidad CVE.

## Estado por objetivo

| Objetivo | Estado |
|---|---|
| Recuperación, referencias y contexto | IMPLEMENTADO Y PROBADO |
| Registro con versión desconocida y propiedad | IMPLEMENTADO Y PROBADO |
| Búsqueda/candidatos por API, confirmación e historial | IMPLEMENTADO Y PROBADO |
| SQL/ORM/Alembic, instalación limpia y migración con datos | IMPLEMENTADO Y PROBADO |
| Autorización, idempotencia y carreras | IMPLEMENTADO Y PROBADO |
| UI móvil/web | PENDIENTE; fuera de implementación de esta vertical backend |
| Ratificación de Rudi/despliegue/escala | PENDIENTE |
| CVE/aplicabilidad/persistencia/seguimiento MVP-B | PENDIENTE; propuesta en MVP_A.md, no iniciado |

Se entrega guía de instalación, contratos, límites, variables, pruebas y propuesta
MVP-B en [MVP_A.md](MVP_A.md). No hay una base persistente de uso diario arrancada;
el entorno de desarrollo y los runners permiten reproducir la vertical validada.

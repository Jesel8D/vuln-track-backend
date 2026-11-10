# MVP-A — registro e identificación CPE

Misión autorizada por Jesel el 2026-11-08. Ratificación de Rudi PENDIENTE;
no cambia decisiones globales ni habilita producción. Base Backend V1.3
`2cb124d` y Database V1 `b493fd1`. Contexto `caa7ef1`, sin modificar.

## Matriz previa de cambios

| Área | Clasificación | Acción |
|---|---|---|
| Login/JWT/usuario activo/propiedad | Ya implementado, reutilizable | Conservar política 404 para ajeno y legado sin dueño |
| Registro/listado/detalle/idempotencia 24 h | Reutilizable | Conservar ruta, huella v1 y snapshots antiguos |
| assets.created_by | Requiere modificación coordinada | SQL bootstrap corresponde a Alembic 0002, sin backfill |
| Versión desconocida | Requiere modificación, autorizada explícitamente en este chat | Pydantic/ORM/SQL nullable; conservar lectura histórica |
| Identificación e historial | Nuevo | Una tabla, FK compuesta, cierre atómico, claves permanentes |
| NVD Products API | Nuevo | HTTPS fijo, paginación limitada, cuotas, validación y fixtures |
| HTTP CPE | Nuevo | GET cpe-candidates, POST/GET assets/{id}/cpe-identifications |
| SQL/ORM/Alembic | Requiere modificación | Nuevo catálogo verificable; conservar V1 y 0002 históricos |
| CVE/worker/seguimiento | Pospuesto | MVP-B, después de validar MVP-A |
| Frontend/móvil | Pendiente | Remoto frontend vacío; no inventar aplicación |
| V2/workspaces/ZAP | Pospuesto | No integrar ni ejecutar |

La suite original ejecutada aquí: PostgreSQL 16.15 desechable, 122 pruebas
correctas y regresión SQL V1 correcta. No son resultados de MVP-A.

## Contrato implementado en esta rama

Autorización posterior explícita de Jesel en este chat: «Sí, implementar versión
 desconocida». Se implementa `version` omitida/null sin atribuir aprobación a Rudi
ni modificar Context. Se rechazan versiones nuevas `unknown`, `*`, `-`, vacías o
no string. Los valores históricos se conservan y pueden leerse. La huella v1 y
los snapshots antiguos de registro no se recalculan.

Rutas (todas Bearer, usuario activo, respuestas no-store y request_id):

| Método/ruta | Entrada | Respuesta |
|---|---|---|
| GET `/api/v1/cpe-candidates` | query 2–200, product_query opcional 1–160, limit 1–20 default10, offset 0–10000 | items: UUID/nombre/título/deprecated, page y source_timestamp |
| POST `/api/v1/assets/{asset_id}/cpe-identifications` | Idempotency-Key UUID, cuerpo discriminado | 201 evento inmutable; Location del recurso consultable |
| GET `/api/v1/assets/{asset_id}/cpe-identifications` | scope=current o history, limit 1–100 default20, offset 0–1000000 | current_state, items, page; valid_to/is_current en items |

Sin evento: pending virtual, items vacíos. Confirmación exige state=confirmed,
cpe_name_id UUID, component_kind (hardware/firmware/os/software),
expected_current_id explícito (null para primer evento) y reason 1–500.
Revisión exige state=needs_review, expected_current_id y reason; prohíbe campos
CPE entrantes y copia snapshot de la confirmación anterior. Solo confirmed puede
pasar a needs_review. Un nuevo confirmed puede reemplazar confirmed/needs_review.
No se borra ni reabre un evento anterior.

Ejemplo de cuerpo de confirmación (UUID real de fixture, no activo inventado):

```json
{"state":"confirmed","cpe_name_id":"c817e5ba-62c1-41e7-a15c-fb851fea761e","component_kind":"firmware","expected_current_id":null,"reason":"Comparado con el componente observado"}
```

Flujo de uso: login existente → POST assets con version string o null → GET
cpe-candidates con búsqueda tecnológica editable → presentar candidatos y pedir
selección humana → POST identificación → GET actual o scope=history. Reusar clave
y cuerpo tras respuesta perdida; nueva intención usa otra clave. `expected_current_id`
procede de la última lectura. No confundir fabricante físico con proveedor del SO.
La API no acredita que exista una interfaz móvil/web: Frontend continúa vacío.

401 sin identidad, 404 para activo ajeno/inexistente/sin dueño, 422 para formato,
campos desconocidos o CPE enviado directamente en body. 409 para selección
inexistente/deprecada, discrepancia de componente/versión, transición inválida,
current_id desactualizado o huella distinta. Límites 429 con Retry-After. NVD
inválido/redirect:502, fallo/conexión/403/429 de origen:503, timeout:504. Los mensajes
externos no se transmiten. Límites de cuerpo 8192 y CORS GET/POST permanecen.

## NVD y límites conocidos

Cliente exclusivamente backend con URL HTTPS constante. Parametriza keywordSearch,
resultsPerPage/startIndex y cpeNameId según [Products API oficial](https://nvd.nist.gov/developers/products).
Una página por búsqueda; el cliente decide pedir otra dentro de offset máximo.
No scraping, referencias, URLs arbitrarias, redirecciones ni descarga masiva.
Valida JSON/UUID/CPE 2.3, metadatos y coherencia de página; máximo 2 MiB decodificados.
No retry automático. NVD_API_KEY opcional SecretStr y solo header apiKey;
NVD_TIMEOUT_SECONDS 1–20 (default10), connect timeout5. Plazo total comprobado
al recibir chunks; un read individual puede añadir hasta el timeout configurado.

Presupuesto local: separación de 7 s entre llamadas, 6 búsquedas/minuto/usuario y
6 eventos nuevos/minuto/usuario; pausa60 tras 403/429/5xx. Replay no consume NVD.
Presupuesto compartido entre búsqueda/resolución **dentro de un solo proceso**.
Ejecutar una instancia y `uvicorn app.main:create_app --factory --workers 1`.
Antes de escalar, implementar cuota compartida entre procesos/instancias/egresos;
otras aplicaciones tras la misma IP también consumen presupuesto NVD. La página
oficial Start Here no devolvió contenido legible al verificar esta misión; no se
declara confirmada la cuota oficial vigente ni se sube presupuesto por tener key.

Confirmar resuelve de nuevo el UUID oficial, rechaza deprecated y solo usa el CPE
retornado por NVD. Comparación conservadora: part h/o/a según componente y versión
conocida exactamente igual tras deshacer escapes y casefold; no intenta resolver
rangos, traducciones, update/edition o equivalencias de versión. Un dato legítimo
no soportado puede requerir revisión humana. Con null se permite identificar sin
afirmar versión suficientemente específica. Sintaxis/procedencia no demuestran que
el producto esté instalado ni la aplicabilidad de una CVE.

## Persistencia y concurrencia

Tabla nueva `asset_cpe_identifications`: id, asset_id, state, cpe_name,
cpe_name_id, component_kind, observed_version, source, validated_at, recorded_by,
recorded_at, reason, replaces_id, valid_to, idempotency_key, request_hash.

PK UUID; FK RESTRICT activo/actor; FK compuesta del reemplazo al mismo activo;
UNIQUE(asset_id,id) y (asset_id,recorded_by,idempotency_key); índices únicos
parciales para actual por activo y sucesor por replaces_id; índice de historial
(asset_id,recorded_at,id). CHECK de estados/componentes/fuente/huella/texto/fechas.
Triggers impiden mutar snapshots/borrar historia y exigen cierre+reemplazo en la
misma transacción mediante constraint trigger diferido. Actor de evento debe
coincidir con propietario. Datos SQL no acreditan por sí solos verificación NVD.

Servicio autoriza antes del replay y de NVD. Revalida estado y replay bajo lock
assets, cierra fila actual e inserta evento atómicamente. No hay locks durante
HTTP. Lecturas bloquean brevemente el activo para obtener página/total/estado
coherentes bajo READ COMMITTED. Primera carrera de selecciones diferentes: un
201 y un 409; misma clave/huella devuelve mismo evento. La respuesta POST omite
valid_to/is_current para que replay siga estable después de sustitución.

Runtime recibe SELECT/INSERT en eventos y UPDATE(valid_to); sin DELETE, DDL ni
UPDATE de snapshots. UPDATE(id) en assets permite SELECT FOR UPDATE; el trigger
V1 bloquea cambios reales de id. No concede modificar created_by. Se conservan
las restricciones de V1: no RLS, aislamiento por API; el login runtime debe quedar
exclusivo del backend, no compartirse con clientes.

## Instalación y actualización coordinadas (D-002)

Database mantiene `001_schema.sql`, `002_privileges.sql` y seed V1 sin modificar.
`sql/bootstrap_mvp_a.sql` es parte de **instalación nueva**, no migración operativa:
añade propiedad equivalente a 0002 y estructura CPE equivalente a 0003.
`VULNTRACK_SCHEMA=mvp-a` hace que el entrypoint nuevo lo ejecute solo con PGDATA
vacío; default=v1 conserva bootstrap original. Cambiar la variable con un volumen
existente no migra nada. El proceso API nunca migra.

Backend mantiene ORM, DDL congelado de 0003 y catálogos por revisión. El catálogo
MVP-A se capturó de SQL Database en PostgreSQL desechable independiente, y se compara
con migración y ORM, incluidos checks/índices/triggers/defaults. V1/0002 se validan
contra sus catálogos históricos, sin exigirles el ORM de head. Catálogo, flags y
adopción no se desactivan para aceptar drift.

Secuencia de instalación limpia aislada: V1 esquema → privilegios → bootstrap
MVP-A → seed opcional → login runtime privado (incluido permiso de password_hash
solo al login de autenticación) → `MIGRATION_DATABASE_URL` de mantenimiento y
`python -m app.db.adopt_schema --confirm-proposal --mvp-a` → verificación y API.
Adopción exige transacción, lock, catálogo y ORM exactos antes/después del marcador.

Actualización V1 con datos, **solo ensayada en copias desechables**: revisar respaldo,
coordinación/ventana de mantenimiento y catálogo; desde backend, con URL privada de
mantenimiento, ejecutar `alembic -x ownership_proposal=1 -x mvp_a=1 upgrade head`.
0001 reconoce V1, 0002 añade dueño nullable sin backfill, 0003 admite versión null
y añade eventos. Desde 0002 basta `alembic -x mvp_a=1 upgrade head`.
Nunca ejecutar bootstrap_mvp_a sobre esa base ni stamp a ciegas. Downgrade bloqueado
porque perdería historial/versiones; diseñar restauración o migración forward
revisada. Ningún dato antiguo se reasigna, elimina ni transforma en CPE confirmado.

## Pruebas reproducibles

Desde backend con .venv y lockfiles instalados:

```bash
DATABASE_V1_PATH=../database .venv/bin/python scripts/test_postgres.py -q
DATABASE_V1_PATH=../database .venv/bin/python scripts/test_postgres.py --bootstrap-mvp-a -q
.venv/bin/ruff check app alembic scripts tests
```

Desde Database: `python3 tests/run_mvp_a.py` verifica el entrypoint real en un
contenedor propio nuevo, tmpfs, sin puerto/red/volumen. El runner Backend usa
puerto localhost efímero y testea migraciones, SQL V1 y CPE, API y usuarios reales.
Los contenedores propios se detienen; no se tocan volúmenes ajenos. Tests NVD
bloquean transporte real; fixtures verificadas documentadas en tests/fixtures.
Ver resultados finales y riesgos en [MVP_A_RESULTS.md](MVP_A_RESULTS.md).

## Propuesta MVP-B (no iniciada)

1. Ratificar con Rudi detalles/alcance y aprobar política de recuperación/cuota compartida.
2. Aceptar análisis solo para identificación actual confirmed con versión específica;
   409 VERSION_REQUIRED cuando falte y bloqueo de análisis simultáneo por activo.
3. Cliente CVE API 2.0 bajo demanda, cola SQL y worker único; límites de páginas,
   cobertura complete/partial, metadatos y errores distinguibles de cero resultados.
4. Congelar identificación/CPE/versión/procedencia al aceptar; no reinterpretar históricos.
5. Evaluar condiciones AND/OR y rangos conservadoramente; potential/undetermined,
   nunca explotación confirmada. Persistir evidencia acotada y deduplicar por ejecución.
6. Endpoints de ejecuciones/hallazgos y revisión con expected_updated_at según contrato;
   migración coordinada y pruebas de rollback, cuotas, autorización y cobertura parcial.
7. Implementar presentación móvil/web y seguimiento sin sumar CVE repetidos de varias
   ejecuciones como vulnerabilidades distintas. Mantener V2 y ZAP pospuestos.

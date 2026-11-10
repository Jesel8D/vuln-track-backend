# Evidencia Backend V1.3 — 30-10-2026

Continuación de 3d23a1afdf5fae1321c90abf91ea874408977dfa, misma rama, historial íntegro.
Linux x86_64, Python 3.12.14, PostgreSQL real **16.15**, Docker 28.4.0. Paquete/OpenAPI
0.1.3; rutas /api/v1 y esquema 0002 sin cambios. Dependencias conservadas y pip check
aprobado. No se usó SQLite ni se operó sobre bases persistentes.

## Resultados exactos

| Ejecución | Aprobadas | Fallidas | Omitidas | Excluidas |
|---|---:|---:|---:|---:|
| Suite anterior antes de cambios | 71 | 0 | 0 | 0 |
| Suite unitaria V1.3, `pytest -q tests/unit` | **77** | **0** | **0** | **0** |
| Completa PostgreSQL, `scripts/test_postgres.py -q` | **122** | **0** | **0** | **0** |
| Bootstrap nuevo, `--bootstrap-v11 -q` | **29** | **0** | **0** | **1** |
| pytest sin PostgreSQL configurado | **77** | **0** | **45** | **0** |

Las 29 pruebas de bootstrap nuevo repiten contratos sobre otra ruta de instalación;
no se cuentan como casos distintos adicionales. Allí se excluye solo el test específico
de readiness frente a V1 sin migrar, ejecutado en la suite completa. Los 45 skips sin DB
son explícitos; el runner completo ejecuta todas. No se sustituyen autenticación ni
política de propietario por mocks.

Suite completa final: `vulntrack-backend-test-a70f1abc34ca`, **122 passed en 29.71 s**.
Ruta bootstrap nuevo: `vulntrack-backend-test-4c74d494e9c4`, **29 passed, 1 deselected**.
La ruta V1 original volvió a ejecutar sus **55 aserciones SQL intactas** antes de migrar.
El esquema de propiedad mantiene estado PROPUESTA pendiente de aprobación formal.

## Comandos ejecutados

Desde venv (se usó `.venv/bin/` en el entorno):

```bash
python -m pytest -q tests/unit
python -m pytest -q
ruff check .
python -m pip check
python -m compileall -q app alembic scripts
python -m alembic heads
DATABASE_V1_PATH=../vuln-track-database python scripts/test_postgres.py -q
DATABASE_V1_PATH=../vuln-track-database python scripts/test_postgres.py --bootstrap-v11 -q
```

Ruff: All checks passed. Dependencias: No broken requirements found. Compileall: salida 0.
Alembic: `0002_asset_owner (head)`. Importación y contrato OpenAPI verificados en tests.
Ejemplos JSON web/móvil comprobados contra modelos Pydantic reales y rutas existentes.
No hay migraciones, cambios ORM o DDL nuevo de esta etapa.

## Contratos HTTP y CORS

- Login, me, creación, detalle, listado/página vacía, validación y errores JSON con
  cabeceras reales: Location, correlación, no-store, nosniff, WWW-Authenticate y CORS.
- Configuración rechaza wildcard/null, patrones, credenciales en URL, rutas, puertos/
  URLs ambiguos, duplicados y credenciales implícitas. Producción excluye HTTP/loopback.
  Lista JSON desde entorno y lista vacía por defecto verificadas.
- Preflight OPTIONS permitido 200 JSON; origen, método o cabeceras no permitidos 400
  JSON genérico. Solo GET/POST, Bearer/JSON/idempotencia y safelisted estándar, sin ACAC.
  OPTIONS preflight no autentica ni consulta DB; ordinary OPTIONS conserva 405.
- 401/422/413/500/503 de origen permitido conservan CORS. Origen no listado no recibe
  Allow-Origin; un HTTP real autorizado puede procesarse: CORS no se trata como ACL.
- Usuarios A/B aislados incluso compartiendo origen permitido. Created_by manipulado
  se rechaza; replay y totales no revelan datos ajenos. X-User-ID no autentica.
- Retry simultáneo web (con Origin) y nativo (sin Origin), sincronizado antes de insertar
  solicitud: un único activo/owner/snapshot y mismo 201, CORS solo en la respuesta web.

## JWT y confidencialidad

- Firma/algoritmo fijo HS256; rechazo de none/HS384/HS512, firma incorrecta, malformados
  y tamaño excesivo. Expiración, tiempos futuros, claims obligatorios, audiencia/issuer.
- Se endurecen claims temporales a enteros no booleanos, orden y TTL positivo acotado;
  audiencia estrictamente escalar. Emisor propio compatible, sin nueva arquitectura.
- Tokens inválidos se rechazan antes de abrir sesión SQL. Token válido consulta usuario
  activo/versión; desactivación impide acceso. Errores HTTP 401 genéricos con CORS.
- caplog comprueba ausencia de token válido, inválidos, expirado, secreto, contraseña
  errónea y contraseña de prueba. No se registran cuerpos ni excepciones con sus valores.
- Revocación individual solo propuesta en JWT_SECURITY_REVIEW.md, no implementada.

## Docker y HTTP real

```bash
docker build --secret id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt \
  -t vulntrack-backend:v1.3 .
DATABASE_V1_PATH=../vuln-track-database python scripts/test_postgres.py --docker-smoke
DATABASE_V1_PATH=../vuln-track-database python scripts/test_postgres.py --bootstrap-v11 --docker-smoke
```

Build salida 0, imagen SHA-256
`1f7f4b3ed77f1d92554b1f9a4692d2c3e522e8d4e92c820df27805ea45f0fb2d`.
Ambos smoke pasaron: UID 10001, health/ready 200, preflight permitido 200/rechazado 400,
login 200, creación/replay 201, detalle/lista propios 200 y cabeceras CORS efectivas.
Proyectos: `vulntrack-backend-test-fabade39a0e0` (migración) y
`vulntrack-backend-test-4008ef40704b` (bootstrap nuevo). CA montada solo en build;
TLS no se deshabilitó. Logs de acceso Uvicorn desactivados.

## Incidencias y limitaciones

Ruff detectó inicialmente un raise sin encadenamiento explícito en el validador CORS;
se corrigió con from None y se repitió la validación, sin suprimir la regla.
Una repetición final no llegó a ejecutar pytest: Docker run devolvió **125** con el
filesystem del entorno al **100 %**. Se retiraron únicamente siete contenedores detenidos
creados en esta misión, comprobando sus nombres/estado, ausencia de volúmenes persistentes,
label o imagen de prueba y PGDATA tmpfs. No se podaron imágenes, redes, volúmenes ni
artefactos anteriores. Después la repetición completa pasó con 122 aprobadas.

Permanece un aviso de deprecación Starlette/TestClient con httpx, no ocultado. No quedan
fallos conocidos de pytest o Ruff. No se desarrollaron ni probaron aplicaciones React/
React Native reales; se prueban contratos del servidor y HTTP en Docker, no un navegador
completo, plataforma Keychain/Keystore o proxy TLS de producción.

No se probaron carga, backup/restauración, corte TCP durante commit ni limitador compartido
multiworker. Origin no sustituye credenciales ni límites de red. CORS vacío por defecto;
lista de despliegue debe revisarse. Tokens siguen sin revocación individual ni refresh.
Propiedad y coordinación Database pendientes de aprobación; sin declaración de producción.

No se modificaron Database/Context/Frontend/main ni bases persistentes, no se hizo push/
merge ni se configuraron credenciales GitHub. Sin NVD/ZAP/escáneres. Evidencia histórica:
[V1](TEST_RESULTS_V1.md), [V1.1](TEST_RESULTS_V1_1.md), [V1.2](TEST_RESULTS_V1_2.md).

# MVP-B — resultados de implementación y pruebas

Fecha: 2026-11-08 America/Mexico_City; ejecuciones/capturas UTC 2026-11-09.
Implementación autorizada por Jesel para esta misión; ratificación de Rudi
PENDIENTE. No constituye despliegue ni aprobación técnica global inventada.

## Estado inicial

| Repositorio | Rama inicial | Commit inicial | Árbol |
|---|---|---|---|
| Backend | feat/mvp-cpe-backend | 2e12badb7a29d421c72c1faf1cf11de5383d0b1b | limpio |
| Database | feat/mvp-cpe-database | 80db7fd411f49f648263f275b412384bc49f7ed8 | limpio |
| Frontend | feat/frontend-web-v1 | 2643467864c54226043d43efa5859d38c332ab92 | limpio |
| Context | docs/mvp-context-consolidation | caa7ef13b0e2b24848991e32b3c0ee3fc59139c7 | limpio |

Remotos SSH oficiales comprobados; las ramas MVP-B propuestas no existían al
comenzar. Se crearon desde sus referencias reales, sin reset, rebase, merge ni
fuerza. Frontend y Context permanecen en esos commits, sin cambios. No se
modifican main, ramas de Rudi, decisiones D-001/D-002 ni V2.

## Arquitectura y coordinación

Se inspeccionaron las seis tablas, ORM, SQL/bootstrap, permisos, Alembic,
catálogos y suites previas. Se reutilizan analysis_runs/findings: cero tablas
nuevas. Metadatos nuevos congelan identificación/CPE por ejecución, conservan
idempotencia, progreso, cobertura, cooldown, evidencia y revisión única.

[Contrato implementado](MVP_B.md): cola SQL con worker del mismo backend,
transacciones por página, recuperación de running, cuota local compartida CPE/CVE
y evaluación parcial. El contrato propuesto no se reetiqueta como acuerdo
conjunto: not_applicable solo por revisión humana; rangos/AND no soportados
permanecen undetermined. 0004 requiere mantenimiento explícito sin otro flag,
conservando el launcher Web V1 sin modificar Frontend.

Database conserva originales V1 y añade bootstrap, guards/grants/índices y SQL de
pruebas MVP-B. El catálogo se capturó desde ese SQL en PostgreSQL independiente;
Alembic/ORM se comparan contra él y un manifiesto fija hashes cruzados. Catálogos
históricos originales intactos. Legacy sin evidencia no se reinterpreta.

## Pruebas finales

Python 3.12, PostgreSQL 16.15 alpine con digest fijado, Docker local, puertos
aleatorios solo loopback y runtime dedicado sin privilegios de dueño. Cada
runner crea PGDATA tmpfs y detiene únicamente su propio contenedor. No acepta
URLs de bases personales ni migra volúmenes persistentes. NVD real está bloqueado
en pytest mediante HTTPTransport; se usa MockTransport. El HTTP local de la
prueba integrada utiliza Uvicorn real y urllib.

| Suite/comando | Ejecutadas | Aprobadas | Fallidas | Omitidas |
|---|---:|---:|---:|---:|
| MVP-A antes de cambios, scripts/test_postgres.py -q | 194 | 194 | 0 | 0 |
| Final V1/seed→head, scripts/test_postgres.py -q | 301 | 301 | 0 | 0 |
| Final SQL MVP-B→adopción, scripts/test_postgres.py --bootstrap-mvp-b -q | 301 | 301 | 0 | 0 |

Prefijo de ejecución: `DATABASE_V1_PATH=../database .venv/bin/python` desde
Backend. Las dos rutas finales ejecutan **la misma suite**, no 602 casos únicos.
Se conservan 194 casos anteriores, ajustando expectativas de head/CORS a 0004 y
PATCH; se añaden 107: 58 unitarias, 6 migración, 43 integración CVE. Revisiones
históricas se siguen comprobando con catálogos exactos, incluida inyección de
fallo de 0003. Duraciones finales: 83.93 s y 83.99 s.

Un warning preexistente: StarletteDeprecationWarning por adaptador httpx de
TestClient. No se cambian librerías para eliminar ese aviso ajeno al alcance.
Sin fallos ni omisiones en las ejecuciones finales.

[evidence/MVP_B_TESTS.json](evidence/MVP_B_TESTS.json) registra comandos completos,
ambiente, conteos y SHA-256 de logs locales, sin contraseñas/JWT/URLs privadas.
No se publican logs de fallos que puedan incluir variables de fixtures.

Validaciones adicionales satisfactorias:

- Database `python3 tests/run_mvp_b.py`: entrypoint real, inventario vacío,
  metadatos, FK/unicidad/guards y privilegios. Sin puerto/red/volumen.
- Database `python3 tests/run_mvp_a.py`: bootstrap anterior y seed V1 repetible.
- `ruff check app tests scripts alembic`: todos los checks pasan.
- Imagen `vulntrack-backend:mvp-b` construida con Buildx. Smoke Docker/HTTP real
  por runner desechable: UID 10001, health/ready, preflight permitido/denegado,
  login, POST/replay/GET/list de activos y privilegios mínimos.
- `git diff --check`, revisión de archivos preparados y búsqueda de secretos
  antes de commit. Sin dependencias nuevas; SQL/catálogos incluidos en paquete
  e imagen.

## Cobertura comprobada

**Cliente:** fixture CVE verificado, cero/una/varias páginas; tipos, offset y total
inconsistentes; JSON inválido/duplicado/NaN/grande; timeout/red/HTTP, 403/429,
Retry-After; sin CVSS, múltiples CVSS, Rejected/Modified; referencias y
configuraciones ausentes; destino/params/header fijo; cuota compartida CPE/CVE.

**Evaluador:** coincidencia literal por componentes; producto/versión/variante
incompatible; versión observada ausente/discordante; igualdad con sufijo; AND/OR,
negación, vulnerable=false, entorno adicional y expresión parcial. Rangos dentro,
fuera, inclusivos/exclusivos y sufijos explícitamente undetermined. Preservación
de evidencia y degradación visible por presupuesto.

**PostgreSQL/API:** login A/B, registro/confirmación, 202 estable, historial,
evidencia; páginas/contadores; parcial/fallida frente a cero válido; reintento
transitorio y nueva intención tras fallo; duplicados/CVE modificado/total u orden
cambiante; carreras de dos conexiones/huella; CPE sustituido después; review con
timestamp obsoleto y concurrencia de una sola transición; permisos/integridad;
rollback de aceptación y página; interrupción/reinicio; dos workers bajo lock;
caída real de un hijo con lock y recuperación por worker nuevo; cooldown CVE
persistido/restaurado; aislamiento A/B, usuario inactivo, rutas mezcladas,
no existentes y sin autenticación; logs saneados, rechazo de confirmed. HTTP
real con Uvicorn incluido. Recursos ajenos se rechazan antes de consultar NVD.

**Migración:** V1 y MVP-A con activos, confirmación e historial→MVP-B; conserva
OID/filas/snapshots y no inventa evidencia del legado; SQL limpio equivalente;
ORM/Alembic sin diferencias; duplicados antiguos abortan preservando datos;
inyección post-DDL revierte esquema/marcador; drift en guards/UNIQUE/índice
activo detectado; downgrade destructivo bloqueado.

## NVD real y limitaciones

Las páginas oficiales son SPA: el primer lector HTML no mostró el contenido.
Chrome/Playwright cargó y abrió Parameters/Response de
[CVE](https://nvd.nist.gov/developers/vulnerabilities),
[Products](https://nvd.nist.gov/developers/products) y
[Start Here](https://nvd.nist.gov/developers/start-here); también se consultó CPE
FAQ. Cuotas oficiales 5/30 s sin key y 50/30 s con key; política local 7 s,
una instancia/worker, sin elevar tasa por key ni afirmar cuota distribuida.

Captura oficial limitada `nvd_cve_verified.json`: CVE-2017-6784, 1 informado/1
recuperado, timestamp 2026-11-09T05:15:22.760. Un segundo request único mediante
el cliente CVE implementado devolvió el mismo ID, 1/1, timestamp
2026-11-09T05:24:40.007 UTC. Sin key, descarga masiva, referencias visitadas ni
contacto con dispositivos. Variantes de fixture identificadas como simuladas.
La respuesta real contiene AND firmware/hardware y múltiples CVSS; el evaluador
la clasifica undetermined, sin afirmar vulnerabilidad en un dispositivo.

Fallo detectado y resuelto: al recortar una descripción, el título podía terminar
en espacio y violar el CHECK V1. Se normaliza después del recorte, manteniendo
estricto el CHECK. Las primeras pruebas de ingesta fallaron por esa causa; las
cifras finales corresponden a suites completas después de corregirla. No se
ocultaron casos ni se relajó la restricción.

Límites: sin evaluador CPE universal/orden genérico de versiones; rangos/AND/
negación requieren revisión; evidencia grande puede omitirse con hash y aviso;
NVD no garantiza snapshot entre páginas; cuota de un proceso API/egreso; ventana
inevitable entre respuesta externa y commit; nueva consulta completa tras caída,
sin retomar offset; revisión una vez; sin UI CVE ni producción preparada.

## Git y estado de entrega

Publicación autorizada por push normal en Backend `feat/mvp-b-nvd-cve-backend`
y Database `feat/mvp-b-nvd-cve-database`. Hashes finales y comprobación remota
se entregan en el chat, evitando autorreferencia de un commit con su propio
hash. Sin merge/fuerza ni cambios en Frontend/Context.

| Capacidad | Estado |
|---|---|
| Endpoints, propiedad, persistencia, historial y revisión única | IMPLEMENTADO Y PROBADO |
| Cliente CVE, paginación, cobertura, límites y reintentos | IMPLEMENTADO Y PROBADO |
| Cola SQL, concurrencia, recuperación y cooldown | IMPLEMENTADO Y PROBADO, una instancia |
| SQL limpio/migración, ORM/Alembic y regresión MVP-A | IMPLEMENTADO Y PROBADO |
| Aplicabilidad y cobertura de fuente | IMPLEMENTADO CON LIMITACIONES descritas |
| Frontend MVP-B | PENDIENTE, excluido de la implementación actual |
| Ratificación Rudi, producción y escala compartida | PENDIENTE |

Siguiente misión: conectar las seis operaciones al Frontend actual con historial,
estado/progreso, CVE/CVSS/evidencia, identificación anterior y revisión única.
Mostrar cobertura parcial e incertidumbre, conservar intención tras respuesta
perdida y nunca traducir cero resultados a activo seguro. No se implementó esa UI.

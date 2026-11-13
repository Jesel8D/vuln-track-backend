# Resultados locales — 2026-11-13

## Verificado en esta misión

| Comprobación | Resultado |
|---|---|
| Inventario real | 39 operaciones en 30 rutas: 2 estado, 15 V1, 22 V2 |
| Colección | 61 solicitudes definidas, JSON válido y esquema oficial Postman 2.1 válido |
| OpenAPI | 3.1.0 válido con openapi-spec-validator 0.7.2; copia idéntica al generador servido |
| Contrato frente al commit base | Mismos parámetros, cuerpos, modelos de respuesta positiva y esquemas de autenticación; sin nuevas rutas |
| Ejemplos | 15 esquemas de request con ejemplo; 17 cuerpos de casos positivos/bloqueado comprobados con Pydantic, sustituyendo password vacío por secreto efímero; 41 respuestas positivas de casos y 39 ejemplos por operación (38 positivos y un error conocido) |
| Newman: instalación existente | 65 envíos HTTP, 245 aserciones, 0 fallidas; 61 solicitudes distintas |
| Newman: instalación nueva | 65 envíos HTTP, 245 aserciones, 0 fallidas; 61 solicitudes distintas |
| SQL por recorrido | 55 integridad + 21 seguridad + 6 bootstrap + 10 privilegios = 92 comprobaciones |
| Regresión backend completa | 371 passed, 0 failed, 0 skipped; 129,86 s |
| Defectos existentes | 4 reproducciones confirmadas, NO cuatro funcionalidades correctas |
| Ruff / pip check / git diff --check | Correctos |
| Docs HTTP | /docs, /redoc y /openapi.json devuelven 200; no se probó visualmente su UI |

El número de envíos/aserciones puede variar porque el worker V1 termina antes o después del primer GET. Ese polling solo consulta la misma ejecución; el historial exige total=1. Las repeticiones no se suman como nuevos endpoints o casos únicos. Los runners usaron contenedores propios PostgreSQL 16.15 en tmpfs, con limpieza al terminar y sin bases persistentes.

El resultado completo está sanitizado en [results-summary.json](examples/results-summary.json). Los reportes locales originales quedan ignorados dentro de .artifacts; no se publica ningún entorno resuelto ni respuesta con token real.

## Qué demuestran y qué no

Se ejecutaron registro/login/me, captura de JWT e IDs, workspace personal, aplicaciones/targets/tecnologías, selección del UUID fijo CPE de fixture, análisis V2 simulado, historial/hallazgos/recomendaciones, flujo V1 asíncrono separado y los 19 negativos de la colección. Las cuentas A/B son reales dentro de ese PostgreSQL: los accesos ajenos se rechazan sin manipular RLS. La regresión conserva las pruebas de carreras de registro y reutilización de conexiones SQLAlchemy.

**38 operaciones consiguieron respuesta positiva. POST /api/v2/workspaces está bloqueado y la colección exige su 404 conocido.** La aprobación de esa aserción no demuestra creación adicional. El perfil CVE positivo requiere OR y título corto SIMULADOS. Las cuatro reproducciones de LIMITACIONES comprueban que AND/undetermined y título original siguen fallando. No se corrigieron funcionalidades ni se relajaron restricciones.

## Incidentes durante la construcción

- El primer borrador de scripts chocaba con la variable global data de Postman; se encapsularon los scripts y se ejecutó nuevamente el flujo real.
- La primera igualdad del OpenAPI detectó que FastAPI descartaba null de ejemplos. Se restauran solo en metadatos para conservar los cuerpos válidos; no se cambió el tratamiento HTTP de entradas/salidas.
- La expectativa inicial 201 del workspace adicional reveló SQLSTATE 42501. Se documentó como defecto y se cambió la expectativa del caso de diagnóstico a 404, sin dar por exitosa la funcionalidad.
- El fixture AND original reveló app_findings_applicability_valid; al aislar con OR se detectó además app_findings_title_valid por truncado con espacio. Ambos originales se conservaron y se agregaron reproducciones separadas. Solo el perfil positivo usa la variante explícitamente simulada.
- El error de aplicación ajena se esperaba inicialmente como APPLICATION_NOT_FOUND, pero la API real produce RESOURCE_NOT_FOUND al establecer contexto. La colección se ajustó a la respuesta observada.
- Los avisos de dependencias Newman y deprecaciones no se ocultaron; ver LIMITACIONES. No se modificaron dependencias productivas ni lockfiles originales.

## Entorno y alcance

Python 3.12.3, FastAPI 0.162.0 de requirements-dev.lock, Docker 29.8.2, PostgreSQL 16.15 fijado por digest, Node 24.12.0, npm 11.6.2 y Newman 6.2.3 local. Solo el transporte NVD está simulado. No se ejecutaron NVD en vivo, escaneos, ZAP, Postman/Swagger nativos visuales, carga, otros navegadores, móvil, restore o despliegue. No se repiten como nuevas las pruebas frontend/navegador de la misión anterior.

OpenAPI SHA-256: `a8095975fa1fd5aaf95e05756c63d1bd78a616518ea681d77fd673ec5c2de7d4`.

## Git y publicación

Rama: `test/v2-api-collection`, creada directamente desde Backend `5a34f6439881f40eb9aaa931ff5777b60b62e023` en un worktree adicional. Sin merge/rebase ni cambios a main, Rudi, Database, Frontend o Context. Los artefactos y metadatos se revisan antes de commit; la publicación se realiza mediante push normal y se verifica después del commit.

[Rama de revisión en GitHub](https://github.com/Jesel8D/vuln-track-backend/tree/test/v2-api-collection). El hash definitivo se informa al publicar; para comprobarlo sin introducir un hash autorreferente dentro de este mismo commit:

```bash
git rev-parse HEAD
git ls-remote origin refs/heads/test/v2-api-collection
```

La ratificación global de V2 sigue pendiente. Documentar/probar/publicar esta rama no equivale a integrar la arquitectura ni corregir los defectos identificados.

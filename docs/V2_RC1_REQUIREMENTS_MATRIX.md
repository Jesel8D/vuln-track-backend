# RC1 — compatibilidad y requisitos

Fecha: 2026-11-15. Esta matriz describe la candidata local V2 y no una entrega
final aprobada. La [integración](V2_RC1_INTEGRATION_REPORT.md) registra resultados
de esta misión; las fases anteriores conservan sus propios informes históricos.

## Conjunto de fuentes

| Componente / propietario | Referencia exacta de partida | Contrato requerido y disponible | Resultado / defecto observado |
|---|---|---|---|
| Backend / Backend | `feat/v2-security-egress-phase2c`, `f571ea8d0f943900b3ddde900d6f7011726e8f56` | FastAPI V1 conservada + V2, JWT Bearer, worker NVD, verificación bloqueada | Compatible; RC1 añade herramientas de aceptación y transmite el modo público de fixture a Vite |
| Bootstrap, roles, RLS / Database | `feat/v2-security-verification-database`, `a562e638dfe5b7e8d07eec0e8046e6998f8a2802` | SQL001/002/004/005/006/007/008; fuentes empaquetadas Backend con hashes iguales | Compatible sin cambiar SQL; sin rama Database RC1 |
| ORM y migraciones / Backend | misma base Backend | Alembic legado `0004_mvp_cve`; versión separada `v2_0001_target_verification` | Catálogos estrictos, bootstrap nuevo y ruta existente probados; no se usa stamp para ocultar drift |
| UI / Frontend | `feat/v2-security-analysis-web-phase2b`, `0ab0f117651dd058cb2cb70d994999781e18e75f` | Workspaces, aplicaciones, tecnologías, CPE, análisis, hallazgos, recomendaciones y readiness de API | Compatible; correcciones RC1 de procedencia, dashboard, contraste, semántica y ancho de tablet |
| Postman / Backend | histórico `test/v2-api-collection`, `63315644121bb0074cd18f5d2da11720358caea0` | Colección 2.1, OpenAPI 3.1, 44 operaciones actuales | El histórico es ancestro de f571ea8; archivos evolucionaron después. No se hizo merge redundante |
| Context / Context | `docs/mvp-context-consolidation`, `caa7ef13b0e2b24848991e32b3c0ee3fc59139c7` | Decisiones existentes; D001/D002 globales; propuesta de alcance sujeta a ratificación | Sin cambios ni rama RC1; aprobación individual no se interpreta como acuerdo del equipo |

Backend publica `release/v2-rc1-integration`; Frontend publica
`release/v2-rc1-web`. Los hashes finales completos de ambas ramas se registran en
el manifiesto de entrega local y en el informe exportado después del push. El
commit que contiene este documento identifica exactamente el Backend publicado;
no se confunde su base con el resultado RC1. Usar el conjunto coordinado, no HEAD
de main/rudi ni una base de datos MVP-B.
Frontend RC1 ya verificado por push normal y ls-remote:
`4674cbcd9f46ad0e9e587b0db630b9f51a990a86`.

## Requisitos y evidencia

| Requisito | Clasificación | Evidencia RC1 / límite |
|---|---|---|
| Compatibilidad real de los tres repositorios | IMPLEMENTADO Y PROBADO | Bootstrap, pruebas SQL/API, Newman y navegador contra el conjunto indicado |
| Registro normal, JWT, identidad, workspace owner inicial | IMPLEMENTADO Y PROBADO | A, C y regresión de registro; creación transaccional |
| Inventario aplicación / URL / tecnología | IMPLEMENTADO Y PROBADO | A mediante formularios; la URL se guarda, no se escanea |
| Búsqueda y confirmación CPE explícita | IMPLEMENTADO Y PROBADO | Captura Cisco RV340 1.0.0.33; radio y botón de confirmar en navegador |
| Worker CVE e historial persistentes | IMPLEMENTADO Y PROBADO | A; estado guardado completed y evidencia AND original |
| Hallazgo, revisión y recomendación | IMPLEMENTADO CON LIMITACIONES | Hallazgo real del fixture, revisión undetermined/reviewed y medida manual; no validación de un sistema real |
| Dashboard con métricas reales | IMPLEMENTADO Y PROBADO | Contadores y períodos comparados con API después del flujo A; cero abiertos después de revisar no significa ausencia de riesgo |
| Dos usuarios, IDs ajenos, roles y workspace_id | IMPLEMENTADO Y PROBADO | C, RLS y reutilización de conexiones; 404/422 esperados y lecturas propias válidas |
| Roles owner/editor/viewer | IMPLEMENTADO CON LIMITACIONES | SQL/API probados; no hay administración pública de membresías ni roles globales en la UI |
| Autorización declarada, desafío, revocación y caducidad | IMPLEMENTADO Y PROBADO | D, SQL008 y suites API; caducidad real, sin cambiar reloj |
| Verificación técnica remota y egreso público | BLOQUEADO | verify 503, cero intentos operativos; laboratorio propio no demuestra control de dominio externo |
| Gateway y SSRF de laboratorio | IMPLEMENTADO CON LIMITACIONES | 45 comprobaciones 2B y 51 de gateway 2C repetidas en RC1; perímetro privado, sin certificación operativa |
| ZAP Baseline / ejecuciones / hallazgos ZAP | BLOQUEADO | Botón disabled; no se crean ejecuciones ni resultados ficticios |
| UX 375/768/1280/1440, carga/error/reintento | IMPLEMENTADO Y PROBADO | Suite RC1 Chromium y axe; revisión básica, no certificación universal de accesibilidad |
| Reinicio, backup, restore separado | IMPLEMENTADO Y PROBADO | Driver `scripts.test_rc1_recovery`, comparación exacta de DTO y navegador B; ver informe de recuperación privado |
| Instalación personal protegida | IMPLEMENTADO Y PROBADO | Directorios, HEAD, volumen y puertos separados; no se actualiza ni restaura sobre development |
| Dispositivos V1: router/switch/servidor | IMPLEMENTADO CON LIMITACIONES | Contratos heredados conservados en API/modelos; no están montados como pantallas en App V2 |
| Aplicación móvil nativa | PENDIENTE | No implementada ni probada en esta misión; responsive web no equivale a móvil nativo |
| Alcance definitivo y ratificación Jesel/Rudi | PENDIENTE | Decisión humana, no sustituible por suites automáticas |
| Producción / despliegue Internet | BLOQUEADO | Fuera de RC1 local; faltan operación, endurecimiento y aprobaciones |

## Propuesta para Jesel y Rudi

Revisar RC1 como candidato académico del flujo **web V2**: cuenta, workspace,
inventario de aplicaciones/URLs/tecnologías, identidad CPE confirmada, consulta
NVD reproducible y evaluación humana con evidencia. Conservar V1 como línea
histórica de dispositivos con propiedad individual; V2 usa membresías/RLS de
workspace. No son contratos intercambiables ni una migración automática de
routers a aplicaciones. No se crea otra arquitectura de activos.

Si el entregable exigido sigue siendo el MVP de dispositivos originalmente
aprobado individualmente por Jesel, RC1 web V2 necesita ratificación explícita de
ambos revisores antes de sustituirlo. Deben decidir qué flujo mostrar, qué partes
V1 se conservan como requisito, si móvil queda fuera y qué criterio académico
acepta datos de fixture. ZAP continúa como ampliación bloqueada.

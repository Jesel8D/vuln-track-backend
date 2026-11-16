# VulnTrack V2 RC1 — integración verificable

Fecha de ejecución: **2026-11-15**. **IMPLEMENTADO CON LIMITACIONES.** Candidato
para revisión académica local del flujo V2, sin despliegue público ni aprobación
final. La instalación habitual permanece en sus versiones y volumen anteriores.

Documentos: [matriz de compatibilidad/requisitos](V2_RC1_REQUIREMENTS_MATRIX.md),
[guion](V2_RC1_DEMO_GUIDE.md), [limitaciones](V2_RC1_KNOWN_LIMITATIONS.md),
[checklist](V2_RC1_RELEASE_CHECKLIST.md), [ejecución/backup/recuperación](V2_RC1_LOCAL_RUN.md).
Los [resultados saneados y hashes de evidencia](evidence/V2_RC1_RESULTS.json)
se derivan de los logs finales; no incluyen contraseñas, tokens ni dumps.

## Fuentes y genealogía

| Repositorio | Base verificada por Git y remoto | Trabajo RC1 |
|---|---|---|
| Backend | `f571ea8d0f943900b3ddde900d6f7011726e8f56`, `feat/v2-security-egress-phase2c` | `release/v2-rc1-integration` |
| Database | `a562e638dfe5b7e8d07eec0e8046e6998f8a2802`, `feat/v2-security-verification-database` | Checkout separado exacto, sin cambios/commit/rama RC1 |
| Frontend | `0ab0f117651dd058cb2cb70d994999781e18e75f`, `feat/v2-security-analysis-web-phase2b` | `release/v2-rc1-web` |
| Context | `caa7ef13b0e2b24848991e32b3c0ee3fc59139c7`, `docs/mvp-context-consolidation` | Sin cambios |

`63315644121bb0074cd18f5d2da11720358caea0` de Postman es ancestro real del
Backend seleccionado. Sus archivos ya están incorporados y evolucionaron en
fcabbe9, 56c1274 y 7a158b8; no se hizo merge de la rama histórica. Los hashes
finales RC1 se entregan en el manifiesto y reporte exportado posterior al push;
las bases de esta tabla no se presentan como commits finales RC1.
Frontend RC1 publicado y verificado en remoto:
`4674cbcd9f46ad0e9e587b0db630b9f51a990a86` (`release/v2-rc1-web`). El Backend
compatible es el commit que contiene este informe; el manifiesto exportado
registra su hash completo junto a este Frontend y Database a562e638.

Se comprobó correspondencia entre SQL canónico y empaquetado, modelos,
migraciones, roles, FORCE RLS, JWT y contexto HMAC por transacción, membresía,
DTOs de CPE/CVE, worker, recomendaciones y desafíos duraderos. La compatibilidad
se probó en conjunto por SQL/API/Postman/navegador, no solo por suites aisladas.
El contrato OpenAPI no cambió: SHA-256
`082d1c6a0b84564b8814ede1724b5d72e54249d5fd9893d65149b0af00133b16`.

## Aislamiento y protección

Directorio `/home/mz/VulnTrack-rc1`; perfil `rc1`; volumen
`vulntrack_v2_rc1_pgdata`; contenedor `vulntrack-v2-rc1-postgres`; PostgreSQL
127.0.0.1:55438; API 8004; web 5177. Configuración y claves propias en
`.local/rc1/`. El launcher existente ya permitía perfiles/puertos/nombres
alternativos: se auditó esa capacidad antes de arrancar y no fue necesario
reescribir su aislamiento.

El bootstrap nuevo aplica SQL001/002, Alembic legado hasta 0004, modelo V2 y
evidencia/registro/estabilización, más SQL008 y su revisión independiente. Verifica
catálogos exactos y login API sin privilegios administrativos/BYPASSRLS; el API
no es dueño de tablas ni recibe credenciales de migración. Ready no reaplica
migraciones al reiniciar.

La instalación protegida sigue en `/home/mz/VulnTrack`, volumen
`vulntrack_v2_development_pgdata`, PostgreSQL55434, API8000, web5173. Sus HEAD
iniciales fueron Backend `fcabbe986f2a4d3dffb259edda0b7245e533ee91`, Database
`b377b5bd8013cc2151f6a1681d168e1df0f5fe42`, Frontend
`4514b6840b428152c1cd875c95e3e55ad81c4196`, Context caa7ef13 completo arriba,
todos limpios. No se detuvo, migró, restauró, actualizó ni usó para fixtures.

## Defectos demostrados y corrección mínima

| Defecto reproducido | Causa y corrección | Regresión |
|---|---|---|
| El modo capturado no era visible en la UI | Launcher transmite solo `VITE_NVD_MODE`; aviso de fixture en layout autenticado | A/B exigen aviso; no hay secretos VITE |
| Dashboard mostraba resumen vacío anterior al volver del historial | Caché aún fresca tras mutaciones; refetch al montar | A compara los cuatro contadores con API real |
| Meses del gráfico desplazados uno hacia atrás en México | Parseo de fecha mensual UTC mostrado en zona local; formato de mes con timeZone UTC | A compara todos los períodos/conteos de API en America/Mexico_City |
| Notas/estados de texto pequeño con contraste insuficiente | Tonos demasiado claros; oscurecer solo colores demostrados | Axe en datos vacíos y poblados a los cuatro anchos, sin excluir reglas |
| Login móvil sin encabezado principal/landmark adecuado | Marketing usaba h1 oculto y formulario h2; aside rotulado y h1 visible | Axe login/registro en cuatro anchos; footer WEB V2 |
| Salto de encabezado CVE y landmarks complementarios indistinguibles | h4 bajo h2; sidebar sin nombre junto a nota de revisión | h3 CVE con estilo conservado y sidebar rotulado; axe con datos |
| Dashboard de 768px desbordaba y superponía nombre/botón | Track min-content y banner sin wrap en tablet | Columna minmax(0,1fr), título divisible y wrap; prueba de scrollWidth y capturas |
| Reinicio inmediato rechazaba puerto sin listener | La sonda sin SO_REUSEADDR confundía TIME_WAIT con puerto ocupado | Sonda con semántica de reinicio; dos pruebas reales TCP: acepta conexión cerrada y rechaza listener activo; recuperación completa repetida |

No se modificaron modelos, endpoints, SQL, RLS, SSRF, reglas del gateway ni
semántica CVE. Tampoco se cambiaron locks. Se añadieron pruebas/herramientas RC1,
no pantallas nuevas ni arquitectura de activos.

Durante los ensayos se corrigieron también supuestos de prueba: creación de
análisis devuelve 201 según contrato, el login puede volver a la ruta protegida
solicitada y la sesión en memoria exige login tras recarga. Un selector del
combobox y una carrera de menú móvil se ajustaron a la UI real. La batería
repetida alcanzó la cuota normal de login; ahora respeta el Retry-After de 429.
También se corrigió la selección del ejecutable del navegador de la suite previa:
el Chrome por defecto de `/usr/bin` no existe en esta PC; se utiliza el Chromium
ya instalado por Playwright, sin cambiar la suite ni instalar herramientas globales.
Estas incidencias no se atribuyen a defectos de la aplicación ni se resolvieron
relajando sus políticas. Los ensayos intermedios fallidos se conservan en logs
privados; los recuentos siguientes son de las ejecuciones finales verdes.

## Pruebas ejecutadas en esta misión

| Ejecución | Resultado final | Alcance |
|---|---|---|
| Backend completo, ruta existing sobre tmpfs propia | **755 aprobadas**, 0 fallidas/omitidas, 196.13s | 734 conservadas + 21 nuevas (guardas RC1 y TCP) |
| Backend completo, ruta new sobre otra tmpfs | **755 aprobadas**, 0 fallidas/omitidas, 196.10s | Misma suite, segundo bootstrap; no son 1510 casos únicos |
| SQL integrado por ruta | **120 comprobaciones** por existing/new | 55+21+6+10+4+24; roles, RLS, migraciones y transacciones |
| SQL003 adversarial adicional | **27 llamadas de comprobación**, todas correctas | assert_true/expect_error, solo tmpfs nueva |
| Ruff / pip check | Correctos | Sin dependencias rotas; warning Starlette/httpx documentado |
| OpenAPI/Postman | Validación correcta | 44 operaciones, 71 solicitudes definidas, 23 cuerpos Pydantic y 49 ejemplos positivos |
| Newman existing | **283 aserciones / 74 HTTP**, 0 fallidas | Conteo HTTP varía por polling |
| Newman new | **288 / 75 HTTP**, 0 fallidas | Misma colección sobre bootstrap limpio |
| Newman contrato persistente | **185 / 50 HTTP**, 0 fallidas | Sobre tmpfs, verifica omisión de carpeta negativa persistente |
| Frontend | **96 unitarias/componentes**, 0 fallidas/omitidas | 8 archivos, TypeScript, ESLint y build correctos |
| Navegador previo V2, existing/new | **6 + 6 aprobadas**, 0 fallidas/omitidas | Misma suite repetida, tmpfs independientes |
| A/C/D/E y UX RC1 persistente | **9 aprobadas**, 0 fallidas/omitidas | Chromium real, UI/API/worker/RLS; cuatro anchos y axe |
| Repetición UX después de conservar estilo del encabezado login | **4 aprobadas**, 0 fallidas/omitidas | Mismos cuatro casos, sin regenerar el dataset; no son casos únicos adicionales |
| B tras reinicio + B tras restore | **1 + 1 aprobadas**, 0 fallidas/omitidas | Mismo usuario/dataset contra API/web reales |
| Recuperación RC1 | **13 comprobaciones** aprobadas | Stop/restart, DTO exacto, backup privado, volumen nuevo y aislamiento |
| Laboratorio 2B repetido en RC1 | **45 comprobaciones** aprobadas | DNS/TLS fijado, SSRF, cancelación, RLS, recursos propios |
| Gateway 2C repetido en RC1 | **51 comprobaciones** aprobadas | Filtros IPv4/IPv6, revocación activa, lease, concurrencia y recuperación |

Las 19 pruebas nuevas de seguridad impiden dirigir las herramientas RC1 a perfiles
personales, rutas ambiguas, puertos protegidos, volumen ajeno o configuración
incompleta. Otras dos pruebas TCP reproducen el defecto de reinicio y conservan
el rechazo de listeners ocupados (21 nuevas en total). No son tests que borren
datos ni equivalen a una certificación.

En el nuevo laboratorio 2C se midió revocación→cierre TLS **0.536s**, pérdida del
broker→denegación **1.205s**, máximo refresh **0.543s**, descartes worker IPv4/IPv6
13/14 y gateway2/16. Son observaciones de esta misión, no valores reciclados del
informe 2C anterior ni un SLA. Cero tráfico adversarial a canarios prohibidos.

No ejecutados: NVD live, escaneo de URL/dominio externo, verificación remota,
ZAP, despliegue Internet, suites UI históricas V1 con rutas ausentes de App V2,
otros navegadores y móvil nativo. Estos límites son explícitos y no son skips
silenciosos de las suites ejecutadas.

## Navegador, datos y recuperación

A registra usuario normal, confirma identidad/workspace, crea aplicación, URL y
tecnología por UI, busca CPE y confirma con radio/botón. Inicia consulta CVE del
worker, observa estado, abre CVE-2017-6784 con AND original, conserva
undetermined/reviewed, agrega medida manual pending, consulta historial y vuelve
a entrar. El dashboard se contrasta contra la API, sin métricas inventadas.

C prueba dos cuentas normales en ambas direcciones, IDs ajenos GET/PATCH404,
campos falsificados de rol/workspace422 y reutilización alternada del pool con
lectura propia200/ajena404, además de limpieza de caché al cambiar usuario.
D emite y revoca desafío mediante UI, comprueba caducidad real de una declaración
de ocho segundos, verify503 sin intentos y Baseline disabled. E inyecta solo una
interrupción de red del dashboard para ver carga/error y reintento200 real; no
simula respuestas exitosas de autenticación ni datos inventados.

El driver de recuperación detiene únicamente RC1, arranca el mismo volumen y
compara IDs, fechas y DTO completos de aplicación/tecnología/CPE/ejecución/
hallazgo/recomendación. B repite login e historial. El JWT previo sigue válido
en el mismo perfil. Luego verifica checksum/permisos/Git-ignore del dump y
restaura transaccionalmente en `rc1-restore-<nonce>`, otro volumen nuevo y puertos
55439/8005/5178. Verifica catálogos y compara los mismos DTO; el JWT antiguo
recibe401, login normal funciona y el aislamiento se repite. B se ejecuta en
la copia. Se detienen sus servicios conservando ambos volúmenes y RC1 encendida.

El resultado con nombres, SHA y ruta privada del backup queda en
`api-tests/v2/.artifacts/rc1/recovery-results.json`. Dump/configuración/accesos
no se publican. Contienen secretos y hashes: no se afirma que el backup sea
inofensivo ni que una copia en el mismo disco cubra pérdida física.

## Evidencia, publicación y recomendación

Los logs y resultados completos permanecen privados/ignorados en
`api-tests/v2/.artifacts/rc1/`; capturas pobladas en Frontend
`test-results-rc1/evidence/`. La entrega local exporta solamente documentos,
resultados saneados y capturas revisadas, sin credenciales/tokens/dumps. El
manifiesto final registra hashes de evidencia, commits publicados y verificación
remota normal, sin force push, merges o cambios en main/rudi/MVP-B.

La propuesta académica distingue V1 dispositivos con propiedad individual, V2
aplicaciones con workspaces y móvil pendiente. No se elimina V1 ni se inventa
aprobación de Rudi. **GO técnico para revisión académica local controlada V2**
por integración, regresión y recuperación verificadas; **NO-GO para producción,
entrega final aprobada, escaneo externo o cambio automático del MVP original**.
La ratificación de alcance por Jesel y Rudi sigue pendiente.

# Resultados actuales de API V2

# Estabilización V2 — 2026-11-14

## Resultado y alcance

Backend feat/v2-stabilization parte de 63315644121bb0074cd18f5d2da11720358caea0. Database coordinada: `b377b5bd8013cc2151f6a1681d168e1df0f5fe42`, rama feat/v2-persistent-development-database. Frontend permanece en 4514b6840b428152c1cd875c95e3e55ad81c4196, sin cambios de código. Las pruebas indicadas se ejecutaron en esta misión; no se reutilizan los resultados de recuperación o documentación anteriores.

Se corrigieron tres causas: creación de workspace adicional (no era una limitación deliberada), incompatibilidad undetermined entre API/evaluador y CHECK SQL V2, y título de presentación truncado en espacio que PostgreSQL rechazaba. Las cuatro manifestaciones históricas ahora tienen regresiones positivas.

- Workspace ya devuelve201, crea owner, admite retry/carrera con la misma clave y conserva aislamiento. Se evita SELECT prematuro de INSERT RETURNING/ON CONFLICT y se usa un savepoint para la carrera de unicidad, sin ampliar RLS.
- SQL007 admite undetermined y retiene confirmed y los valores históricos. No modifica filas, evidencia, políticas, roles o guards.
- El truncamiento se hacía en FastAPI, antes de PostgreSQL/HTTP/React/Postman. El título es un resumen deliberado de hasta 500; ahora se recorta espacio final y se avisa TITLE_TRUNCATED. La descripción original del fixture se conserva íntegra en evidence. El presupuesto heredado de evidencia sigue acotado y señaliza omisiones, sin aumentar almacenamiento ilimitadamente.

## Persistencia comprobada

Volumen principal: `vulntrack_v2_development_pgdata`. PostgreSQL propio con etiqueta de instalación, secretos privados y login restringido. La secuencia SQL001/002 → Alembic0001..0004 → SQL004..007 se verificó en una base nueva, sin seed ni stamp ciego. Repetir up no vuelve a ejecutar baseline; parar no elimina el volumen. El modo temporal conserva tmpfs, guards y limpieza de sus propios recursos.

La prueba real usó `vulntrack_v2_validation_869479fe_pgdata` y restauró en `vulntrack_v2_restore_869479fe_pgdata`: cuentas, workspace, aplicación, tecnología/CPE, análisis AND original, historial, hallazgo revisado y recomendación mantuvieron IDs/estado/evidencia tras parar todos los servicios y reiniciar. Otra cuenta siguió sin acceso. Se creó pg_dump custom con SHA256 y se restauró a un volumen NUEVO, sin --clean ni sobrescribir el origen. El JWT permanece válido al reiniciar; tras restore se usa una clave nueva y se requiere login otra vez. Las credenciales SQL y HMAC no se publican.

## Resultados reales

| Comprobación | Resultado |
|---|---|
| Backend completo | **380 aprobadas, 0 fallidas, 0 omitidas**, 194,12s; 9 casos nuevos (4 integración contando parametrización +5 seguridad de recursos) |
| SQL por recorrido | tests/001:55, 002:21, 004:6, 005:10, 006:4 = **96** |
| SQL003 adversarial | **27 comprobaciones**, sin cambios en las aserciones históricas |
| SQL007 reaplicación | Rechazada; constraint idéntico después del rechazo |
| Newman existing | 61 solicitudes distintas;67 envíos por polling; **254 aserciones, 0 fallidas** |
| Newman new | 61 solicitudes distintas;63 envíos; **234 aserciones, 0 fallidas** |
| Guardia de Postman persistente | 39 solicitudes positivas distintas, carpeta 10 omitida;46 envíos/**169 aserciones, 0 fallidas** sobre tmpfs; retención probada aparte |
| React | **77 pruebas en 6 archivos**, typecheck/ESLint/build correctos |
| Chrome/Playwright existing | **5 aprobadas**, 30,7s |
| Chrome/Playwright new | **5 aprobadas**,31, 0s |
| Persistencia/backup/restore | Recorrido HTTP completo aprobado en dos volúmenes propios; aislamiento posterior verificado |
| Docker API | Build nuevo v2-stabilization-review-20261114 y smoke como UID10001, registro/login/owner/401/409 correctos |
| OpenAPI/Postman | Esquemas válidos,39 operaciones/modelos/autenticación del baseline conservados,61 solicitudes preparadas, regeneración verificable |
| Ruff/pip check | Correctos |

Los reintentos/polling y las repeticiones no se suman como casos únicos. La cobertura browser es el perfil de registro/responsividad/aislamiento; CVE/recomendaciones/retención se probaron por HTTP y PostgreSQL, no como recorridos visuales completos de navegador.

## Newman y deprecaciones

Los 19 avisos iniciales eran entradas npm audit:10 paquetes con avisos propios y 9 cadenas heredadas, no19 deprecaciones ni19 CVE distintos. Se mantuvo Newman 6.2.3 y se actualizaron seis dependencias transitivas de la misma versión mayor, con lockfile y recorridos completos aprobados. Resultado: **10 pendientes: 5 altos, 5 moderados, 0 críticos**. Ver [clasificación](../../docs/V2_NEWMAN_DEPENDENCIES.md). Quedan aparte deprecaciones de librerías, Node DEP0176 y Starlette/TestClient/httpx2; no se silenciaron ni se cambiaron dependencias productivas.

## Incidentes y límites

El primer intento de workspace sin RETURNING aún falló por la visibilidad exigida por ON CONFLICT; las dos regresiones fallidas se corrigieron con INSERT normal/savepoint y después pasaron. La primera validación persistente descubrió una consulta incorrecta del marcador de base compartida; se corrigió a shobj_description y la repetición completa pasó. Su volumen de validación anterior se conservó, sin borrarlo. Una comprobación ad hoc de reaplicación comparó objetos de proceso en vez de stdout; se corrigió la aserción y se repitió sobre un clúster nuevo con resultado satisfactorio.

No se alteraron main/Rudi/MVP-B, el diagrama local ni Context. No se ejecutó ZAP, no se escanearon páginas ni se consultó NVD live; tampoco se afirma producción, carga, operación de backups externos cifrados/rotación o recuperación de contraseña. La ratificación global del modelo V2 sigue pendiente.

## Uso y Git

Guía operativa: [V2_PERSISTENT_DEVELOPMENT.md](../../docs/V2_PERSISTENT_DEVELOPMENT.md). Inicio: `python -m scripts.v2_development up`; parada: Ctrl+C o `python -m scripts.v2_development stop`; backup: `python -m scripts.v2_development backup`. La restauración siempre exige perfil/volumen nuevo.

Ramas independientes para publicar mediante push normal, sin merge: Backend feat/v2-stabilization y Database feat/v2-persistent-development-database. El informe final registra los hashes locales/remotos verificados después del commit; no se introduce un hash autorreferente dentro del propio commit. El checkout Frontend original queda limpio.

Evidencia resumida sin secretos: [JSON](../../docs/V2_STABILIZATION_RESULTS.json). Logs/reportes completos locales ignorados en api-tests/v2/.artifacts y backups privados en .local. Ninguno se publica con credenciales.

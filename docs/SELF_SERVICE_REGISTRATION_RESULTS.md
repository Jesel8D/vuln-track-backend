# Evidencia de registro V2 — 2026-11-13

Ensayos reales en Codex Cloud recuperado, Python3.12.14, Docker29.9.2,
Compose2.40.3, PostgreSQL16.15 Alpine fijado por digest. Ninguna URL de una base
persistente existente fue usada. Se clonaron/fetchearon los cuatro repositorios
oficiales; ramas base y hashes están en `MVP_V2_COMPATIBILITY.md`.

## Resultados de cierre

| Comando/cobertura | Aprobadas | Fallidas | Omitidas |
|---|---:|---:|---:|
| `python -m pytest -q tests/unit` | 216 | 0 | 0 |
| `python -m scripts.test_v2_registration --installation existing --full` | 371 | 0 | 0 |
| `python -m scripts.test_v2_registration --installation new` | 32 | 0 | 0 |
| `python -m pytest -q` sin variables PostgreSQL | 216 | 0 | 155 |
| Frontend `npm run check`: Vitest, 6 archivos | 77 | 0 | 0 |
| Playwright registro V2 sobre instalación existente | 5 | 0 | 0 |
| Playwright registro V2 sobre instalación nueva | 5 | 0 | 0 |

La suite completa incluye los216 unitarios y los32 casos de registro; no sumar
repeticiones como casos únicos. La última ejecución completa duró86.91s; la ruta
nueva32 casos6.72s. Los155 skips corresponden exclusivamente a ejecutar pytest
sin el runner PostgreSQL: **sí se ejecutaron** sus pruebas en la suite completa.
Un warning conservado de Starlette recomienda httpx2 para TestClient; no se oculta.

Se fortaleció la prueba de carrera específicamente en la ruta nueva: dos PIDs
PostgreSQL distintos sincronizados antes de insertar; con username idéntico se
observa un backend esperando un lock de unicidad mientras el ganador mantiene su
transacción abierta. Resultado201/409, una cuenta y un workspace. Para usernames
distintos, ambos INSERT permanecen sin commit simultáneamente y terminan201/201.
El test de reutilización de contexto usa otro perfil con pool1/overflow0 y prueba
el mismo PID con usuarios distintos, commit y rollback, sin datos cruzados.
No se usa SQLite ni una política de autorización sintética para esas garantías.

También se verificaron rollback tras insertar usuario/workspace/membresía, retry
después de commit, rechazo de campos internos, duplicados normalizados, seed
inactivo, firma/contexto inválidos o expirados, JWT inválido/caducado, baja de
cuenta, permisos insuficientes y recuperación de datos con un nuevo engine/API.

## SQL, Alembic, contenedor y navegador

Database `tests/001_integrity.sql`:55; `002_v2_security.sql`:21;
`004_v2_workspace_bootstrap.sql`:6; nuevo `005_self_service_privileges.sql`:10.
**92 comprobaciones SQL por recorrido**, repetidas por los runners; sin editar las
aserciones originales. `003_v2_adversarial.sql` también se ejecutó sin cambios
en otro clúster nuevo: **27 aprobadas**,0 fallidas. Incluye preparación repetida;
no son119 casos nuevos únicos. Confirma además que el nonce no es de un solo uso:
una firma vigente admite replay dentro de su vigencia. El backend no expone
firmas/clave a clientes ni instala GUC de sesión; el protocolo actual conserva ese límite.

Runner general Database `tests/run.sh` completado sobre una copia temporal de
**solo archivos públicos de prueba**:92 avisos SQL satisfactorios y6 confirmaciones
adicionales (loopback, SCRAM/rechazo de contraseña, baseline rechazado al reaplicar,
concurrencia/rollback/snapshot, reinicio y recreación con el mismo volumen).
Proyecto final: `vulntrack-db-test-registration-final-593638f6`.
El contenedor quedó detenido; su volumen temporal se conserva según ese runner.
El helper Backend usa tmpfs y elimina únicamente sus contenedores propios al parar.

`alembic heads`: `0004_mvp_cve`. No se crea otra revisión por un grant de rol.
La suite completa ejecuta upgrade/check y regresiones históricas, incluyendo
rechazo de drift y baseline verificado. La ruta nueva aplica SQL004/005 antes
de Alembic para probar bootstrap coexistente; el delta exacto incluye29 políticas.
No se utilizó stamp a ciegas ni se ignoraron tablas arbitrarias para hacer pasar check.

`ruff check .`, `python -m pip check` y compileall: correctos. Frontend: typecheck,
ESLint, Vitest, build y Prettier de TS/TSX/CSS/configuración cambiados correctos; `npm audit`:
**0 vulnerabilidades** (incluidas dependencias de desarrollo). Ruff también comprueba
el nuevo launcher Python del frontend. No se cambiaron lockfiles/dependencias.

Docker build correcto con CA montada como secreto de BuildKit, sin desactivar TLS:

```bash
docker build --secret id=proxy_ca,src=/etc/ssl/certs/ca-certificates.crt -t vulntrack-backend:v2-registration .
python -m scripts.test_registration_container
```

Imagen verificada `sha256:df2d0b09a64e76a46cf8ad6979af3541b1ccdb379d932071d3cb5c52c4614772`.
Smoke HTTP desde la imagen: UID10001, readiness, registro201, login, me, workspace
owner, listado vacío,401 sin sesión y409 de reintento. Secretos solo por entorno.

Playwright usa Chromium `/usr/bin/chromium`, React/Vite y API/JWT/RLS/SQL reales.
No intercepta autenticación ni necesita NVD. Se comprobaron formulario/confirmación,
errores reales422/409/429, login/me, dashboard/aplicaciones/historial vacíos,
registro de aplicación por la UI, tecnología vacía, separación A/B y cachés,
logout/rutas privadas, ausencia de almacenamiento de tokens y ZAP disabled.
Formulario a375px: sin desbordamiento y **0 violaciones axe**; también se comprobó
el ancho1440px. La captura conservada muestra el formulario vacío, sin credenciales.

## Incidentes observados y corregidos

- Baseline unitario:185 aprobadas; Ruff inicial tenía60 errores de la línea rudi.
  Se corrigieron imports/formato/SQL con espacios equivalentes; no se suprimieron reglas.
- Dos intentos iniciales de integración dieron28 aprobadas/2 fallidas por una
  aserción nueva que buscaba `total` fuera de `page`. Se corrigió el test para
  comprobar el contrato real y exigir también HTTP200; no se cambió la API.
- La primera suite completa dio363 aprobadas/3 fallidas: fixtures heredaban flags
  del runner; faltaba el nombre de rol SQL esperado por la regresión de readiness;
  `alembic check` proponía eliminar tablas V2. Se aislaron los fixtures, se usó el
  rol temporal esperado y se verificó todo el delta V2 antes de filtrar la comparación ORM.
- Primer navegador:3 aprobadas/2 fallidas. Se corrigieron el estado vacío de
  historial, landmarks/encabezado del formulario móvil y un locator que no usaba
  el texto real del botón ZAP. No se deshabilitó ninguna regla axe.
- Compose directo falló antes del bootstrap: checkout privado0700/0600 y Docker
  rootless no permitían leer scripts montados. Se mantuvieron sus permisos y se
  ensayó una copia temporal pública limitada a init/sql/seed/tests/compose/env.example.
- Una recreación Compose agotó el disco7.9GiB. Esa ejecución llegó a92 SQL,
  concurrencia y reinicio correctos; no se contó como runner exitoso. Otra ejecución
  backend terminó370 aprobadas/1 error de creación de directorio pytest por ENOSPC.
  Se retiraron solo tres contenedores detenidos creados en esta misión, sin `-v`;
  no se podaron imágenes, redes, volúmenes ni respaldos. Las repeticiones finales
  completas pasaron con espacio disponible.

## Límites y clasificación

**IMPLEMENTADO Y PROBADO:** registro/login/me, onboarding atómico, normalidad de
cuentas, aislamiento API/RLS con usuarios HTTP reales, reutilización de conexiones,
integridad/carreras/rollback, coexistencia SQL/Alembic y UI de registro/estados vacíos.

**IMPLEMENTADO CON LIMITACIONES:** limitador por proceso, registro opt-in sin prueba
de identidad/correo, JWT sin revocación individual y protocolo HMAC de corta vigencia
sin nonce consumible. No equivale a certificación de seguridad ni preparación de producción.

**PENDIENTE:** aprobación global workspace/dispositivos, coordinación de integración,
cuotas distribuidas, recuperación/cambio de contraseña, políticas de retención,
custodia/rotación operativa de claves, carga, restore real y despliegue HTTPS/CSP.

**NO EJECUTADO:** E2E históricos MVP de rutas diferentes, navegadores distintos de
Chromium, dispositivos móviles nativos, pruebas de todas las operaciones NVD y
recomendaciones V2, NVD en vivo, escaneos, ZAP y migraciones sobre bases persistentes
ajenas. Los archivos E2E históricos se conservan intactos; no se cuentan como aprobados V2.

No hay repositorios bloqueados por acceso en esta ejecución. La integración
definitiva sigue pendiente de revisión/publicación coordinada; no hay push ni merge.

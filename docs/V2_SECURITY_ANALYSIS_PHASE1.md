# Análisis de seguridad web — entrega de Fase 1

Fecha: 2026-11-15. Entorno local Windows 11, Ubuntu 24.04 WSL2 y Docker Desktop.
**IMPLEMENTADO CON LIMITACIONES. ZAP NO está autorizado para activarse.**

La misión autoriza implementar y probar controles preparatorios, no escanear,
activar ZAP, desplegar sobre sesiones activas o aprobar globalmente la arquitectura.
Las decisiones de producto compartidas de Jesel y Rudi siguen pendientes donde
el contexto así lo indica. D-001 y D-002 permanecen intactas.

## A. Estado inicial y separación de trabajo

| Repositorio | Rama activa original | HEAD verificado contra GitHub |
|---|---|---|
| Backend | feat/v2-stabilization | fcabbe986f2a4d3dffb259edda0b7245e533ee91 |
| Database | feat/v2-persistent-development-database | b377b5bd8013cc2151f6a1681d168e1df0f5fe42 |
| Frontend | feat/v2-registration-web | 4514b6840b428152c1cd875c95e3e55ad81c4196 |
| Context | docs/mvp-context-consolidation | caa7ef13b0e2b24848991e32b3c0ee3fc59139c7 |

La rama remota Backend test/v2-api-collection sigue en
63315644121bb0074cd18f5d2da11720358caea0. No se fusionó: estabilización ya contiene
su colección. No se tocaron main, rudi, MVP-B ni las ramas que ejecutan la
instalación principal.

Los originales permanecen en /home/mz/VulnTrack. El trabajo nuevo está en
/home/mz/VulnTrack-security-phase1: Backend y Frontend tienen ramas nuevas;
Database es un worktree detached del commit compatible, sin cambios SQL.

## B. Persistencia — IMPLEMENTADO Y PROBADO en instalación aislada

La instalación principal estaba ready, con PostgreSQL saludable y API/Vite
activos en 8000/5173. Se comprobó Docker integrado, Python 3.12.3, Node 24.18.0 y
el launcher real. No se detuvieron sus servicios ni se usó una cuenta personal.

El runner publicado scripts.test_v2_persistence pasó en perfiles nuevos:
validation-7e1f154b y restore-7e1f154b. Conservó usuarios, owner/membresía,
aplicación, tecnología/CPE, análisis NVD fixture, evidencia, revisión e historial,
recomendación e IDs tras parar y reiniciar API/worker y PostgreSQL propios. Otra
cuenta siguió sin acceder a los datos de la primera. La restauración en un volumen
nuevo conservó esos datos y rotó JWT correctamente. Ambos volúmenes quedaron
conservados y sus contenedores detenidos. No se ejecutó ZAP ni NVD live.

**PENDIENTE:** repetir con una aplicación DEMO en la instalación principal en una
ventana acordada sin actividad. El checklist está al final. La prueba aislada
usa HTTP real y PostgreSQL; no se presenta como recorrido visual completo de Vite.

## C. Respaldo y restauración

**IMPLEMENTADO Y PROBADO:** backup de la instalación principal mediante
scripts.v2_development backup mientras seguía activa; archivo privado en
.local/development/backups/20261115T174453Z-90d6/database.dump con su manifiesto.
No se publica su contenido ni sus secretos.

El runner de persistencia verificó pg_dump custom, checksum y restauración del
backup sintético en vulntrack_v2_restore_7e1f154b_pgdata. No se restauró ni
sobrescribió la base principal. Copia fuera del disco, cifrado, rotación y ensayo
operativo de recuperación de los datos personales reales: **PENDIENTE**.

## D. Auditoría de destinos

**IMPLEMENTADO CON LIMITACIONES:** los destinos ya tenían FK de workspace y
aplicación, JWT, RLS, roles, vigencia, control optimista y auditoría transaccional.
La validación previa de URL comprobaba esquema/userinfo/fragmento/puerto, pero
admitía loopback, redes privadas, puertos arbitrarios y formas ambiguas de host.
No había DNS validado, control del dominio, transporte con IP fijada, aislamiento
de salida ni executor ZAP. La vista mostraba solo declaraciones approved activas.

El registro de una URL nunca prueba autorización. Un approved existente es una
declaración de owner/editor; no se convierte en verificación. Detalle, estados y
límites de auditoría: [V2_TARGET_AUTHORIZATION.md](V2_TARGET_AUTHORIZATION.md).

## E. Backend — IMPLEMENTADO Y PROBADO para controles locales

- Política reutilizable de URL pública, canonicalización y conjuntos DNS con
  pruebas sin resolver ni contactar servicios externos.
- Rechazo de nuevos destinos inseguros en TargetCreate, sin reescribir filas
  históricas ni cambiar contratos de autenticación/NVD.
- analysis_readiness aditivo en las respuestas de destinos: evidencia ausente
  significa control sin verificar; ejecución siempre false y bloqueos explícitos.
- Contrato interno de evidencia ligado a IDs, origen, versión, vigencia y
  revocación, sin productor remoto ni persistencia ficticios.
- Retirada de declaración mediante rejected, con evento withdrawn cuando
  sustituye una aprobación; mismo bloqueo/versión y atomicidad de auditoría.
- No hay endpoint o worker para lanzar análisis web. No hay flag de activación.

La colección conserva 39 operaciones y 61 solicitudes definidas. Su positivo de
registro antes usaba localhost:8080; ahora registra un dominio público de ejemplo
sin conectarse a él. Los rechazos locales están cubiertos por pruebas negativas.
Se regeneraron ejemplos sintéticos/OpenAPI y se añadieron aserciones de bloqueo.
El verificador conserva el baseline de requests, éxitos tipados y autenticación.
Las salidas de destinos conservan el esquema permisivo heredado; la validación
de readiness se prueba en el serializer y cliente, no se atribuye a ese esquema.

## F. Database

**IMPLEMENTADO Y PROBADO: compatibilidad sin cambios SQL.** Se reutilizan los
estados, grants, auditoría, FK y las 29 políticas RLS publicadas. No hay rama SQL
nueva, modelos/migraciones nuevos ni cambio del manifiesto de fuentes.
Los ensayos de bootstrap limpio y camino de migración compatible usan clústeres
desechables. No se aplicó SQL experimental a la instalación principal.

## G. Frontend

**IMPLEMENTADO Y PROBADO:** tipado y validación de readiness; destinos pendientes,
declarados, rechazados/retirados y vencidos visibles desde la API real. La falta de
metadata válida falla cerrado. Se puede retirar una declaración con motivo y
versión usando el endpoint existente, sujeto a owner/editor en Backend.

Se conserva la disposición responsive, con ajustes de contraste y nombre accesible
de la marca detectados por Axe en navegador. El botón de análisis permanece disabled
literalmente, incluso ante una respuesta hipotética de control verificado.
Dashboard e inventario describen declaraciones, sin prometer control verificado.
Baseline se explica como rastreo que genera tráfico, sin resultados inventados.

Las ramas nuevas no se desplegaron sobre la sesión principal. Frontend requiere
el Backend de esta fase para recibir readiness; no se debe actualizar solo uno.

## H. Política SSRF — IMPLEMENTADO CON LIMITACIONES

La validación estática y los planes/revalidación DNS están implementados y
probados. No hay un resolver remoto ni un transporte que aplique el plan.
No se afirma protección completa frente a TOCTOU/rebinding en conexiones reales.
Requisitos y matriz de amenazas: [V2_SSRF_THREAT_MODEL.md](V2_SSRF_THREAT_MODEL.md).

## I–J. Pruebas y regresiones

| Verificación | Resultado de esta misión |
|---|---|
| Persistencia/backup/restore sintético | Aprobado en perfiles/volúmenes nuevos; principal activo |
| Pruebas nuevas | 138 unitarias y 21 de integración incluidas en las suites completas |
| Backend completo existing | 539 aprobadas, 0 fallidas y 0 omitidas; 149,75 s |
| Backend completo new | 539 aprobadas, 0 fallidas y 0 omitidas; 142,47 s |
| SQL001/002/004/005/006 | 55/21/6/10/4 comprobaciones por recorrido desechable (96) |
| SQL003 adversarial | 27 comprobaciones aprobadas en otro clúster desechable |
| React | 82 pruebas en 7 archivos; typecheck, ESLint y build correctos |
| Navegador Chromium existing | 6 aprobadas, 13,8 s; API/JWT/RLS reales sobre tmpfs y puertos libres |
| Navegador Chromium new | 6 aprobadas, 13,5 s; mismo alcance sobre bootstrap nuevo |
| Postman existing | 61 solicitudes definidas, 62 envíos por polling; 232 aserciones, 0 fallos |
| Postman new | 61 solicitudes definidas, 62 envíos por polling; 232 aserciones, 0 fallos |
| Guardia Postman persistente | 39 solicitudes enviadas, 137 aserciones, 0 fallos, siempre sobre tmpfs |
| OpenAPI/Postman offline | 39 operaciones conservadas, 61 requests, 17 cuerpos Pydantic y ejemplos sanitizados válidos |
| Ruff / pip check | Correctos; IDNA 3.20 ya bloqueado se declara dependencia directa sin actualizar locks |

Los duplicados por polling y recorridos repetidos no se suman como casos únicos.
La prueba nueva de navegador registra destinos/declaraciones sintéticos solo en
tmpfs, verifica que no se emitan requests externos y comprueba el bloqueo en
1440 y 390 píxeles. Axe no encontró incidencias en esos estados tras ajustar
contraste/etiqueta de marca. Esto no certifica accesibilidad de toda la aplicación.
Los diagnósticos SQL de denegación esperada no son fallos de esas pruebas.
Newman conserva las dependencias/deprecaciones y avisos transitivos documentados
en V2_NEWMAN_DEPENDENCIES.md; no se actualizaron locks para ocultarlos.

Para reproducir las regresiones, siempre desde el worktree aislado:

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack-security-phase1/vuln-track-backend
.venv/bin/python -m scripts.test_v2_registration --full
.venv/bin/python -m scripts.test_v2_registration --installation new --full
.venv/bin/python api-tests/v2/validate.py
.venv/bin/python api-tests/v2/run.py
.venv/bin/python api-tests/v2/run.py --installation new
.venv/bin/python api-tests/v2/run.py --persistent-contract
# Crea perfiles/volúmenes nuevos y conserva los backups de validación:
.venv/bin/python -m scripts.test_v2_persistence
cd ../vuln-track-frontend
npm run check
export PLAYWRIGHT_CHROMIUM_EXECUTABLE="$(node --input-type=module -e "import { chromium } from 'playwright'; process.stdout.write(chromium.executablePath());")"
../vuln-track-backend/.venv/bin/python scripts/v2_registration_stack.py --e2e --api-port 0 --web-port 0
../vuln-track-backend/.venv/bin/python scripts/v2_registration_stack.py --e2e --installation new --api-port 0 --web-port 0
```

Los logs/reportes privados están en api-tests/v2/.artifacts/phase1 y las capturas
en Frontend test-results, todos ignorados por Git. No se guardan HAR, trazas,
contraseñas o JWT en los artefactos versionados. El informe de persistencia
permanece en api-tests/v2/.artifacts/persistence-results.json.

## K–M. RLS, módulo y ZAP

**IMPLEMENTADO Y PROBADO:** pruebas reales de JWT ausente/inválido, usuario ajeno,
IDs cruzados, viewer/editor, estado vencido, auditoría, rollback, pool de una
conexión y concurrencia. No se desactiva RLS. No hay lectura de auditoría privada
por el login API ni un rol administrativo global nuevo.

El contexto HMAC es local a la transacción, vence y no se expone al cliente. Su
nonce no es de un solo uso: SQL003 documenta replay dentro de su vigencia. No se
presenta como protección contra un operador que ya posea credenciales y la HMAC.

El módulo prepara y explica estados. **ZAP: BLOQUEADO.** Ausencia de endpoint de
escaneo, guardia de executor y botón incondicionalmente deshabilitado se verifican
con pruebas. No hubo ejecución, descarga de imágenes ZAP ni tráfico de escaneo.

## N–P. Riesgos, ramas y Fase 2

**PENDIENTE:** verificación remota segura, origen confiable/persistencia de prueba,
revisión administrativa, transporte con IP fijada, gateway/ACL de salida probado,
límites operativos, cancelación/revocación en ejecución y auditoría de trabajos.
La posesión de DNS no acredita por sí sola autorización legal. No se promete
producción ni seguridad de un contenedor cuya red no se ha probado.

Ramas de entrega: Backend feat/v2-security-analysis-phase1 y Frontend
feat/v2-security-analysis-web-phase1. Los hashes de entrega se informan después
de commit/push normal y de comprobar las referencias remotas, sin introducir un
hash autorreferente aquí. Database/Context no requieren commits. No se crea PR,
merge o despliegue automático.

Fase 2 necesita decisiones explícitas de Jesel y Rudi sobre método de control,
alcance del permiso, vigencias, responsables, retención, presupuestos y política
de salida. La habilitación de ZAP requiere otra autorización y pruebas reales
de transporte/aislamiento. Este documento no la concede.

## Q. Continuar usando VulnTrack en WSL2

La instalación personal mantiene sus checkouts originales y su volumen. En Ubuntu:

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack/vuln-track-backend
.venv/bin/python -m scripts.v2_development status
# Solo si está detenido:
.venv/bin/python -m scripts.v2_development up --frontend ../vuln-track-frontend --nvd-mode fixture
```

Parada en una ventana acordada sin actividad y backup:

```bash
cd /home/mz/VulnTrack/vuln-track-backend
.venv/bin/python -m scripts.v2_development stop
# Backup es una operación independiente; inicia PostgreSQL si estaba parado:
.venv/bin/python -m scripts.v2_development backup
```

Para revisar las ramas nuevas sin adoptar la base personal, usar un perfil nuevo:

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack-security-phase1/vuln-track-backend
.venv/bin/python -m scripts.v2_development up --profile phase1-preview --pg-port 55435 --api-port 8001 --web-port 5174 --frontend ../vuln-track-frontend --nvd-mode fixture
# Detener ese perfil desde otra terminal en esta misma carpeta:
# .venv/bin/python -m scripts.v2_development stop --profile phase1-preview
```

No usar el perfil development desde este worktree para adoptar recursos ajenos.
El preview tendrá datos propios vacíos y no se inició automáticamente.

### Checklist manual pendiente en la instalación personal

1. Acordar una ventana sin actividad y generar backup con el launcher original.
2. Crear una cuenta de prueba claramente identificada; registrar una aplicación
   DEMO, anotar usuario/workspace/aplicación y comprobar que otro usuario no la ve.
3. Detener limpiamente, reiniciar con fixture e iniciar sesión con esa cuenta.
4. Confirmar mismos IDs, membresía y aplicación; verificar aislamiento con otra cuenta.
5. Conservar datos y backup; no limpiar tablas ni borrar volúmenes para repetir.

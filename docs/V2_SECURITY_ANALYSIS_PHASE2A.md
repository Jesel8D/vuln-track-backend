# Fase 2A: componentes probados, integración remota bloqueada

**IMPLEMENTADO CON LIMITACIONES. ZAP NO está autorizado para activarse.**

Misión de Jesel del 15 de noviembre de 2026. Autoriza implementación y pruebas
locales, commits y push normal de ramas nuevas; no autoriza despliegue personal,
escaneos ni aprobación técnica global. D-001/D-002 permanecen intactas; las
decisiones de arquitectura conjunta siguen PENDIENTES de Jesel/Rudi.

## 1. Código inspeccionado — IMPLEMENTADO Y PROBADO

Se verificaron rutas WSL, worktrees, limpieza, remotos y procesos. Base personal:

| Repositorio | Rama original | HEAD verificado |
|---|---|---|
| Backend | feat/v2-stabilization | fcabbe986f2a4d3dffb259edda0b7245e533ee91 |
| Database | feat/v2-persistent-development-database | b377b5bd8013cc2151f6a1681d168e1df0f5fe42 |
| Frontend | feat/v2-registration-web | 4514b6840b428152c1cd875c95e3e55ad81c4196 |
| Context | docs/mvp-context-consolidation | caa7ef13b0e2b24848991e32b3c0ee3fc59139c7 |

Fase 1 remota comprobada antes de crear ramas: Backend
56c1274fdb4f48f7c2cb852c4975c8c0ec5bafff y Frontend
e0f3abbf352b1c23db1654afed3071437b3f2e33. Rama Postman 6331564 inspeccionada,
sin merge. No se modificaron main, rudi, Database ni Context.

Inspección funcional: targets, declaraciones, JWT, workspace_session, contexto
HMAC, RLS/FK compuestas, auditoría, arranque, worker NVD, contratos Postman y
componentes React. El estado SQL approved sigue siendo una declaración de un
owner/editor; no acredita control técnico ni permiso para lanzar análisis.

## 2. Protección y compatibilidad — IMPLEMENTADO CON LIMITACIONES

La instalación personal sigue en /home/mz/VulnTrack. No se cambió su código, no
se detuvieron sus servicios y no se probó contra sus cuentas. El volumen
vulntrack_v2_development_pgdata no se borró, recreó, restauró ni utilizó para
pruebas. PostgreSQL conserva publicación exclusiva en 127.0.0.1:55434.

Los cambios viven en /home/mz/VulnTrack-security-phase2a. Las pruebas SQL/API usan
PostgreSQL tmpfs con credenciales efímeras y roles restringidos. La prueba de
actualización usa perfiles persistentes NUEVOS upgrade-<nonce> y
upgrade-restore-<nonce>, detenidos al terminar y con volúmenes conservados.

`scripts.test_v2_upgrade` ejecuta procesos Python independientes de la versión
estable, Fase 1, Fase 2A y regreso a la estable sobre el mismo volumen sintético.
Comprueba registro/login, membresía, IDs de aplicación/destino, versión de la
declaración y denegación A/B. También reinicia esa base, respalda y restaura en
OTRO volumen y verifica rollback. Compara fuentes de migraciones; no introduce
migraciones nuevas. Esto demuestra compatibilidad local del código inspeccionado,
no una intervención de actualización sobre la instalación personal.

El backup personal de Fase 1 permanece privado y se volvió a comprobar su
checksum (155478 bytes, sin mostrar el contenido SQL). No se ejecutó un restore ni una
prueba de reinicio personal en esta misión. El ensayo manual de actualización
personal sigue PENDIENTE y tiene instrucciones concretas en el plan enlazado.

## 3. Componentes nuevos — IMPLEMENTADO CON LIMITACIONES

`web_target_evidence.py` separa el contrato interno ControlEvidence, conservando
su import público anterior para compatibilidad. No añade tablas ni campos SQL.

`web_target_challenges.py` ofrece una referencia local explícitamente llamada
LaboratoryChallengeStore/LaboratoryVerifier. Emite 256 bits aleatorios, con
propósito y UUID propios, ruta HTTPS fija bajo el origen canónico y TTL máximo
de diez minutos limitado por la declaración. Solo conserva SHA-256 del cuerpo
esperado; no conserva el token en claro ni lo incluye en repr/auditoría.

La referencia vincula workspace, aplicación, destino, actor, rol, versión de
declaración y origen. Solo owner/editor con declaración vigente y aplicación
activa puede emitirla. Una sección crítica reclama el desafío una sola vez;
errores consumen el intento y requieren uno nuevo. Antes de producir evidencia
se vuelve a comprobar el scope, su vigencia y el token exacto mediante comparación
constante del digest. Cambios de membresía/declaración, caducidad o revocación
impiden confirmar la evidencia. Esta vence como máximo en 24 horas y nunca
después de la declaración. Los valores son PROPUESTAS locales, no política
global aprobada.

La auditoría local registra IDs, actor, acción, versión y propósito, sin tokens,
URLs, query strings ni cuerpos. Un fallo del sink antes del commit no publica
evidencia. El almacén está limitado a 256 registros sin borrar marcadores de
repetición; **no es duradero ni un repositorio de producción**. Sus Scope son
contratos internos de pruebas; un futuro adaptador deberá construirlos desde
JWT, membresía y filas bloqueadas bajo RLS, nunca desde JSON del cliente.

## 4. Pruebas y evidencias

**IMPLEMENTADO Y PROBADO**, sin fallos en los recorridos finales:

| Verificación | Resultado |
|---|---|
| Backend completo, existing | 598 passed; 0 skipped |
| Backend completo, new | 598 passed; 0 skipped |
| Nuevas unitarias Fase 2A, incluidas arriba | 59 passed |
| SQL001/002/004/005/006 | 55+21+6+10+4 = 96 por bootstrap |
| SQL003 adversarial, otro tmpfs | 27 passed |
| React/Vitest | 86 passed, 7 archivos |
| TypeScript, ESLint y compilación | Aprobados |
| Chromium, existing/new | 6 passed por recorrido |
| Newman existing/new/persistent-contract | 257/267/177 aserciones, 0 fallos |
| Laboratorio TCP/TLS/red/recursos | 27 comprobaciones aprobadas |
| Actualización, rollback, reinicio y restore aislados | Aprobados |
| Ruff / pip check | Aprobados |

La colección mantiene 61 solicitudes definidas; se enviaron 67/69/47 solicitudes
respectivamente por polling y guardias de ejecución. Esas repeticiones y los
recorridos no se suman como casos únicos. La guardia persistent-contract se
probó sobre tmpfs, nunca sobre el volumen personal. OpenAPI/Postman conservan
39 operaciones, 17 cuerpos Pydantic y 42 ejemplos positivos; SHA-256 OpenAPI
41dc15ba8c53292d15e78a6d6c87a1cf1e8956c94dbffae5a6cf6e9275b09d97.
No se cambiaron locks. Se conservaron advertencias heredadas de Starlette y
Newman sin actualizar dependencias. Axe y overflow se comprobaron en los
estados de escritorio/móvil ensayados; no se declara certificación WCAG completa.

Preparar únicamente las dependencias de estos worktrees, si aún faltan:

```bash
cd /home/mz/VulnTrack-security-phase2a/vuln-track-backend
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.lock -r api-tests/v2/requirements-api.lock
.venv/bin/python -m pip install --no-deps -e .
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
npm ci --prefix api-tests/v2
(cd ../vuln-track-frontend && npm ci)
```

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack-security-phase2a/vuln-track-backend
.venv/bin/python -m scripts.test_v2_registration --full
.venv/bin/python -m scripts.test_v2_registration --installation new --full
.venv/bin/python -m scripts.test_v2_upgrade
.venv/bin/python -m scripts.test_v2_security_lab
.venv/bin/python api-tests/v2/validate.py
.venv/bin/python api-tests/v2/run.py
.venv/bin/python api-tests/v2/run.py --installation new
.venv/bin/python api-tests/v2/run.py --persistent-contract
.venv/bin/ruff check .
.venv/bin/python -m pip check
cd ../vuln-track-frontend
npm run check
export VULNTRACK_BACKEND_PATH=/home/mz/VulnTrack-security-phase2a/vuln-track-backend
export PLAYWRIGHT_CHROMIUM_EXECUTABLE=/home/mz/.cache/ms-playwright/chromium-1254/chrome-linux64/chrome
../vuln-track-backend/.venv/bin/python scripts/v2_registration_stack.py --e2e --api-port 0 --web-port 0
../vuln-track-backend/.venv/bin/python scripts/v2_registration_stack.py --e2e --installation new --api-port 0 --web-port 0
```

SQL003 adversarial se ejecuta además una vez en otro PostgreSQL tmpfs propio:

```bash
cd /home/mz/VulnTrack-security-phase2a/vuln-track-backend
.venv/bin/python - <<'PY'
import re
from scripts.disposable_v2 import DisposableV2
with DisposableV2('new', sql_checks=False) as stack:
    result = stack.apply('tests/003_v2_adversarial.sql')
    assert len(re.findall(r'ok - ', result.stderr)) == 27
    print('27 comprobaciones SQL003 aprobadas')
PY
```

El laboratorio puede descargar la imagen oficial fijada y dependencias de
construcción. Esas descargas no son pruebas de destinos; todas las conexiones
de verificación y pruebas adversariales ocurren dentro del namespace sin red.
Los paquetes apt se resuelven al construir: el digest de la imagen base y el ID
final se registran, pero no se afirma reproducibilidad binaria de apt. Cada
ejecución genera certificados sintéticos nuevos; ninguna clave se versiona.

Evidencias privadas e ignoradas: api-tests/v2/.artifacts/phase2a, .local y
test-results del Frontend. El protocolo del laboratorio entrega el cuerpo del
desafío exclusivamente por pipes al orquestador y al fixture; no lo imprime en
el informe ni en logs. No se suman repeticiones como pruebas únicas.

## 5–6. Verificación técnica de dominios — BLOQUEADO en servicio

Se prueba emisión → transporte HTTPS real del laboratorio → consumo → evidencia
→ revocación. Esto no verifica ningún dominio de Internet ni cuenta personal.
No hay endpoint de desafíos, verificación o autoaprobación, ni worker que los
ejecute. El serializador real mantiene evidence=None y control_verified=false
para las declaraciones existentes. Un flag de entorno no cambia ese bloqueo.

DNS TXT y verificación administrativa permanecen PENDIENTES: requieren resolver
acotado y política de desafíos/revisores aprobada. La variante HTTPS no funciona
con HTTP, redirecciones, cookies, credenciales, compresión, respuestas chunked ni
contenido arbitrario. Exige un archivo text/plain pequeño con Content-Length y
cierre de conexión. No se considera prueba legal de permiso para analizar.

Persistencia de desafíos/evidencia, consumo único entre procesos, rate limits,
cuotas, recuperación tras caídas y auditoría duradera con RLS son PENDIENTES.
Debe coordinarse SQL Database y modelos/Alembic Backend según D-002 antes de
conectar este componente al servicio. No se añadió esquema innecesario mientras
el flujo real permanece bloqueado.

## 7. Transporte SSRF — IMPLEMENTADO CON LIMITACIONES

PinnedHTTPS reutiliza DestinationPolicy HTTPS/443. Revalida todas las respuestas
inmediatamente antes de conectar y rechaza cambios, planes viejos, conjuntos
mixtos y destinos prohibidos. Selecciona una única IP numérica canónica para un
socket AF_INET/AF_INET6; no usa create_connection con hostname. El peer conectado
debe coincidir con la IP seleccionada. Se conserva el hostname original en SNI,
verificación de certificados y Host. TLS mínimo 1.2 explícito, CERT_REQUIRED y
check_hostname obligatorios; también se rechaza un contexto inseguro inyectado.

No se consultan proxies de entorno, no se reintenta ni se sigue Location, incluso
del mismo origen. Solo GET, cabeceras fijas, sin cookies/autenticación. Límite de
8192 bytes de cabeceras, 4096 de cuerpo, cinco segundos de intercambio I/O y
cierre acotado a 0.2 segundos; configurable únicamente hacia límites menores.
Respuestas ambiguas/duplicadas, codificadas o sin longitud válida fallan cerrado.
Cancelación de tarea o evento cierra sockets, también durante handshake/lectura.
Errores públicos son códigos estables, sin datos recibidos ni excepciones DNS.

La prueba real prohíbe socket.getaddrinfo durante el intercambio y comprueba TCP,
certificado, Host y SNI para IPv4/IPv6. Un cambio DNS aborta antes de conectar.
No se afirma que un plan o una revalidación por sí solos autoricen solicitudes.

**PENDIENTE:** adaptador DNS operativo, autorizado y acotado en tiempo. El resolver
inyectado es síncrono, en memoria en las pruebas; sus llamadas ocurren fuera del
deadline I/O. No debe conectarse un resolver bloqueante/arbitrario al servicio.
Tampoco se ha desplegado un contexto de red con salida pública controlada. Por
ello PINNED_TRANSPORT_UNAVAILABLE y NETWORK_ISOLATION_UNAVAILABLE siguen siendo
motivos reales de bloqueo del contrato API: indican indisponibilidad en servicio.

## 8. Aislamiento — IMPLEMENTADO CON LIMITACIONES

El laboratorio comparte únicamente un namespace Docker `--network none`, con
fixtures vinculados a loopback y sin interfaces externas, rutas externas ni
puertos publicados. Las IP con apariencia pública son alias locales de ese
namespace para ejercitar la política sin excepciones a redes privadas; no se
envían paquetes a sus titulares externos ni se resuelve example.net públicamente.

Un helper de confianza con NET_ADMIN instala OUTPUT DROP IPv4/IPv6 y permite
solo las IP/puerto 443 de los fixtures y respuestas de conexiones establecidas.
Ese helper termina antes de iniciar las pruebas; no es el worker ni usa red del
host o modo privileged. No se modifican reglas del host Docker/WSL.

Worker: UID/GID 65532, CapDrop ALL, CapAdd vacío, no-new-privileges, raíz de solo
lectura, tmpfs noexec/nosuid/nodev de 8 MiB, sin bind mounts de usuario ni docker.sock,
sin volúmenes PostgreSQL, sin secretos de aplicación. CPU 0.5, memoria/swap 128 MiB,
32 PIDs, 64 FDs y logs locales rotados de 1 MiB × 2. Se inspeccionan configuración
y cgroups en ejecución; una sonda separada de 32 MiB confirma OOM real con código
137. El runner controla tiempo y elimina exclusivamente sus contenedores por
etiqueta aleatoria; no crea ni elimina volúmenes de este laboratorio.

Las sondas negativas saltan deliberadamente Python y usan sockets TCP/UDP crudos:
loopback, canarios privados/5432, metadatos/80, HTTP/80, DNS y loopback IPv6. Los
canarios locales escuchan y deben recibir cero conexiones/datagramas. Eso prueba
un control de red independiente en este laboratorio, no solo tests unitarios.

WSL2/Docker Desktop: las reglas viven en un namespace del kernel Linux administrado
por Docker. No prueban reglas del firewall Windows, egreso público selectivo de
un futuro runner, aislamiento multiworkspace de jobs ni resistencia a un host/
daemon comprometido. Un administrador del host puede modificar contenedores.
La cancelación/borrado del laboratorio no equivale a un scheduler duradero con
recuperación tras caída. Esos controles siguen PENDIENTES.

## 9–10. Frontend y ZAP

**IMPLEMENTADO Y PROBADO:** la UI distingue declaración, verificación técnica y
elegibilidad. Muestra pendientes, verificados, rechazados/retirados, revocados,
expirados e incompletos únicamente según el contrato recibido. Los estados
verificados/revocados del contrato no se fabrican para registros históricos.
No se añadió un botón operativo de desafíos ni nuevos contratos HTTP de escritura.
El botón de análisis permanece disabled independientemente de la selección.

**BLOQUEADO:** ZAP no se instaló, descargó, ejecutó ni registró como endpoint.
No se generaron hallazgos ZAP, ni datos de demostración en la base personal.
Baseline rastrea y genera tráfico; las pruebas aprobadas no autorizan su uso.

## 11–13. Entrega, actualización y próximos requisitos

Ramas independientes: feat/v2-security-analysis-phase2a y
feat/v2-security-analysis-web-phase2a. Los hashes finales y su comprobación
remota se entregan al confirmar las validaciones. No hay rama SQL, PR, merge ni
despliegue personal. Locks y secretos permanecen sin cambios.

- [Actualización y reversión local concretas](V2_PHASE1_LOCAL_UPGRADE.md).
- [Lista independiente previa a cualquier fase ZAP](V2_ZAP_READINESS_CHECKLIST.md).
- [Laboratorio reproducible y límites](../laboratory/phase2a/README.md).
- [Antecedente de autorización Fase 1](V2_TARGET_AUTHORIZATION.md).
- [Amenazas SSRF Fase 1](V2_SSRF_THREAT_MODEL.md).

Referencias primarias: [SSRF OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html),
[Python SSL](https://docs.python.org/3.12/library/ssl.html),
[Python socket](https://docs.python.org/3.12/library/socket.html),
[Docker bridge](https://docs.docker.com/engine/network/drivers/bridge/),
[Docker recursos](https://docs.docker.com/engine/containers/resource_constraints/),
[ZAP Baseline](https://www.zaproxy.org/docs/docker/baseline-scan/).

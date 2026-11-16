# Fase 2C — resultados observados

**IMPLEMENTADO CON LIMITACIONES. Egreso público BLOQUEADO.** Resultado del nuevo
runner: **51 comprobaciones aprobadas**, ejecutadas en esta misión. No son las
45 comprobaciones de Fase 2B ni ensayos de salida a Internet.

## Evidencia y alcance

Comando: `.venv/bin/python -m scripts.test_v2_egress_lab` con DATABASE_V2_PATH
apuntando al checkout Database a562e638dfe5b7e8d07eec0e8046e6998f8a2802.
El runner elimina el JSON de éxito anterior antes de comenzar y solo escribe
`api-tests/v2/.artifacts/phase2c/egress-lab-results.json` tras terminar las pruebas
y limpiar sus contenedores/redes. La evidencia completa es privada e ignorada
por Git. La imagen probada fue
`sha256:cd012237146bc80f95adbf60e0fb7ff6f561c09c98cf34ffe3ef46b3cfba935f`.
El JSON registra SHA-256 de los diez archivos enviados a su construcción.

| Medición del recorrido aprobado | Valor observado |
|---|---|
| Revocación SQL hasta cierre TLS activo visto por fixture | 0.591 s |
| Pérdida del broker hasta denegación de operación activa | 1.181 s |
| Máximo de lectura/publicación de snapshot del broker | 0.562 s |
| Publicaciones correctas del broker | 146 |
| Observaciones de scope invalidado | 64 |
| Errores de lectura/publicación contabilizados durante el recorrido con fallos inyectados | 4 |
| Descartes OUTPUT worker, IPv4 / IPv6 | 13 / 14 paquetes |
| Descartes OUTPUT gateway tras reinicio, IPv4 / IPv6 | 2 / 16 paquetes |

Estas latencias son observaciones de una ejecución, no un SLA ni un límite de
tiempo real garantizado. El lease de lectura es 1.5 s, el sondeo del gateway
0.1 s y el timeout de control 0.35 s. Revocar cancela sockets activos del gateway;
no retira bytes ya enviados ni modifica dinámicamente conntrack en el kernel.
Los errores de componentes provocados durante las pruebas de caída no equivalen
a pruebas fallidas; la condición comprobada es la denegación y el vencimiento.

Se confirmaron dos accesos de control a canarios IPv4/IPv6 antes de las negativas.
Después, **cero accesos TCP/UDP adversariales** adicionales a esos canarios. No se
confunde un servicio inexistente con una denegación. Se verifican ambas familias,
localhost con listeners propios y contadores reales del kernel, además de las
decisiones del gateway. Los servicios internos son representaciones del
laboratorio, no sondeos de Windows, WSL2, PostgreSQL o Backend personales.

Los contenedores propios se eliminaron por etiqueta/nonce y las tres redes se
eliminaron únicamente tras comprobar que no contenían endpoints ajenos. No se
borraron volúmenes personales. Las imágenes y cachés permanecen disponibles.

## Garantías y límites

- Demostrado: ruta obligatoria por gateway para el worker evaluado, permiso
  acotado, filtros independientes de Python, IPv4/IPv6, DNS/TLS fijado, denegación
  de bypass, revocación activa, caducidad, concurrencia y recuperación sin replay.
- No demostrado: egreso público selectivo, reglas globales del host/VM,
  aislamiento multitenant desplegado, resistencia a administrador/kernel/gateway
  comprometidos, control operativo autenticado o verificador real.
- Diseñado: alternativa Linux nativo/VM dedicada con perímetro de salida y reglas
  por job. No se instaló ni certificó esa plataforma.
- Bloqueado: verificación remota de dominios, cualquier escaneo y ZAP. El endpoint
  operativo verify conservó 503, cero consultas DNS y cero intentos duraderos.

El filtro del gateway impone un techo fijo de IP/puerto del fixture; el componente
confiable aplica el alcance por operación. No se atribuye al kernel una semántica
de workspace o una revocación SQL que no tiene. Véanse
[arquitectura y amenazas](V2_PHASE2C_EGRESS_SECURITY.md) y
[checklist de pendientes](V2_ZAP_READINESS_CHECKLIST.md).

## Comprobaciones del nuevo runner

Los identificadores siguientes corresponden a las etiquetas exactas del JSON
aprobado y permiten contrastarlas con el runner; cada etiqueta se agrega solo
después de su aserción real.

- R01: three owned dual-stack internal bridges, no published ports or host mounts.

- R02: worker kernel OUTPUT DROP forces the gateway on IPv4 and IPv6.

- R03: gateway kernel INPUT/OUTPUT/FORWARD DROP and forwarding disabled.

- R04: untrusted worker cannot change firewall, open raw sockets or read control credentials.

- R05: live worker root filesystem, cgroup limits and private-key permissions audited.

- R06: private IPv4/IPv6 canaries independently confirmed listening.

- R07: real API verify stays 503 with zero DNS and zero durable attempts.

- R08: allowed operation reaches real IPv4 TLS only through gateway and controlled DNS.

- R09: consumed operation cannot be replayed on another connection.

- R10: allowed operation reaches real IPv6 TLS through IPv6 gateway ingress.

- R11: original Host and SNI verified by the separate TLS fixture.

- R12: raw worker TCP denied: allowed TLS IP directly without gateway.

- R13: raw worker TCP denied: unauthorized IPv4 and IPv6.

- R14: raw worker TCP denied: non-HTTPS ports.

- R15: raw worker TCP denied: simulated Windows and WSL hosts.

- R16: raw worker TCP denied: simulated PostgreSQL and Backend.

- R17: raw worker TCP denied: simulated Docker API and alternate proxy.

- R18: raw worker TCP denied: unapproved DNS TCP.

- R19: raw worker TCP denied: metadata representation.

- R20: listening localhost IPv4/IPv6 services unreachable even in worker namespace.

- R21: worker UDP DNS cannot bypass the mandatory gateway.

- R22: raw gateway TCP independently denied: private services.

- R23: raw gateway TCP independently denied: unapproved TLS IP.

- R24: raw gateway TCP independently denied: unapproved TLS port.

- R25: gateway UDP denied despite allowing operator DNS TCP.

- R26: worker cannot supply host, IP, port, workspace or arbitrary egress rules.

- R27: unknown operation fails closed without upstream connection.

- R28: forged control authentication rejected over the actual TCP control channel.

- R29: real HTTPS redirect denied without contacting metadata canary.

- R30: DNS set differing from the authorized permit denied before TLS.

- R31: DNS rebinding between fresh resolutions denied.

- R32: DNS failure has no system resolver fallback or permissive retry.

- R33: real SQL challenge revocation prevents new connections.

- R34: changed declaration invalidates the bound target version.

- R35: expired policy prevents new connections.

- R36: SQL revocation closes an already active gateway TLS socket within measured bound.

- R37: revoked active operation cannot reuse its previous policy.

- R38: expiry during operation cancels TLS and releases no buffered result.

- R39: concurrent consumption of the same operation is denied.

- R40: distinct scoped operations proceed concurrently without sharing a tunnel.

- R41: existing worker connection cannot be reused for another request.

- R42: loss of authorization broker heartbeat closes active TLS and denies new work.

- R43: control service outage fails closed for active and new operations.

- R44: authority restart cannot resurrect an old unconsumed policy.

- R45: recovery requires a freshly issued policy bound to the new authority epoch.

- R46: gateway restart closes old connections and rejects old epoch policies.

- R47: gateway recovery applies kernel filters before serving new operations.

- R48: IPv4/IPv6 denials repeated after gateway restart with fresh kernel counters.

- R49: all forbidden canaries received zero adversarial TCP or UDP traffic.

- R50: IPv4 and IPv6 kernel counters prove drops independently of Python and routing.

- R51: live kernel rules and counters retained as private reproducible evidence.

## Reproducción de regresiones

La suite heredada de seguridad del launcher requiere Database como checkout
hermano del Backend, incluso cuando DATABASE_V2_PATH está definido. Para esta
misión se creó un worktree detached en
`/home/mz/VulnTrack-security-phase2c/vuln-track-database`, commit exacto a562e63,
sin rama nueva ni modificaciones. La primera pasada detectó cuatro errores por
la ausencia de esa ruta; se corrigió la preparación y se repitieron los recorridos
completos. No se omitieron ni relajaron esas comprobaciones.

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
export DATABASE_V2_PATH=/home/mz/VulnTrack-security-phase2c/vuln-track-database
cd /home/mz/VulnTrack-security-phase2c/vuln-track-backend
.venv/bin/python -m scripts.test_v2_registration --full
.venv/bin/python -m scripts.test_v2_registration --installation new --full
.venv/bin/python -m scripts.test_v2_security_lab --phase2b
.venv/bin/python -m scripts.test_v2_verification_persistence
.venv/bin/python api-tests/v2/validate.py
.venv/bin/python api-tests/v2/run.py
.venv/bin/python api-tests/v2/run.py --installation new
.venv/bin/python api-tests/v2/run.py --persistent-contract
.venv/bin/ruff check .
.venv/bin/python -m pip check
export VULNTRACK_BACKEND_PATH=/home/mz/VulnTrack-security-phase2c/vuln-track-backend
export PLAYWRIGHT_CHROMIUM_EXECUTABLE=/home/mz/.cache/ms-playwright/chromium-1254/chrome-linux64/chrome
cd /home/mz/VulnTrack-security-phase2b/vuln-track-frontend
npm run check
/home/mz/VulnTrack-security-phase2c/vuln-track-backend/.venv/bin/python scripts/v2_registration_stack.py --e2e --api-port 0 --web-port 0
/home/mz/VulnTrack-security-phase2c/vuln-track-backend/.venv/bin/python scripts/v2_registration_stack.py --e2e --installation new --api-port 0 --web-port 0
```

SQL003 adversarial se ejecuta adicionalmente con `DisposableV2('new',
sql_checks=False)` y `stack.apply('tests/003_v2_adversarial.sql')`, únicamente en
su PostgreSQL tmpfs propio. Los puertos de las suites se asignan sin tocar los
puertos habituales 8000/5173. Los perfiles persistentes de ensayo son nuevos y
sus volúmenes se conservan detenidos para inspección; no se usan datos personales.

## Matriz final de regresiones ejecutadas en esta misión

| Recorrido | Resultado final |
|---|---|
| Backend sobre V2 existente compatible | 734 passed, 0 failed, 0 skipped; 212.85 s |
| Backend sobre instalación nueva | 734 passed, 0 failed, 0 skipped; 209.31 s |
| SQL por recorrido | 120 comprobaciones, incluidas las 24 de SQL008 |
| SQL003 adversarial separado | 27 comprobaciones; la llamada de preparación de firma no cuenta como aserción |
| React | 96 pruebas, ocho archivos, sin fallos |
| Navegador, existente / nueva | 6 / 6 passed; 21.0 / 18.9 s; Axe y responsive 1440/390 px |
| Laboratorio anterior Fase 2B repetido | 45 comprobaciones aprobadas |
| Laboratorio nuevo Fase 2C | 51 comprobaciones aprobadas |
| Postman, existente | 288 aserciones, 75 envíos HTTP, cero fallos |
| Postman, nueva | 303 aserciones, 78 envíos HTTP, cero fallos |
| Postman, contrato persistente desechable | 200 aserciones, 53 envíos HTTP, cero fallos |
| Reinicio, backup/restore separado y lectura con código estable/Fase 2A | Siete comprobaciones aprobadas |
| Ruff, pip check, TypeScript, ESLint y compilación | Sin fallos |

Los 734 casos Backend incluyen **57 unitarios nuevos de política/protocolo** y
los **677 casos previos repetidos**. No se suman ambos recorridos como escenarios
únicos. React y navegador no agregaron casos nuevos en esta fase. Las 51
comprobaciones de la nueva topología y las 45 del runner anterior se identifican
por separado; prueban entornos y tienen coberturas que se solapan.

Postman repitió la colección sin cambiarla; los envíos/aserciones varían por
polling. El validador confirmó 44 operaciones, 71 solicitudes definidas, 23
cuerpos Pydantic y 49 ejemplos positivos. El contrato y SHA-256 OpenAPI siguen
siendo `082d1c6a0b84564b8814ede1724b5d72e54249d5fd9893d65149b0af00133b16`.
Las respuestas V2 previamente permisivas conservan esa limitación de contrato.

Los nuevos volúmenes persistentes ensayados, retenidos y detenidos, son
`vulntrack_v2_verification_test_459e72960c_pgdata` y
`vulntrack_v2_verification_test_restore_459e72960c_pgdata`. No son el volumen
personal. Se verificó conservación de IDs/fechas/evidencia, FORCE RLS y JWT.

Persisten advertencias heredadas de TestClient/Newman, sin actualizar pins para
ocultarlas. No se ejecutaron pruebas de egreso público, firewall global Windows,
Linux nativo/VM alternativa, verificación de dominios públicos ni ZAP. Son
capacidades no demostradas o expresamente excluidas, no casos omitidos de pytest.

# Fase 2B — persistencia e integración sin verificación remota operativa

**IMPLEMENTADO CON LIMITACIONES. ZAP BLOQUEADO.** La misión del 15-11-2026
autoriza ramas y pruebas aisladas, no despliegue personal, escaneos ni aprobación
global de arquitectura. Jesel/Rudi conservan las decisiones pendientes.

## Alcance real

Bases remotas verificadas: Backend 7198de7c986f6b86a0f2ac1a94d1d88b893b3a84,
Frontend 1a0263a859ecdbf844887d27ae17c7c6fa903ed7 y Database
b377b5bd8013cc2151f6a1681d168e1df0f5fe42. Se inspeccionaron cuatro repositorios,
worktrees, contenedores, volúmenes, redes, puertos, JWT, membresías, RLS,
autorizaciones, transporte, desafíos, auditoría, worker, OpenAPI y Postman.

La instalación personal /home/mz/VulnTrack sigue en fcabbe9/4514b68. Su volumen
vulntrack_v2_development_pgdata, claves, cuentas y procesos no se modificaron.
PostgreSQL mantiene publicación 127.0.0.1:55434. El trabajo nuevo está en
/home/mz/VulnTrack-security-phase2b, con PostgreSQL tmpfs o perfiles persistentes
NUEVOS. No se ejecutaron migraciones sobre la base personal.

## Persistencia y límites de confianza

SQL008 añade exclusivamente el esquema vulntrack_verification, dos tablas,
roles no-login y funciones acotadas. No altera estructura, datos ni políticas
V1/V2 existentes; añade grants mínimos al nuevo propietario técnico. No cambia
public.alembic_version=0004_mvp_cve. Backend administra
ORM y una línea Alembic explícita con public.alembic_verification_version;
Database administra bootstrap SQL, conforme D-002. No hay mezcla de líneas MVP-B.

challenges conserva IDs compuestos de workspace/aplicación/destino, actor,
Idempotency-Key, origen HTTPS exacto, digest de la URL completa, versión y vigencia
de declaración, SHA-256 del cuerpo esperado, estado, contador, versiones y fechas.
No duplica query strings, tokens en claro, cuerpos HTTP o credenciales de sitios.
attempts conserva procedencia, lease, resultado, fechas y digests/IP/certificado
de laboratorio. Esos últimos datos no se exponen por el rol API.

Un token contiene 256 bits aleatorios, propósito y UUID propios. Solo se devuelve
al emisor autorizado en la primera respuesta no-store. La repetición idempotente
devuelve el mismo recurso con instructions=null; si se perdió el token se revoca
y se crea otro desafío. Se comparte la generación con el laboratorio anterior,
sin reemplazar el transporte HTTPS ni duplicar su política.

Estados persistentes: pending, failed, expired, revoked y verified reservado.
Ninguna función actual produce verified; el trigger rechaza esa transición.
La procedencia de attempts está restringida a laboratory. Incluso una coincidencia
correcta termina como failed/LABORATORY_MATCH_ONLY, con verified_at=null y
control_verified=false. No puede convertirse un fixture en prueba real mediante
un parámetro, JSON, variable de entorno o una declaración approved.

TTL diez minutos, un intento por desafío, lease quince segundos, un pending por
destino y veinte emisiones por workspace/24 h son límites conservadores de esta
implementación, **PROPUESTA pendiente de ratificación de equipo**. Se serializan
destino, desafío, intento y cuota en PostgreSQL. Revocación repetida es idempotente;
versiones incompatibles fallan. La lectura deriva effective_state sin inventar
fechas ni reescribir historia: expiración o cambio de URL/declaración/aplicación
invalida el recurso. Consumo y resultado vuelven a comprobar scope y membresía.

## RLS y privilegios

Las dos tablas tienen ENABLE y FORCE ROW LEVEL SECURITY, seis políticas acotadas
al contexto HMAC transaccional existente. Lectura owner/editor/viewer; escritura
owner/editor. FK compuestas y triggers impiden trasladar recursos o reescribir
identidad/evidencia terminal. No hay DELETE/TRUNCATE ni DML directo para API/lab.

vulntrack_app solo recibe SELECT de metadatos y EXECUTE de issue/revoke. No puede
leer proof_sha256/received_sha256 ni ejecutar claim_laboratory/finish_laboratory.
vulntrack_registration no obtiene USAGE ni permisos sobre el esquema nuevo.
vulntrack_verification_lab es NOLOGIN/NOBYPASSRLS y no se concede al login API.
Solo un operador del laboratorio usa ese rol, sujeto al mismo contexto firmado.

Las cinco funciones SECURITY DEFINER son de vulntrack_verification_owner:
NOLOGIN, NOSUPERUSER, NOBYPASSRLS, sin miembros, search_path=pg_catalog y nombres
de objetos totalmente calificados. Su permiso UPDATE(name/label) en aplicaciones/
destinos existe únicamente para SELECT FOR SHARE/UPDATE; las funciones no escriben
esas columnas. Tiene REFERENCES para FK y permisos mínimos de auditoría. FORCE RLS
también obliga al propietario. Funciones internas y PUBLIC no tienen EXECUTE.
El operador de mantenimiento/host sigue siendo una autoridad de confianza.

Cambios y auditoría ocurren en la misma transacción. Eventos contienen actor,
objeto, acción y fecha, sin cuerpo/token/URL. Fallar auditoría revierte emisión.
Se prueban firmas, roles, IDs ajenos, consumo concurrente, rollback y conexiones
reutilizadas. El contexto HMAC existente no adquiere semántica de nonce de uso
único: el consumo único del desafío lo garantiza su propia transacción SQL.

## API y frontend

[Contrato HTTP completo](V2_VERIFICATION_API.md): cinco operaciones nuevas,
39 operaciones previas preservadas. No hay fetch al registrar URL o emitir un
desafío. POST verify exige JWT/roles/recurso/versión y devuelve 503 sin crear un
intento, resolver DNS, encolar trabajo o contactar el destino. No existe flag
que elimine ese límite. El worker NVD existente sigue separado.

React consulta esos datos reales y permite emitir/revocar cuando corresponde.
Valida esquema e IDs del workspace/aplicación/destino, mantiene instrucciones
solo en memoria del componente y las elimina al revocar/cambiar de destino.
No conserva tokens en localStorage ni en consultas de metadatos. Una evidencia
de laboratorio se identifica explícitamente y nunca aparece como control real.
El botón Baseline permanece disabled independientemente del estado recibido.

## DNS, HTTPS y egreso

ControlledDNS usa dnspython 2.9.2 para parsing de wire, con endpoint numérico
TCP/53 seleccionado por operador, no por usuario o DNS del entorno. Límites:
dos segundos por resolución, 4096 bytes antes de leer el cuerpo, dieciséis IP,
32 RRsets, cuatro CNAME y diez consultas. Sin caché, reintentos, UDP fallback,
recursión externa o configuración automática. Normaliza IDNA con la política
existente, revisa A/AAAA y direcciones adicionales; una IP prohibida rechaza
todo el conjunto. Rechaza loops, alias ambiguos, alcance ajeno y cambios entre
familias. No afirma DNSSEC ni autenticación de un resolver público desplegado.

DNSPinnedHTTPS compara dos resoluciones frescas, incluyendo CNAME e IP, y entrega
solo IP numérica al transporte de Fase 2A. Este conserva Host/SNI y verificación
de certificado, TLS mínimo 1.2, sin proxies de entorno, credenciales, redirects
o retries. Mantiene 8192 bytes de cabeceras, 4096 de cuerpo y cinco segundos I/O;
el conjunto DNS/HTTPS tiene deadline diez segundos y cancelación con cierre.
Las nuevas llamadas DNS ya no son callbacks síncronos bloqueantes dentro del
componente integrado. El transporte anterior sigue disponible sin reescritura.

**BLOQUEADO en servicio:** no hay instancia operativa de ese adaptador. Su DNS
y conexiones reales solo se probaron en un namespace network-none propio, con
alias locales y sin rutas externas. El helper NET_ADMIN efímero instala OUTPUT
DROP IPv4/IPv6 dentro de ese namespace, permitiendo solo DNS TCP a fixtures
concretos y HTTPS a IP autorizadas. No modifica firewall Windows, Ubuntu host
o Docker Desktop. El worker conserva UID 65532, capacidades cero, raíz read-only,
no-new-privileges, sin docker.sock, mounts del usuario ni credenciales de DB/API.

El broker de prueba, fuera del worker, mantiene PostgreSQL tmpfs propio y usa
roles restringidos para consumir el resultado. Se comprueban DNS/TLS reales,
CNAME, rebinding, certificados, límites, cancelación, FD, canarios TCP/UDP sin
tráfico, cgroups y OOM controlado. Saltarse Python tampoco permite llegar al
alias DNS cambiado. Los números con apariencia pública son loopback del
laboratorio, no destinos de terceros. Egreso público selectivo sigue PENDIENTE.

## Reproducción y límites pendientes

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack-security-phase2b/vuln-track-backend
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
cd ../vuln-track-frontend
npm run check
export VULNTRACK_BACKEND_PATH=/home/mz/VulnTrack-security-phase2b/vuln-track-backend
export PLAYWRIGHT_CHROMIUM_EXECUTABLE=/home/mz/.cache/ms-playwright/chromium-1254/chrome-linux64/chrome
../vuln-track-backend/.venv/bin/python scripts/v2_registration_stack.py --e2e --api-port 0 --web-port 0
../vuln-track-backend/.venv/bin/python scripts/v2_registration_stack.py --e2e --installation new --api-port 0 --web-port 0
```

Instalar requirements-dev.lock y api-tests/v2/requirements-api.lock en la venv,
editable --no-deps y npm ci en Frontend y api-tests/v2. Solo se añadió el pin
dnspython 2.9.2; los demás pins no se actualizaron. Evidencias privadas ignoradas
en api-tests/v2/.artifacts/phase2b y .local; conteos finales en el reporte de entrega.

Pendiente: DNS/egreso operativos autenticados y controlados, verificador real,
proveniencia operativa, políticas de vigencia/retención, scheduler, cuotas de
ejecución, recuperación tras caída y cancelación/revocación de jobs reales.
Un intento de laboratorio abandonado requiere revocación o expiración; no existe
un reconciliador duradero de trabajos. Las pruebas WSL2 no certifican producción.

- [Plan de actualización y reversión](V2_PHASE2B_LOCAL_UPGRADE.md).
- [Checklist de controles y decisiones](V2_ZAP_READINESS_CHECKLIST.md).
- [PostgreSQL primario: RLS](https://www.postgresql.org/docs/16/ddl-rowsecurity.html),
  [SECURITY DEFINER](https://www.postgresql.org/docs/16/sql-createfunction.html),
  [dnspython wire](https://dnspython.readthedocs.io/en/stable/message-make.html).

Ni las pruebas ni la publicación autorizan ZAP: hace falta una decisión explícita
posterior del equipo y del alcance real de cada operación.

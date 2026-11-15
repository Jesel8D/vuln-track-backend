# VulnTrack V2: desarrollo persistente local

Esta instalación es exclusivamente de desarrollo. Usa un PostgreSQL 16.15 propio con volumen dedicado; la API y Vite se ejecutan en el host. No conecta ni migra bases personales/productivas. El modo temporal sigue separado y es el destino de pytest, Newman, Playwright y pruebas SQL.

## Requisitos y checkouts coordinados

- Docker con Compose y acceso del usuario al daemon; Python 3.12; Node compatible con el frontend (aquí 24.22.1) y npm.
- Backend: rama `feat/v2-stabilization`, basada en `test/v2-api-collection` `63315644121bb0074cd18f5d2da11720358caea0`.
- Database: rama `feat/v2-persistent-development-database`, basada en `0cc4dfd719463fb15eb1689a0f46550d9f204a71`, con SQL007.
- Frontend: rama existente `feat/v2-registration-web`, commit `4514b6840b428152c1cd875c95e3e55ad81c4196`; no necesita cambios de código.

En esta PC:

```bash
cd /home/mz/Desktop/vulntrack-stabilization-v2/vuln-track-backend
export DATABASE_V2_PATH=/home/mz/Desktop/vulntrack-stabilization-v2/vuln-track-database
export VULNTRACK_FRONTEND_PATH=/home/mz/Desktop/vulntrack-registration-v2/vuln-track-frontend
export PATH="/home/mz/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin:$PATH"
```

En otro checkout, ajustar las rutas a esos tres repositorios reales. El helper verifica SHA-256 de SQL001/002/004/005/006/007 y rechaza fuentes divergentes. No sustituir Database por la línea MVP-B.

Si faltan dependencias, desde Backend:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.lock
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/python -m pip install -r api-tests/v2/requirements-api.lock
npm ci --prefix api-tests/v2 --ignore-scripts --no-fund
```

Desde el directorio Frontend: `npm ci` con el Node compatible seleccionado. No se instala ninguna herramienta global.

## Inicializar e iniciar

```bash
.venv/bin/python -m scripts.v2_development init
.venv/bin/python -m scripts.v2_development up
```

`up` también inicializa si es una instalación nueva. Mantener su terminal abierta. No interrumpir la primera inicialización SQL; si falla, el helper conserva los datos y bloquea un reset automático.

- Frontend: **http://127.0.0.1:5173/crear-cuenta**.
- API/Swagger: **http://127.0.0.1:8000/docs**.
- OpenAPI: http://127.0.0.1:8000/openapi.json; ReDoc: http://127.0.0.1:8000/redoc.
- Puerto PostgreSQL local: **55434**, solo loopback.
- Volumen: **`vulntrack_v2_development_pgdata`**.
- Contenedor: `vulntrack-v2-development-postgres`; proyecto Compose: `vulntrack-v2-development`.

La creación de volumen comprueba primero que volumen/contenedor/red homónimos no sean de otro proyecto. Las etiquetas identifican la instalación exacta. Un volumen inicializado ausente no se recrea silenciosamente: el helper falla para evitar que una instalación vacía parezca una pérdida de datos normal.

El modo NVD predeterminado es **fixture**, indicado en la terminal: captura CPE y CVE AND original, no datos actuales. Permite probar sin Internet ni consultar dispositivos. Para NVD real sobre recursos propios de desarrollo:

```bash
.venv/bin/python -m scripts.v2_development up --nvd-mode live
```

En live, seleccionar y confirmar manualmente el CPE correcto; respetar cuotas. No se ejecutó NVD live en esta estabilización. No hay ZAP habilitado ni escaneos externos. Cambiar de modo no modifica ni borra análisis históricos; los resultados de fixtures no deben presentarse como análisis actuales de sistemas reales.

## Cuentas y uso

Crear una cuenta desde el frontend, iniciar sesión y utilizar el workspace personal. Usuarios, membresías, aplicaciones, tecnologías, CPE confirmado, consultas, historial, revisiones y recomendaciones permanecen en PostgreSQL. No hay credenciales de demo compartidas. Owner de workspace no es administrador global.

Usar siempre 127.0.0.1 en las URLs indicadas: localhost es otro origen para CORS. La API recibe su login SQL restringido y las claves locales; Vite recibe solo la URL pública de la API. No poner contraseñas SQL/HMAC/JWT en VITE_*.

Swagger: registrar usuario con contraseña privada, hacer login y pegar solo access_token en Authorize/HTTPBearer. Los ejemplos versionados llevan secretos vacíos.

## Parada y reinicio sin pérdida

En la terminal de `up`, **Ctrl+C** detiene API, Vite y PostgreSQL; el volumen permanece. Desde otra terminal:

```bash
.venv/bin/python -m scripts.v2_development stop
.venv/bin/python -m scripts.v2_development status
.venv/bin/python -m scripts.v2_development up
```

El helper no tiene comando de borrado, no usa `down -v`, DROP DATABASE ni TRUNCATE. Compose declara el volumen como externo y su ciclo de vida queda fuera de `down`, conforme a la [documentación Docker](https://docs.docker.com/reference/cli/docker/compose/down/). No ejecutar prune ni borrar ese volumen manualmente. El secreto JWT es estable al reiniciar, igual que el HMAC almacenado en la base.

Si los puertos están ocupados, elegir otros al crear un perfil nuevo (`--profile laboratorio --pg-port 55435 --api-port 8001 --web-port 5174`), y utilizar sus URLs. Las opciones de puerto se guardan al crear el perfil; no cambian la configuración de un perfil existente. No editar secretos o nombres para adoptar volúmenes ajenos.

## Configuración y bootstrap reales

`dev/v2/.env.example` contiene solo referencias sin secretos. El helper genera `.local/development/.env` con nombres/puerto/ruta del archivo secreto, `postgres.password` y `config.json` privados. El directorio tiene modo 0700 y los archivos de secretos 0600. Están excluidos de Git y Docker. No publicar esos archivos ni perderlos: contienen credenciales de acceso y claves operativas.

Secuencia nueva comprobada, sin stamp a ciegas:

1. PostgreSQL vacío en el volumen dedicado; marcador de instalación y etiquetas propias.
2. Database SQL001 y SQL002, sin cargar demo/seed.
3. Alembic verificado: 0001 → 0002 → 0003 → `0004_mvp_cve` para las rutas heredadas que conserva la API V2.
4. SQL004, SQL005, SQL006 y SQL007, en ese orden.
5. Login `vulntrack_v2_api` sin SUPERUSER/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS; pertenencia explícita a `vulntrack_app` y al grupo separado `vulntrack_registration` NOLOGIN, más SELECT(password_hash) para login.
6. Verificación exacta del catálogo y sus 29 políticas RLS. La API no es propietaria de tablas ni puede leer la clave HMAC por SQL.

Al reiniciar, la fase ready solo verifica: no reaplica baseline, seeds ni migraciones. El modo Alembic acepta únicamente los dos catálogos V2 publicados exactos (antes/después de SQL007), sin ignorar drift arbitrario. SQL007 conserva filas y valores históricos, sin reescribir evidencia; amplía el CHECK para admitir undetermined. No es una nueva revisión Alembic sobre los modelos heredados.

Una base V2 existente fuera de esta instalación requiere inventario, backup y restore de ensayo antes de SQL007; no se adopta con este helper. Si la primera instalación queda incompleta, conservar el volumen y los logs privados para inspección o crear otro perfil con nombres/puertos diferentes; no resolverlo borrando datos o haciendo stamp.

## Copia de seguridad

```bash
.venv/bin/python -m scripts.v2_development backup
```

Se inicia PostgreSQL propio si estaba parado, se verifica su esquema y se crea un `pg_dump -Fc` consistente en `.local/development/backups/FECHA-ID/database.dump`, con manifiesto SHA-256 y versiones de fuentes. No se borra ni detiene trabajo del usuario para obtenerlo. El comando imprime la ruta, no contraseñas.

El dump contiene hashes de usuarios y la clave privada de contexto, por lo que es sensible. Mantenerlo privado, cifrarlo para transportarlo y copiarlo a un soporte distinto del disco del volumen. Los backups locales por sí solos no protegen frente a pérdida del disco. Guardar también la configuración privada si se desea recuperar la instalación original; no subirla a Git ni enviarla en reportes.

## Restauración sin sobrescribir

Restaurar **solo copias propias y confiables**, siempre en un perfil y volumen nuevos. No sustituir el desarrollo original:

```bash
.venv/bin/python -m scripts.v2_development restore --profile restore-manual --pg-port 55436 --api-port 8002 --web-port 5175 --archive /RUTA/PRIVADA/database.dump
.venv/bin/python -m scripts.v2_development up --profile restore-manual
```

El manifiesto debe acompañar al dump. Se comprueba checksum y versiones; se crean los roles conocidos y se restaura la base vacía sin `--clean`, verificando catálogo, privilegios y RLS. El helper rechaza cualquier perfil/volumen de destino existente. Se conservan cuentas, contraseñas de usuarios (hashes), datos y HMAC de contexto; se generan credenciales SQL y secreto JWT nuevos, por lo que los usuarios inician sesión otra vez. Probar login, datos e aislamiento antes de considerar útil la copia. El origen queda intacto.

## Postman persistente y modo temporal

Para la API persistente importar la colección y `api-tests/v2/persistent-development.postman_environment.json`. Mantener `disposable_confirmed=false`, introducir password solo localmente y establecer `persistent_development_confirmed=true` tras comprobar la instalación local. El modo persistent-development omite toda la carpeta negativa 10; los positivos crean una cuenta UUID nueva y sus datos sin limpiar tablas. Para inspeccionar una cuenta existente, ejecutar login y solicitudes individuales con sus IDs; no volver a lanzar el alta automática ni asumir que solo tiene un workspace.

La suite completa de negativos continúa en PostgreSQL temporal:

```bash
.venv/bin/python -m scripts.test_v2_registration --installation existing --full
.venv/bin/python api-tests/v2/run.py
.venv/bin/python api-tests/v2/run.py --installation new
```

El launcher frontend `scripts/v2_registration_stack.py` sigue creando tmpfs y descarta sus datos al salir; no sirve para persistencia. Pytest/Playwright conservan su guardia contra bases existentes. No ejecutar los tests SQL de fixtures sobre el volumen de desarrollo.

Para repetir la prueba de persistencia/restore:

```bash
.venv/bin/python -m scripts.test_v2_persistence
```

Cada ejecución crea **perfiles y volúmenes de validación nuevos**, sin usar development. Conserva esos volúmenes y su backup para revisión, y detiene sus contenedores; los nombres quedan en el reporte privado. No elimina información de ejecuciones anteriores. La prueba usa NVD capturado original, sin escaneo.

## Solución de problemas y límites

- Recurso de otro proyecto: no cambiar etiquetas para forzar acceso; elegir otro perfil o inspeccionar con su propietario.
- Volumen missing/fase incompleta/checksum distinto: parar y revisar fuentes/configuración/backup; no resetear ni reaplicar SQL001.
- API/Vite no arranca: revisar `.local/PERFIL/api.log` y `web.log`, sin publicar secretos; verificar puertos, npm ci y Node compatible.
- Firma/contexto inválido: no inventar una HMAC; recuperar la configuración de esa instalación o restaurar el backup en un perfil nuevo.
- 429 de registro/login: respetar Retry-After. El entorno persistente mantiene las cuotas normales, no las ampliadas de E2E.
- Después de fallo abrupto de terminal, usar `stop` antes de otro `up`; los PID se verifican por tiempo de inicio para no terminar procesos reutilizados.

Persistencia local no equivale a producción: siguen pendientes operación de backups externos/cifrado/rotación, abuso distribuido, recuperación de contraseña, revocación individual y HTTPS/CSP. Newman conserva avisos transitivos, separados de la API. La ratificación global del modelo V2 continúa pendiente.

# Guía de despliegue de VulnTrack — candidato de producción

Preparada el 24 de noviembre de 2026. El responsable del despliegue ejecutará los pasos de servidor. Esta misión no accedió a AWS. **NO-GO de apertura pública hasta validar EC2; CVE live y ZAP no autorizados.** Los ejemplos de dominio y correo se sustituyen por los propios; no son credenciales.

## 1. Proyecto y alcance

VulnTrack administra inventarios por workspace con roles owner/editor/viewer, aplicaciones, dispositivos, tecnologías, identificación CPE e historial. PostgreSQL aplica RLS y contexto firmado. El catálogo CPE público está separado de cuentas e inventario. Una coincidencia CPE identifica un producto; no confirma una vulnerabilidad. En esta instalación las nuevas consultas CVE están deshabilitadas. El historial y sus etiquetas de procedencia permanecen disponibles. No se transfieren cuentas ni inventarios personales.

## 2. Versión y commits exactos

Candidato `v1.0.0-rc1` de entrega de RC4.1-local, sin release estable ni inicio de fase 6. La rama común identifica una combinación reproducible pendiente de aceptación en el servidor. Commits de implementación validados:

| Repositorio | Commit de implementación |
|---|---|
| Backend | `417d190146a9c7babce81f76794e652f71ab0af2` |
| Frontend | `c18709296efc46e47bf3f9afc34dfa40f570213e` |
| Database | `b8fbcdbf3edee9ef733818517b19fe0b37ba35d4` |

La punta publicada puede incluir esta guía en un commit documental posterior; `MANIFIESTO_RELEASE.md` de la entrega registra las puntas remotas verificadas. Los comandos siguientes fijan los commits de implementación para que el contenido documental no cambie los binarios. No desplegar una rama flotante sin comprobar su SHA. Origen anterior: Backend `826ef02c09f2f316f793ec8e71db8348175f91c6`, Frontend `0bf1f78837f718a7ac4a813db238892047766fc2`. Context local `f41abfcc2c28a5d5fb1ae4ba0576a49c6b835445` no se redistribuye por falta de permiso comprobado y no es dependencia de instalación.

## 3. Repositorios y rama

- [Backend](https://github.com/Jesel8D/vuln-track-backend/tree/release/v1.0.0-rc1).
- [Frontend](https://github.com/Jesel8D/vuln-track-frontend/tree/release/v1.0.0-rc1).
- [Database](https://github.com/Jesel8D/vuln-track-database/tree/release/v1.0.0-rc1), sin cambios artificiales respecto al commit ya remoto.

Se publican ramas nuevas sin force, eliminación de referencias ni merge a las ramas principales. No es necesario clonar Context. El paquete de entrega contiene esta guía, ejemplos públicos, referencias/checksums y límites; el respaldo CPE se transfiere por separado.

## 4. Arquitectura

```text
Navegador → HTTPS Caddy → archivos React compilados
                     └→ socket Unix privado → FastAPI (1 worker)
                                              ├→ red interna → PostgreSQL privado + TLS
                                              └→ red interna → PostgreSQL CPE + TLS / lector
```

Compose único: `vuln-track-backend/deploy/production/compose.yaml`. Caddy solo pertenece a la red de borde, sin redes SQL. FastAPI no escucha TCP; usa `/run/backend/api.sock`, volumen 0700 compartido solo con Caddy, mismo UID 10001. La confianza de proxy `*` se limita a este socket protegido. Caddy reemplaza X-Forwarded-For por la IP de conexión y elimina Forwarded/X-Real-IP. No añadir balanceadores/CDN sin revisar esta frontera.

Las dos bases usan volúmenes independientes y no publican puertos. API y proxy son no root, sin capacidades y con raíz de solo lectura. PostgreSQL oficial inicializa permisos y ejecuta el proceso principal como UID 70. `prepare` y `migrate` son tareas de mantenimiento privilegiadas limitadas, no servidores públicos. El API no monta secretos administrativos ni la CA privada. No hay worker ni ruta de egreso NVD desde sus redes internas.

## 5. Servidor admitido

Guía orientada a Ubuntu Server 24.04 LTS x86_64 limpio, mantenido, con SSH por clave y usuario operador dedicado. El laboratorio usó Ubuntu 24.04, Docker Engine 29.8.2 y Compose 5.6.0. Otras versiones compatibles requieren comprobación. ARM/Graviton no se validó; el respaldo de imagen PostgreSQL incluido es de la arquitectura original. No copiar `/var/lib/docker` ni volúmenes de la laptop.

## 6. Recursos

Reserva práctica inicial, no resultado de una prueba de carga: al menos 2 vCPU, 8 GiB RAM y 40 GiB libres para construir/restaurar; recomendado 4 vCPU, 16 GiB y 80 GiB EBS cifrado con espacio adicional para backups. Los límites actuales de contenedor permiten hasta 2 GiB por PostgreSQL, 1 GiB API y 256 MiB proxy; la construcción React necesita memoria adicional. No elegir una instancia pequeña basándose solo en que el dump comprimido ocupa unos 216 MB. Medir disco/RAM/latencia después de restaurar y antes de abrir. Vigilar créditos si se elige una instancia burstable.

## 7. Dependencias del host

En el servidor nuevo, instalar Git, Python 3, OpenSSL, iproute2, curl, certificados y Docker con Buildx/Compose. No hacen falta Python/npm/PostgreSQL del producto en el host: las dependencias se instalan dentro de imágenes. El script operador solo usa la biblioteca estándar de Python.

```sh
sudo apt update
sudo apt install git python3 openssl iproute2 curl ca-certificates
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF_DOCKER
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.asc
EOF_DOCKER
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker version
sudo docker compose version
```

Si ya hay Docker, inspeccionar compatibilidad sin desinstalarlo ni borrar nada. Seguir [la instalación oficial de Docker](https://docs.docker.com/engine/install/ubuntu/) para paquetes/conflictos. No usar el script de conveniencia para este servidor. Dar acceso a Docker solo al operador de confianza: equivale a privilegios administrativos. Los comandos siguientes asumen que ese operador puede ejecutar `docker`; la asignación de permisos del host corresponde al responsable.

## 8. Clonar y fijar la versión

Ejecutar en un directorio nuevo del operador; mantener los tres nombres como hermanos, porque el contexto de build frontend y el bootstrap Database los utilizan.

```sh
mkdir -p "$HOME/vulntrack-release"
cd "$HOME/vulntrack-release"
git clone --branch release/v1.0.0-rc1 https://github.com/Jesel8D/vuln-track-backend.git
git clone --branch release/v1.0.0-rc1 https://github.com/Jesel8D/vuln-track-frontend.git
git clone --branch release/v1.0.0-rc1 https://github.com/Jesel8D/vuln-track-database.git
git -C vuln-track-backend checkout --detach 417d190146a9c7babce81f76794e652f71ab0af2
git -C vuln-track-frontend checkout --detach c18709296efc46e47bf3f9afc34dfa40f570213e
git -C vuln-track-database checkout --detach b8fbcdbf3edee9ef733818517b19fe0b37ba35d4
git -C vuln-track-backend rev-parse HEAD
git -C vuln-track-frontend rev-parse HEAD
git -C vuln-track-database rev-parse HEAD
```

Conservar esta guía recibida fuera del checkout: puede estar en un commit documental posterior. No ejecutar `git pull` automático en producción. No instalar archivos ni dependencias del repositorio Context.

## 9. Docker y operaciones

Desde `vulntrack-release/vuln-track-backend`:

```sh
cd "$HOME/vulntrack-release/vuln-track-backend"
export VULNTRACK_RUNTIME="$HOME/vulntrack-private-runtime"
python3 deploy/production/operate.py --help
```

La ruta runtime debe ser nueva, fuera de los cuatro repositorios, propiedad del operador y no contener espacios ni caracteres de expansión de Compose. El nombre de proyecto se genera con nonce y permanece ligado a ella. Los scripts rechazan inicializar/restaurar sobre tablas existentes. No usar `docker compose down -v`, `volume rm`, `system prune` ni borrar runtime para reparar fallos. Todos los comandos requieren `--runtime` y operan sobre ese proyecto.

Para inspección/mantenimiento usar esta función de shell, siempre con el mismo runtime:

```sh
dc() {
  docker compose --env-file "$VULNTRACK_RUNTIME/compose.env" \
    -f deploy/production/compose.yaml \
    -f "$VULNTRACK_RUNTIME/network-subnets.yaml" "$@"
}
```

No imprimir `docker compose config` completo ni `docker inspect` de secretos en una terminal compartida. Las imágenes de Python, Node, Caddy y PostgreSQL están fijadas por digest. Node solo es etapa de construcción; Caddy sirve el resultado. Etiquetas locales de salida: `vulntrack-backend:production-rc1` y `vulntrack-web:production-rc1`; reservarlas para esta versión/host.

## 10. Configuración y secretos

Sustituir dominio/correo por los propios antes de generar:

```sh
python3 deploy/production/operate.py generate \
  --runtime "$VULNTRACK_RUNTIME" \
  --origin https://vulntrack.example.org --email operator@example.org
```

Genera credenciales aleatorias diferentes para ambas administraciones SQL, API, lector CPE y JWT; CA privada y certificados SQL. Runtime 0700; secretos 0600. `compose.env` contiene metadatos públicos y referencia al runtime; `api-settings.json` contiene secretos y no debe versionarse/transferirse como ejemplo. `prepare` copia solo lo requerido a volúmenes protegidos, con UID correcto. No modificar el runtime de la laptop ni reutilizar sus secretos.

Valores efectivos: `environment=production`, un único origen HTTPS exacto, `cors_allow_credentials=false`, JWT 300 segundos, `nvd_mode=disabled`, `cve_live_enabled=false`, `cve_worker_enabled=false`, pool SQL 5 sin overflow. No API key, autoridad experimental ni credenciales de NVD. Los certificados generados son solo transporte SQL, no permisos para integraciones. La variable pública de build `VITE_NVD_MODE=disabled` no es un control de autorización: el servidor bloquea por separado.

`PUBLIC_BIND=127.0.0.1` es el valor inicial seguro. `TLS_MODE=` vacío significa ACME público; `--tls-internal` sirve exclusivamente para un laboratorio sin certificado público. No copiar el modo internal a la apertura de EC2. El ejemplo público está en `deploy/production/compose.env.example`; no reemplazar el archivo generado con él porque perdería nombre/rutas propios.

## 11. Inicialización PostgreSQL privado

Primero construir imágenes (sección 14). Después:

```sh
python3 deploy/production/operate.py init-db --runtime "$VULNTRACK_RUNTIME" \
  --database ../vuln-track-database
```

Arranca dos PostgreSQL en volúmenes nuevos. Verifica hashes de fuentes SQL canónicas y aplica únicamente 001,002,004,005,006,007, luego migraciones. No carga el seed 003 ni crea usuarios. El rol API `vulntrack_v2_api` no es superusuario/owner ni evita RLS; recibe los permisos y contexto necesarios. Transporte entre contenedores con SCRAM y TLS `verify-full`. La base privada inicia vacía de cuentas. No restaurar el dump personal ni cambiar el destino a una base ya utilizada.

## 12. Migraciones

`init-db` ejecuta V1 hasta `0004_mvp_cve` y verificación hasta `v2_0010_cve_cache`. El API no migra al arrancar. En una actualización posterior aprobada, primero copia recuperable y parada de escrituras, después mantenimiento explícito:

```sh
python3 deploy/production/operate.py migrate --runtime "$VULNTRACK_RUNTIME"
dc exec -T postgres psql -XqAt -U postgres -d vulntrack \
  -c 'SELECT version_num FROM public.alembic_version; SELECT version_num FROM public.alembic_verification_version;'
```

Debe devolver ambas revisiones indicadas. La validación comprueba además estructura, roles, permisos y RLS; no basta el número. No usar `stamp`, downgrade ni SQL manual para saltar un error de integridad.

## 13. Transferir y restaurar CPE

Entregar **completa**, sin alterar, la carpeta `respaldo-cpe-nvd-20261123`. Contiene catálogo público y procedencia, no inventarios. Desde la laptop, una vez que el responsable proporcione un destino SSH real:

```sh
scp -r respaldo-cpe-nvd-20261123 operador@servidor:~/
```

Verificar primero por un canal independiente la huella SSH. Este comando es instrucción para la transferencia futura; no se ejecutó envío al compañero. No adjuntar el respaldo a GitHub. En el servidor:

```sh
cd "$HOME/respaldo-cpe-nvd-20261123"
sha256sum -c SHA256SUMS
cd "$HOME/vulntrack-release/vuln-track-backend"
python3 deploy/production/operate.py restore-cpe --runtime "$VULNTRACK_RUNTIME" \
  --directory "$HOME/respaldo-cpe-nvd-20261123"
```

El script verifica formato 2, nombres/tamaños/SHA de archivos, destino vacío, restaura mediante pg_restore en transacción, crea índices de lectura y verifica huellas de todas las filas/columnas de cinco tablas. Después crea `vulntrack_catalog_reader` con SELECT limitado y transacciones de solo lectura; el API no puede escribir/importar. La cuarentena no es legible por ese rol. El recibo queda ligado al proyecto y `up` lo exige.

Datos esperados: `products` 1,880,952 oficiales y cero fixtures; `summary` 1, `feed_imports` 1, `feed_quarantine` 1, `sync_runs` 0. Un CPE inválido fue descartado; `summary` conserva cobertura parcial por esa razón. No ocultarla ni reconstruir datos para conseguir estado completo. Edición NVD 2026-11-21T04:50:01Z, descarga/importación 2026-11-23; no se actualizó NVD durante esta misión. Fuente preservada en manifest: `https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz`.

Dump 216,094,734 bytes, SHA-256 `5b4244cf14ac916c85791c282b8e0d53d89072d94f5e06e1360ca2fa5d285925`. Contrastar también `manifest.json` y `SHA256SUMS` con las referencias de la entrega. La mera existencia del recibo no sustituye comprobar el catálogo tras una recuperación.

Validación administrativa local, sin credenciales en argumentos:

```sh
dc exec -T catalog psql -XqAt -U postgres -d vulntrack <<'SQL_CPE'
SELECT count(*),count(*) FILTER (WHERE mode='fixture') FROM vulntrack_catalog.products;
SELECT count(*) FROM vulntrack_catalog.summary;
SELECT count(*) FROM vulntrack_catalog.feed_imports;
SELECT count(*) FROM vulntrack_catalog.feed_quarantine;
SELECT count(*) FROM vulntrack_catalog.sync_runs;
SELECT has_table_privilege('vulntrack_catalog_reader','vulntrack_catalog.products','SELECT'),
       has_table_privilege('vulntrack_catalog_reader','vulntrack_catalog.products','INSERT,UPDATE,DELETE,TRUNCATE');
SQL_CPE
```

Se esperan `1880952|0`, `1`, `1`, `1`, `0`, `t|f`. Para esta infraestructura usar el operador de producción anterior; el restaurador autónomo incluido en el respaldo documenta el laboratorio original y no configura este Compose/TLS.

## 14. Construcción del frontend e imágenes

Antes de inicializar:

```sh
python3 deploy/production/operate.py build --runtime "$VULNTRACK_RUNTIME"
docker image inspect vulntrack-backend:production-rc1 --format '{{.Id}}'
docker image inspect vulntrack-web:production-rc1 --format '{{.Id}}'
```

Instala Backend desde `requirements.lock`, frontend con `npm ci --ignore-scripts`, y ejecuta `npm run build`. React usa API del mismo origen, sin puerto localhost compilado ni secretos. No ejecutar `npm run dev` como servicio público. Caddy recibe solo `dist`, no node_modules. Build necesita registries/PyPI/npm accesibles; no confundir funcionamiento offline del inventario con construcción offline desde cero. El secreto BuildKit `proxy_ca` permite CA corporativa pública de confianza; `PROXY_CA_FILE` es opcional y no debe apuntar a claves privadas. No desactivar validación TLS de las descargas.

## 15. Backend

Entrada `app.production:create_app`; configuración privada comprobada por propietario/permisos. Un worker y una réplica obligatorios por los limitadores por proceso. Socket Unix, sin mapeo TCP. `/ready` comprueba dependencia privada; la prueba CPE autenticada de la sección 23 comprueba la otra base. El API solo usa roles SQL dedicados; mantenimiento se ejecuta aparte. No activar los componentes experimentales conservados en el código.

## 16. Proxy inverso

Se utiliza `deploy/production/Caddyfile`, sin Nginx adicional. Sirve SPA, redirige HTTP a origen HTTPS, envía `/api/*`, `/health`, `/ready` al socket y responde 404 para docs/OpenAPI públicos. Cabeceras CSP self, HSTS 86400 segundos, nosniff, frame DENY y referrer no-referrer. `style-src unsafe-inline` se conserva por compatibilidad de estilos; no permite scripts inline. Cuerpo máximo 8192 bytes y timeouts definidos. No convertir `X-Forwarded-For` recibido en identidad confiable. Véase [proxy Caddy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) y [Uvicorn](https://uvicorn.dev/settings/).

## 17. Dominio

El responsable debe asignar DNS A a la IP pública estable de EC2. Publicar AAAA solo si IPv6 funciona y sus reglas se comprobaron; quitar un AAAA incorrecto antes de pedir certificado. `SITE_HOST`, `PUBLIC_ORIGIN` y origen CORS deben coincidir. Elegir dominio antes de `generate`. Un cambio posterior requiere mantenimiento de las tres configuraciones y reconstrucción/verificación correspondiente; no arreglar CORS con comodines.

## 18. HTTPS y certificados

Para EC2: `TLS_MODE=` vacío, dominio real y puertos públicos 80/443 hacia Caddy. Caddy gestiona certificado público/renovación en `caddy_data`, que debe persistir y mantenerse escribible por UID10001. No borrar ese volumen ni copiar la CA local del laboratorio como certificado público. Ver [HTTPS automático oficial](https://caddyserver.com/docs/automatic-https). DNS/ACME/TLS público no se probaron en la laptop.

TLS SQL usa CA privada distinta, `verify-full` y nombres `postgres`/`catalog`. Certificados iniciales duran 90 días, CA 365 días. Programar alerta al día 60 y renovar antes de vencer; no esperar a una caída. En mantenimiento, preservar una copia cifrada del runtime, renovar hojas con la misma CA y verificar antes de aplicar:

```sh
cd "$VULNTRACK_RUNTIME"
for host in postgres catalog; do
  openssl x509 -req -in "$host/server.csr" -CA ca.crt -CAkey ca.key \
    -CAcreateserial -days 90 -extfile "$host/server.ext" -out "$host/server.crt.next"
  openssl verify -CAfile ca.crt "$host/server.crt.next"
  install -m 600 "$host/server.crt.next" "$host/server.crt"
done
cd "$HOME/vulntrack-release/vuln-track-backend"
dc run --rm --no-deps prepare
dc exec -T postgres psql -U postgres -d vulntrack -c 'SELECT pg_reload_conf();'
dc exec -T catalog psql -U postgres -d vulntrack -c 'SELECT pg_reload_conf();'
dc restart api
```

Esta renovación se documenta para operación, no se ensayó el transcurso de 90 días. La rotación de CA es un mantenimiento distinto: emitir CA/hojas nuevas, distribuir confianza y reiniciar clientes de forma coordinada antes de su año de vencimiento; requiere ensayo previo en réplica. Nunca subir CA privada/hojas privadas a Git ni confundirlas con permisos NVD. Referencia: [TLS PostgreSQL 16](https://www.postgresql.org/docs/16/ssl-tcp.html).

## 19. Firewall y grupos de seguridad

Trabajo exclusivo del responsable en EC2. [SG actúa como firewall de la instancia](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html). Entrada SSH22 solo desde IP administrativa; HTTP80 para ACME/redirección; HTTPS443 inicialmente solo desde IP del responsable para crear primera cuenta y pruebas. No abrir5432/8000/8018/5191/8081/2375 ni rangos de Docker. No configurar SG solo por nombre: comprobar reglas IPv4/IPv6 y NIC reales. No hay AWS credentials ni cambios AWS en esta entrega.

Docker puede sortear reglas de ufw al publicar puertos; no confiar solo en ufw. Comprobar SG y reglas Docker/DOCKER-USER del host según [Docker y firewall](https://docs.docker.com/engine/install/ubuntu/). Usar egress mínimo que permita DNS, hora, descarga y ACME durante preparación; el API en redes internas no necesita Internet. No habilitar egreso NVD.

Tras verificar dominio/SG, el operador edita **solo en EC2** `PUBLIC_BIND=0.0.0.0` en su `compose.env`. Nunca hacerlo en esta laptop. La apertura 443 a usuarios se realiza al final de los criterios GO, no durante la creación de la primera cuenta.

## 20. Inicio de servicios

Después de build, inicialización y restauración satisfactoria:

```sh
python3 deploy/production/operate.py up --runtime "$VULNTRACK_RUNTIME"
python3 deploy/production/operate.py status --runtime "$VULNTRACK_RUNTIME"
```

`up` exige recibo CPE verificado del mismo proyecto; espera healthchecks. Servicios persistentes con `restart: unless-stopped`. `prepare` terminado con 0 es normal; `migrate` es tarea explícita. No añadir `--scale api=2`. Si el bind cambió después del primer arranque, `up` recrea el proxy con los mismos volúmenes.

## 21. Disponibilidad

En el servidor y desde una estación permitida, sin omitir verificación TLS:

```sh
curl --fail --show-error https://vulntrack.example.org/health
curl --fail --show-error https://vulntrack.example.org/ready
curl -I https://vulntrack.example.org/
curl -I http://vulntrack.example.org/
curl -I https://vulntrack.example.org/docs
python3 deploy/production/operate.py status --runtime "$VULNTRACK_RUNTIME"
dc port proxy 8443
dc port postgres 5432
dc port catalog 5432
ss -ltn
```

Esperados: health/ready200, frontend200 con assets, HTTP308 a HTTPS, docs404, cuatro servidores healthy, ninguna publicación PostgreSQL/API. `dc port` sin mapeo SQL puede terminar con código no cero: es esperado. Verificar además TLS/cabeceras desde un cliente externo permitido, sin realizar un escaneo remoto. Readiness200 por sí sola no valida CPE ni permisos funcionales.

## 22. Primera cuenta y cierre del registro

Con 443 restringido a IP administrativa, abrir `/crear-cuenta`, elegir usuario y contraseña propios, iniciar sesión y confirmar workspace inicial owner. No hay usuario/password predeterminado ni seed. Guardar credenciales en gestor seguro. El registro crea workspace por cuenta; no existe alta de miembros desde UI ni promoción automática global.

Cerrar registro después de las cuentas previstas:

```sh
python3 deploy/production/operate.py configure --runtime "$VULNTRACK_RUNTIME" --registration off
```

El reinicio es solo del API propio; usuarios y datos persistentes no se borran. Probar que nueva cuenta se rechaza y que la existente aún entra. No incluir usuario/password en historial de shell ni tickets. El acceso de otros miembros debe planificarse por el procedimiento autorizado de membresías de la aplicación; no insertar SQL improvisado para repartir privilegios.

## 23. Pruebas de aceptación del servidor

Registrar resultados, fecha y commit sin datos privados: login/logout, workspace correcto, crear una aplicación/dispositivo sintético autorizado para aceptación, añadir tecnología Apache HTTP Server2.4.49, buscar CPE oficial y confirmar procedencia, revisar historial y páginas totales. UUID público de referencia `10e70f95-eb64-4262-a822-9055aab8fe76`; búsqueda y conteo del catálogo deben responder sin NVD. No interpretar su CVE como hallazgo confirmado.

Verificar owner/editor/viewer con cuentas de aceptación y membresías previamente autorizadas; viewer no escribe, IDs de workspace ajeno no se ven, cambio rápido limpia selección. Confirmar que botones CVE están deshabilitados y el Backend devuelve bloqueo. No solicitar pruebas live ni ZAP. Reiniciar solo este proyecto y comprobar persistencia, health y búsqueda CPE. La validación local ya cubrió estos escenarios con datos sintéticos (ver `VALIDACION_LOCAL.md`), pero no sustituye la aceptación del servidor real. No ejecutar toda la suite contra producción ni cargar fixtures en ella.

## 24. Respaldos y recuperación

Crear copia privada antes de cambios y con periodicidad acordada (punto inicial: diaria, retención30d, RPO24h; son objetivos del operador, no garantía de esta entrega):

```sh
python3 deploy/production/operate.py backup --runtime "$VULNTRACK_RUNTIME"
```

Crea carpeta nueva bajo `runtime/backups`, dump y manifestSHA sin sobrescribir. Dump contiene información privada: cifrar copia externa, restringir acceso, comprobar SHA después de transferir y ensayar restauración. Conservar también runtime cifrado, revisión de código, configuración, volúmenes Caddy y paquete CPE con sus checksums; Docker volume no equivale a backup. No versionar dumps ni pegar logs/secrets. Monitorizar disco y éxito de cada copia. HMAC reside también en la base; recuperación deriva esa clave para conservar contexto.

Para simulacro ante pérdida del servidor, en **otro runtime y volúmenes vacíos**, con código aprobado idéntico:

```sh
export VULNTRACK_RUNTIME="$HOME/vulntrack-recovery-runtime"
python3 deploy/production/operate.py generate --runtime "$VULNTRACK_RUNTIME" \
  --origin https://recovery.example.org --email operator@example.org
python3 deploy/production/operate.py restore-private --runtime "$VULNTRACK_RUNTIME" \
  --archive /ruta/protegida/copia-produccion/database.dump
python3 deploy/production/operate.py restore-cpe --runtime "$VULNTRACK_RUNTIME" \
  --directory "$HOME/respaldo-cpe-nvd-20261123"
python3 deploy/production/operate.py up --runtime "$VULNTRACK_RUNTIME"
```

Mantener `manifest.json` junto al dump. Solo acepta formato `vulntrack-production-private-v1` conSHAyheadv10; no es permiso para transferir la base personal. Preserva propietarios/ACL y verifica esquema; genera credenciales de infraestructura y JWT nuevos. `restore-private` regenera configuración con registro inicialmente habilitado: restringir acceso y volver a cerrarlo antes de abrir. No restaura el catálogo con el dump privado; son dos recuperaciones separadas. Comprobar filas/relaciones/permisos y recuperar ambos antes de cambiar DNS. No copiar un recibo CPE entre proyectos.

## 25. Reinicio y actualización

```sh
dc restart postgres catalog api proxy
python3 deploy/production/operate.py up --runtime "$VULNTRACK_RUNTIME"
```

Si el responsable detuvo los contenedores con `stop`, volver con `up`; no se pierden volúmenes. Tras reiniciar el host, comprobar servicio Docker/health y persistencia. No instalar actualizaciones de dependencias flotantes ni cambiar digests automáticamente. Para una versión nueva: aprobar commits, copia recuperable y runtime cifrado, conservar IDs/imágenes anteriores, probar en réplica, detener escrituras, migrar explícitamente si corresponde y verificar contratos/health/inventario/CPE antes de abrir. No ejecutar `init-db` nuevamente sobre producción.

Los logs Docker requieren rotación para no llenar disco: el responsable debe configurar y comprobar límites del driver en ese host o un destino de logs con acceso restringido antes de abrir. No se modificó el daemon de la laptop.

## 26. Solución de problemas

| Síntoma | Acción segura |
|---|---|
| Error DNS/registry al construir | Comprobar DNS/egress/TLS del host; reintentar secuencialmente. No desactivar TLS ni sustituir imágenes por copias de terceros. |
| Base no vacía | Detener inicialización; verificar runtime/proyecto. Elegir nuevo destino para ensayo; conservar el existente. |
| Migración/deriva SQL | Detener publicación; conservar dump/log protegido y comparar commit Database/Backend. No stamp/downgrade ni reconstrucción. |
| API sin readiness | `dc logs --tail=50 api`, estado SQL/TLS y permisos del archivo; tratar logs como privados. Revisar `operation-errors.log` solo localmente y redactar antes de compartir. |
| Proxy sin certificado | DNS A/AAAA, reloj,80/443, ACME email y permisos persistentes `/data`; no internal para apertura pública. |
| CPE no disponible | Restore/recibo de este proyecto, rol lector, TLS y huellas; no importar NVD ni apuntar al PostgreSQL privado. |
| Fallo de SHA/huella | Parar; conservar origen/destino, pedir transferencia íntegra de respaldo. No editar manifest ni datos para coincidir. |
| CA SQL vencida | Renovar en mantenimiento y verificar hostname/cadena; no `sslmode=disable/require`. |
| Sin subred disponible | Revisar rutas y elegir rangos propios no superpuestos en `network-subnets.yaml`, antes de crear redes; no borrar redes ajenas. |
| 429 o sesión expirada | Esperar ventana e iniciar sesión; no escalar procesos para evadir límites. |

`operate.py` oculta valores de errores, escribe stderr protegido; no enviarlo crudo al repositorio. En un fallo de migración que requiera diagnóstico, el responsable debe capturar salida de Alembic en un archivo privado desde la tarea de mantenimiento, sin cambiar permisos públicos ni exponer la URL. No dar por exitosa una migración fallida porque el contenedor SQL siga healthy.

## 27. Reversión

Este candidato no ejecuta migraciones al arrancar API. Para fallo solo de configuración/imagen, cerrar acceso y escrituras, conservar backup del estado actual, restaurar configuración propia anterior y usar imagen/código aprobado anterior **solo si el esquema es compatible**. Las etiquetas locales son mutables; conservar IDs o guardar las imágenes aprobadas antes de reemplazarlas. No cambiar a commits preproducción que no tengan esta infraestructura.

Si hubo una migración incompatible, no hacer downgrade destructivo: recuperar copia anterior en proyecto/volúmenes nuevos, comprobar integridad/permisos/CPE y trasladar tráfico mediante el procedimiento del responsable. Conservar los volúmenes fallidos para análisis; no eliminarlos. El retorno a una copia pierde cambios posteriores al punto de respaldo: coordinar esa decisión con los propietarios de datos. El simulacro local validó la recuperación del candidato, no migraciones futuras.

Para cerrar servicios de este proyecto conservando volúmenes:

```sh
python3 deploy/production/operate.py stop --runtime "$VULNTRACK_RUNTIME"
```

## 28. Límites funcionales y de seguridad

CVE live/ZAP/escaneos/autoridades experimentales/fase6 no habilitados. CPE es snapshot, no servicio sincronizado; futuras actualizaciones requieren otra misión. Cero coincidencias no prueba seguridad. Historial fixture sigue marcado; no fabricar recomendaciones. No refresh/reset de contraseña, invitaciones ni UI de membresías. Token solo en memoria; logout no revoca un JWT robado en servidor, máximo300s. Ante incidente, rotar todos:

```sh
python3 deploy/production/operate.py configure --runtime "$VULNTRACK_RUNTIME" --rotate-token
```

La rotación fue probada y conserva datos. Limitadores en memoria se reinician con API y requieren una réplica; capacidad/carga/alta disponibilidad no certificadas. Una instancia alberga ambos PostgreSQL, sin redundancia. No se comprobó permisos de redistribución de Context. El catálogo y sus términos de procedencia permanecen en su paquete público; no se cambian por esta guía. Advisories de dependencias son una consulta fechada y deben reevaluarse en EC2; el resultado local de imágenes está en `SEGURIDAD_IMAGENES.md` y `imagenes-advisories.json` de la entrega: Backend0CRITICAL/53HIGH, web0/2, PostgreSQL1/45. El crítico Go de gosu se evaluó como no alcanzable en su uso de cambio de identidad; se mantienen los avisos y el NO-GO público hasta la revisión del servidor. Ninguna auditoría demuestra ausencia total de vulnerabilidades.

## 29. Checklist previo a exposición

- [ ] Repositorios/SHAs coinciden con manifiesto remoto y código sin cambios inesperados.
- [ ] Host actualizado, imágenes revisadas contra advisories vigentes; sin crítico relevante sin resolver.
- [ ] EBS/copia externa cifrados y acceso Docker/SSH restringidos.
- [ ] Runtime fuera de Git, credenciales nuevas, archivos privados protegidos y sin secretos en build/frontend/logs públicos.
- [ ] Solo proxy publica80/443; SQL/API privados, procesos y redes verificados.
- [ ] DNS y certificado público correctos, redirección/cabeceras/CORS exactos, sin confianza de IP declarada por cliente.
- [ ] Un worker/réplica, TTL300s y procedimiento de rotación aceptado.
- [ ] Migración v10 y esquema/permisos/RLS verificados.
- [ ] CPE cinco huellas/count/procedencia/lector solo lectura; cuarentena preservada.
- [ ] Cuenta inicial propia, registro cerrado y permisos de aceptación comprobados.
- [ ] Reinicio/persistencia/backup/recuperación probados en el servidor, alertas disco/RAM/certificados/copias y rotación logs activas.
- [ ] Live/ZAP/escaneos permanecen deshabilitados y no se transfirió base personal.

## 30. Dictámenes y apertura pública

La configuración y ejecución local pueden recibir GO dentro de su alcance cuando las pruebas documentadas pasan. El GO de entrega permite al responsable preparar EC2; **no equivale a GO público**. La transferencia CPE está preparada y verificada localmente; no se ha enviado a un servidor del compañero.

Solo el responsable puede dar GO de apertura tras registrar toda la sección29, pruebas externas permitidas del dominio/TLS, SG/firewall, revisión vigente de imágenes/host, capacidad, registro cerrado, copias externas y recuperación. Si hay fallo de integridad, crítico relevante, puerto SQL/API expuesto, certificado inválido o ausencia de copia recuperable: NO-GO, conservar datos y corregir. Durante este trabajo no se creó infraestructura AWS ni se abrió la laptop.

CVE live: NO-GO. ZAP: NO-GO. El paquete no contiene autorización para activar ninguno. La fase6 no se inició. Publicación Context: NO-GO por permiso no comprobado; su exclusión no impide usar los otros tres repositorios y esta guía.

# RC1 — ejecución y recuperación local en Windows/WSL2

**IMPLEMENTADO Y PROBADO** en esta PC. Entorno RC1 separado, sin actualizar la
instalación habitual `/home/mz/VulnTrack`. Todos los comandos siguientes se
ejecutan en **Ubuntu-24.04**, no en el prompt PowerShell.

## Abrir Ubuntu y arrancar

Desde PowerShell: `wsl -d Ubuntu-24.04`. Dentro de Ubuntu:

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack-rc1/vuln-track-backend
.venv/bin/python -m scripts.v2_development status --profile rc1
```

Si RC1 ya está encendida, abrir sus URLs. Si está detenida:

```bash
.venv/bin/python -m scripts.v2_development up --profile rc1 \
  --pg-port 55438 --api-port 8004 --web-port 5177 \
  --frontend ../vuln-track-frontend --nvd-mode fixture
```

Mantener esa terminal abierta. `up` valida propietarios, etiquetas, claves,
catálogos y puertos; no iniciar dos launchers del mismo perfil. Para un perfil
existente los puertos guardados prevalecen; no editar su config para adoptar otro
volumen. Si falta su volumen, aborta: no lo recrear a mano.

| Recurso | RC1 | Habitual protegida (no usar para RC1) |
|---|---|---|
| Web | http://127.0.0.1:5177 | 5173 |
| API / Swagger | http://127.0.0.1:8004/docs | 8000 |
| PostgreSQL, solo loopback | 55438 | 55434 |
| Perfil / directorio privado | `rc1`, `.local/rc1/` | `development`, `.local/development/` |
| Volumen | `vulntrack_v2_rc1_pgdata` | `vulntrack_v2_development_pgdata` |
| Contenedor | `vulntrack-v2-rc1-postgres` | `vulntrack-v2-development-postgres` |

La API y Vite son procesos WSL; PostgreSQL tiene su contenedor propio. El worker
CVE funciona dentro del único proceso API. El launcher entrega a Vite solo URL
pública y `VITE_NVD_MODE=fixture`; no claves SQL, JWT, HMAC o NVD. El aviso visible
es informativo y no concede capacidades. No utilizar `--nvd-mode live` para esta
demostración.

## Acceso y demostración

Crear una cuenta normal por UI o usar el dataset ya preparado. Para consultar
solo el acceso principal **en una terminal privada, fuera de la proyección**:

```bash
.venv/bin/python - <<'PY'
import json
from pathlib import Path
print(json.loads(Path('.local/rc1/demo-access.json').read_text())['primary'])
PY
```

No publicar esa salida ni el archivo completo. Seguir el
[guion de 13 minutos](V2_RC1_DEMO_GUIDE.md). Recargar exige login; no implica pérdida
de datos. Usar `127.0.0.1`, porque `localhost` es otro origen CORS.

## Detener y reiniciar conservando datos

Ctrl+C en la terminal de `up`, o desde otra terminal Ubuntu en el mismo Backend:

```bash
.venv/bin/python -m scripts.v2_development stop --profile rc1
.venv/bin/python -m scripts.v2_development status --profile rc1
```

Esperar a que termine el launcher y PostgreSQL figure detenido. Después utilizar
el mismo `up` anterior. No hay comando de borrado ni se elimina el volumen. Se
verifican identidad y tiempo de inicio de los PID antes de detenerlos.

## Backup privado

```bash
.venv/bin/python -m scripts.v2_development backup --profile rc1
```

Se verifica la base propia y genera un dump consistente en
`.local/rc1/backups/FECHA-ID/database.dump`, con `manifest.json` y SHA-256. El comando
imprime la ruta, no secretos. Si PostgreSQL estaba detenido lo inicia; comprobar
su estado después. Guardar dump/manifiesto juntos y una copia externa cifrada.
El dump contiene hashes de contraseñas y HMAC de contexto: es **sensible**, 0600,
ignorado por Git. No adjuntarlo al reporte ni moverlo a directorios públicos.

## Restore: siempre otro perfil y volumen NUEVOS

Leer la ruta exacta del backup propio anterior; no usar un dump no confiable. El
restaurador exige manifiesto, checksum y fuentes compatibles. Puertos 55439/8005/
5178 deben estar libres; si están ocupados, elegir tres libres para el nuevo
perfil. No detener servicios ajenos para liberarlos.

```bash
read -r -p 'Ruta privada absoluta del database.dump RC1: ' rc1_archive
rc1_restore="rc1-restore-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
.venv/bin/python -m scripts.v2_development restore --profile "$rc1_restore" \
  --pg-port 55439 --api-port 8005 --web-port 5178 --archive "$rc1_archive"
.venv/bin/python -m scripts.v2_development up --profile "$rc1_restore" \
  --frontend ../vuln-track-frontend --nvd-mode fixture
```

La instalación original RC1 no cambia. El destino debe ser inexistente; no
sobrescribir perfiles ni volúmenes previos. Se restauran datos, hashes de usuarios
y HMAC; se generan credenciales SQL y secreto JWT nuevos. Los tokens antiguos no
sirven en la copia, pero las contraseñas normales sí. Abrir 5178, hacer login,
comparar IDs/CPE/historial/revisión/recomendación y comprobar la segunda cuenta.
Después parar **solo** ese perfil desde otra terminal con el mismo nombre:

```bash
.venv/bin/python -m scripts.v2_development stop --profile "$rc1_restore"
```

Guardar el nombre porque las variables de una terminal no pasan a otra. Retener
volumen y backup para inspección; nunca hacer prune, down -v ni restore sobre
development. Un ensayo fallido se conserva y diagnostica; un nuevo intento usa
otro nonce/perfil, no un reset destructivo.

## Repetir aceptación y regresiones

Con RC1 fixture encendida:

```bash
.venv/bin/python -m scripts.rc1_acceptance --phase create
.venv/bin/python -m scripts.test_rc1_recovery
```

El primero crea cuentas/datos ficticios nuevos y archiva privadamente los accesos
previos. No borra sus datos. El segundo realiza stop/restart RC1, backup y restore
en nuevo volumen con sufijo aleatorio; deja RC1 encendida y la copia detenida.
Guardas verifican perfil, volumen, puertos, PID, directorio y modo fixture real.
No se puede apuntar la aceptación a development. Las pruebas respetan 429 y el
Retry-After normal; no se amplían cuotas para pasar el recorrido.

Las regresiones generales usan bases **tmpfs nuevas**, no la RC1 persistente:

```bash
export PLAYWRIGHT_CHROMIUM_EXECUTABLE="$(cd ../vuln-track-frontend && node --input-type=module -e 'import { chromium } from "@playwright/test"; console.log(chromium.executablePath())')"
.venv/bin/python -m scripts.test_v2_registration --installation existing --full
.venv/bin/python -m scripts.test_v2_registration --installation new --full
.venv/bin/python api-tests/v2/validate.py
.venv/bin/python api-tests/v2/run.py --installation existing
.venv/bin/python api-tests/v2/run.py --installation new
.venv/bin/python api-tests/v2/run.py --persistent-contract
.venv/bin/python -m scripts.test_v2_security_lab
.venv/bin/python -m scripts.test_v2_egress_lab
cd ../vuln-track-frontend
npm run check
../vuln-track-backend/.venv/bin/python scripts/v2_registration_stack.py \
  --e2e --installation existing --api-port 0 --web-port 0
../vuln-track-backend/.venv/bin/python scripts/v2_registration_stack.py \
  --e2e --installation new --api-port 0 --web-port 0
```

El contrato persistent-development de Newman se ensaya en **tmpfs propia**, no
en development ni contra cuentas personales. `existing` significa bootstrap
legado actualizado dentro del fixture, no una base del usuario. Los laboratorios
usan fixtures/redes propios y limpian únicamente sus recursos etiquetados.

## Preparar dependencias en otra copia de estos commits

Disponer de Docker Desktop integrado a Ubuntu, Python3.12, Node compatible y los
tres repositorios hermanos en el conjunto exacto del manifiesto de entrega. En
Backend: crear `.venv`, instalar `requirements-dev.lock` y
`api-tests/v2/requirements-api.lock`, instalar editable con `--no-deps -e .`,
ejecutar `pip check` y `npm ci --prefix api-tests/v2 --ignore-scripts --no-fund`.
En Frontend: `npm ci`. Usar las ramas RC1 exactas y Database a562e638; no actualizar
los cuatro checkouts habituales para reproducirlo.
Chromium de Playwright ya está instalado en esta PC. En otra instalación,
prepararlo con `npx playwright install chromium` desde Frontend y sus bibliotecas
del sistema antes de ejecutar navegador. La suite histórica usa un path de
Chrome del sistema por defecto; la variable anterior selecciona explícitamente
el Chromium instalado por esta versión de Playwright, sin asumir `/usr/bin`.

## Recuperación ante errores

- Puerto ocupado: revisar qué instalación lo posee; usar otro perfil nuevo si
  hace falta. No matar procesos ajenos ni cambiar puertos en un perfil listo.
- Volumen ausente, fase incompleta, drift o checksum: conservar volumen/config/
  logs, no reaplicar baseline, seed o stamp. Restaurar una copia verificada a otro
  volumen, con las mismas fuentes.
- API/web no lista: revisar `.local/rc1/api.log`, `web.log` y `runtime.json`
  localmente; verificar PATH Node, dependencias y Docker. Los logs son privados.
- 429: esperar Retry-After. 401 tras recarga/restore: iniciar sesión de nuevo.
- Error de clave HMAC: recuperar configuración privada correcta, no inventar una
  clave ni editar membresías para resolverlo.
- Falta de red pública no es un error del demo fixture. No habilitar verify,
  egreso, DNS externo o ZAP como solución.

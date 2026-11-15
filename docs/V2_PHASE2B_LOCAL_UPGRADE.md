# Actualización y reversión local — procedimiento preparado, no ejecutado

**IMPLEMENTADO CON LIMITACIONES.** Ensayado con volúmenes nuevos, incluidos
reinicio, restore separado y lectura con código estable/Fase 2A y sus verificadores
de catálogo. **PENDIENTE:** autorizar y realizar una ventana personal. Esta misión
no ejecuta estos pasos sobre vulntrack_v2_development_pgdata.

## Vista previa independiente

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack-security-phase2b/vuln-track-backend
.venv/bin/python -m scripts.v2_development up --profile phase2b-preview --pg-port 55437 --api-port 8003 --web-port 5176 --frontend ../vuln-track-frontend --nvd-mode fixture
```

Inicializa SOLO un perfil vacío nuevo, no copia datos personales. Si hay colisión
de puertos/nombres, abortar y elegir otros libres, sin parar servicios ajenos.
UI http://127.0.0.1:5176, API http://127.0.0.1:8003/docs. Para detener esa vista
previa desde el mismo worktree: `.venv/bin/python -m scripts.v2_development stop
--profile phase2b-preview`. Mantener el volumen de ese perfil.

## Actualizar el principal solo tras decisión explícita y backup verificado

1. Registrar HEAD/estado limpio de Backend, Database y Frontend originales.
   Anotar versiones anteriores: fcabbe9/b377b5b/4514b68. Confirmar ausencia de
   actividad del usuario y crear/verificar backup con el launcher ORIGINAL:

```bash
cd /home/mz/VulnTrack/vuln-track-backend
git status --short
git -C ../vuln-track-database status --short
git -C ../vuln-track-frontend status --short
.venv/bin/python -m scripts.v2_development status
.venv/bin/python -m scripts.v2_development backup
```

2. Obtener los tres hashes publicados/verificados del reporte de entrega. Usar
   los tres repositorios juntos; Database incluye SQL008 y Backend su equivalente
   empaquetado. No usar main/rudi ni merge. Si hay cambios locales, preservar y
   detener el procedimiento. Después de parar el launcher en la ventana acordada:

```bash
.venv/bin/python -m scripts.v2_development stop
git switch --detach HASH_BACKEND_DEL_REPORTE
git -C ../vuln-track-database switch --detach HASH_DATABASE_DEL_REPORTE
git -C ../vuln-track-frontend switch --detach HASH_FRONTEND_DEL_REPORTE
.venv/bin/python -m pip install -r requirements-dev.lock -r api-tests/v2/requirements-api.lock
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/python -m pip check
(cd ../vuln-track-frontend && npm ci && npm run check)
```

3. SQL008 no se aplica automáticamente a un perfil existente phase=ready. Tras
   comprobar el backup, las fuentes compatibles y la aprobación de la migración,
   ejecutar esta operación explícita desde el Backend ORIGINAL actualizado:

```bash
.venv/bin/python - <<'PY'
import os, subprocess, sys
from scripts.v2_development import PersistentV2
stack = PersistentV2('development')
stack.preflight()
stack.start_database()
stack.verify()
subprocess.run([sys.executable, '-m', 'alembic', '-c', 'alembic-verification.ini',
                'upgrade', 'head'], check=True,
               env={**os.environ, 'MIGRATION_DATABASE_URL': stack.url('postgres')})
stack.verify()
PY
.venv/bin/python -m scripts.v2_development up --frontend ../vuln-track-frontend --nvd-mode fixture
```

No imprimir DSN/contraseñas, no ejecutar stamp, no reintentar DDL a ciegas, no
resetear tablas. Alembic verifica catálogos y opera transaccionalmente; si falla,
conservar datos y diagnosticar. Comprobar /health, /ready, login, membresías,
IDs, historial y disponibilidad de metadatos. verify debe seguir devolviendo
503 sin red; Baseline sigue deshabilitado. Guardar las claves existentes.

## Reversión de código sin perder desafíos/evidencias

Cerrar actividad y parar. Volver a los commits exactos anteriores de los tres
checkouts, reinstalar sus dependencias bloqueadas y arrancar con el mismo perfil:

```bash
cd /home/mz/VulnTrack/vuln-track-backend
.venv/bin/python -m scripts.v2_development stop
git switch --detach fcabbe986f2a4d3dffb259edda0b7245e533ee91
git -C ../vuln-track-database switch --detach b377b5bd8013cc2151f6a1681d168e1df0f5fe42
git -C ../vuln-track-frontend switch --detach 4514b6840b428152c1cd875c95e3e55ad81c4196
.venv/bin/python -m pip install -r requirements-dev.lock
.venv/bin/python -m pip install --no-deps -e .
(cd ../vuln-track-frontend && npm ci)
.venv/bin/python -m scripts.v2_development up --frontend ../vuln-track-frontend --nvd-mode fixture
```

SQL008 y su tabla de versión independiente se CONSERVAN. El código anterior
no las utiliza y sus catálogos antiguos se verificaron compatibles. No hacer
downgrade destructivo ni restore sobre el principal: perdería datos nuevos.
Alembic de verificación rechaza downgrade expresamente. Si hiciera falta recuperar
un backup, ensayar siempre en OTRO perfil/volumen con la versión de código y
fuentes que produjo ese backup. Nunca usar down -v, reset --hard o claves nuevas.

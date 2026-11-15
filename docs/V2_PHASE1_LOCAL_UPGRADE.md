# Actualizar y revertir desarrollo Windows/WSL2

**IMPLEMENTADO CON LIMITACIONES:** procedimiento preparado y ensayado con datos
sintéticos en volúmenes nuevos. **PENDIENTE:** su ejecución manual sobre la
instalación personal. Estos comandos no se ejecutaron contra esa instalación.
No usar main/rudi, no borrar volúmenes y no restaurar la base personal para
revertir solamente código. ZAP permanece bloqueado en todas las alternativas.

## Versiones compatibles

| Par | Backend | Frontend | Esquema |
|---|---|---|---|
| Estable original | fcabbe986f2a4d3dffb259edda0b7245e533ee91 | 4514b6840b428152c1cd875c95e3e55ad81c4196 | SQL007 / Database b377b5b |
| Fase 1 | 56c1274fdb4f48f7c2cb852c4975c8c0ec5bafff | e0f3abbf352b1c23db1654afed3071437b3f2e33 | Igual, sin migraciones nuevas |
| Fase 2A | feat/v2-security-analysis-phase2a | feat/v2-security-analysis-web-phase2a | Igual, sin migraciones nuevas |

El frontend de Fase 1/2A exige analysis_readiness de la API: actualizar ambos
componentes juntos. El backend no reescribe autorizaciones históricas. URLs
antiguas fuera de política se conservan, pero se muestran no elegibles; altas
nuevas privadas/ambiguas se rechazan. approved nunca se convierte en verified.

El ensayo `python -m scripts.test_v2_upgrade` usa procesos independientes de las
tres versiones, verifica el mismo usuario/workspace/destino tras cada cambio,
vuelve a la estable, reinicia la base aislada y prueba restore en OTRO volumen.
No demuestra rollback de una migración futura ni autoriza mezclas de versiones.

## Vista previa independiente, sin tocar datos personales

Para revisar Fase 1 en otro volumen, ejecutar en Ubuntu una terminal propia:

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack-security-phase1/vuln-track-backend
.venv/bin/python -m scripts.v2_development up --profile phase1-preview --pg-port 55435 --api-port 8001 --web-port 5174 --frontend ../vuln-track-frontend --nvd-mode fixture
```

Esto crea un entorno vacío independiente, no una copia de la cuenta personal.
Frontend http://127.0.0.1:5174, API http://127.0.0.1:8001/docs.
Si los puertos están ocupados, detenerse y elegir otros libres; no detener
servicios ajenos. Para detener SOLO esta vista previa, desde el mismo worktree:

```bash
.venv/bin/python -m scripts.v2_development stop --profile phase1-preview
```

Para Fase 2A utilizar su par de worktrees y otro perfil, sin reutilizar el
perfil development del worktree personal:

```bash
cd /home/mz/VulnTrack-security-phase2a/vuln-track-backend
.venv/bin/python -m scripts.v2_development up --profile phase2a-preview --pg-port 55436 --api-port 8002 --web-port 5175 --frontend ../vuln-track-frontend --nvd-mode fixture
```

No se inició ninguna de estas vistas previas persistentes automáticamente. Las
pruebas de navegador sí iniciaron API/Vite en puertos efímeros y PostgreSQL tmpfs,
con limpieza de sus propios procesos al terminar.

## Actualizar el entorno personal a Fase 1, únicamente en ventana acordada

1. Confirmar que no hay actividad y comprobar backups y limpieza Git. Mantener
   originales los archivos .local/development y sus claves. No copiar secretos
   de otros worktrees o perfiles. Antes de parar servicios:

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack/vuln-track-backend
git status --short
git rev-parse HEAD
git -C ../vuln-track-frontend status --short
git -C ../vuln-track-frontend rev-parse HEAD
.venv/bin/python -m scripts.v2_development status
.venv/bin/python -m scripts.v2_development backup
```

2. Conservar en privado la ruta de backup y comprobar su manifest/checksum.
   Si falla backup, aparece trabajo sin confirmar, las versiones no coinciden
   con la tabla o existe deriva de esquema, detener el procedimiento. No ejecutar
   reset, clean, down -v ni restauraciones sobre el volumen principal.

3. Solo entonces parar el launcher en esa ventana. Estos comandos cambian HEAD
   de forma explícita y reversible, sin mover las ramas que ya están en otros
   worktrees:

```bash
.venv/bin/python -m scripts.v2_development stop
git switch --detach 56c1274fdb4f48f7c2cb852c4975c8c0ec5bafff
git -C ../vuln-track-frontend switch --detach e0f3abbf352b1c23db1654afed3071437b3f2e33
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/python -m pip check
(cd ../vuln-track-frontend && npm ci && npm run check)
.venv/bin/python -m scripts.v2_development up --frontend ../vuln-track-frontend --nvd-mode fixture
```

Los commits ya existen localmente y se comprobaron en el remoto. No se requiere
merge ni force push. No ejecutar upgrade Alembic manual contra el principal:
estas versiones no tienen migraciones nuevas. El launcher debe verificar el
contrato compatible y conservar volumen y claves; cualquier fallo exige parar
y diagnosticar, sin corregirlo borrando datos.

4. En otra terminal, comprobar /health, /ready y /docs. Entrar con la cuenta
   existente, verificar IDs/membresía/aplicaciones y confirmar que los destinos
   siguen sin verificación técnica automática. El botón Baseline debe seguir
   deshabilitado. Comparar con las notas tomadas antes de la ventana.

## Reversión a los commits originales, conservando todos los datos

Cerrar actividad, parar limpiamente y volver a ambos commits anteriores:

```bash
cd /home/mz/VulnTrack/vuln-track-backend
.venv/bin/python -m scripts.v2_development stop
git status --short
git -C ../vuln-track-frontend status --short
git switch --detach fcabbe986f2a4d3dffb259edda0b7245e533ee91
git -C ../vuln-track-frontend switch --detach 4514b6840b428152c1cd875c95e3e55ad81c4196
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/python -m pip check
(cd ../vuln-track-frontend && npm ci)
.venv/bin/python -m scripts.v2_development up --frontend ../vuln-track-frontend --nvd-mode fixture
```

Si Git muestra cambios, no sobrescribirlos: conservarlos antes de continuar.
Se utiliza el MISMO .local/development y el MISMO volumen. No se hace restore:
no hay una migración que revertir y restaurar podría perder datos introducidos
durante la versión nueva. Revisar nuevamente autenticación, membresías e IDs.

Para adoptar posteriormente Fase 2A sobre el principal se requiere otra decisión
explícita de actualización. Sustituir ambos commits por los hashes verificados
de su entrega, repetir backup/ventana/comprobaciones y conservar el mismo plan
de vuelta. La publicación de ramas no ejecuta este procedimiento.

# Ejecutar RC2.3 en WSL2

En PowerShell, abre Ubuntu con `wsl -d Ubuntu-24.04`.

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack-RC2.3/vuln-track-backend
bash scripts/setup_rc23_dependencies.sh
.venv/bin/python -m scripts.v2_development status --profile rc2-catalog23
```

El script copia las dependencias de RC2.2 a una carpeta temporal exclusiva en WSL cuando se han perdido después de reiniciar. La copia se puede reconstruir y los resultados en PostgreSQL son persistentes. Si el perfil está detenido, ejecútalo desde ese worktree:

```bash
.venv/bin/python -m scripts.v2_development up --profile rc2-catalog23 \
  --pg-port 55446 --api-port 8012 --web-port 5185 \
  --frontend ../vuln-track-frontend --nvd-mode fixture
```

[Interfaz RC2.3](http://127.0.0.1:5185) · [Swagger](http://127.0.0.1:8012/docs)

El catálogo ofrece la fuente oficial sincronizada y la captura independiente de demostración. Selecciona fixture para un recorrido reproducible hasta consulta CVE y revisión. Los CPE del catálogo oficial también se pueden buscar y confirmar desde PostgreSQL con el launcher en fixture. El modo de la consulta CVE y la procedencia de la identificación deben coincidir.

```bash
.venv/bin/python -m scripts.import_cpe_feed stats
.venv/bin/python -m scripts.import_cpe_feed preflight
```

Cuando el preflight indique `full_safe: true`, `stage` descarga y verifica la edición oficial sin modificar el catálogo. `import` verifica el archivo e inicia o reanuda la carga. Si se usa el modo público live del launcher, detén únicamente ese perfil antes de una importación para liberar el candado del presupuesto NVD.

Para repetir el recorrido offline, usa el catálogo oficial ya cargado y la captura fixture del perfil.

```bash
.venv/bin/python -m scripts.rc1_acceptance --profile rc2-catalog23 --phase create
.venv/bin/python -m scripts.rc1_acceptance --profile rc2-catalog23 --phase resume
```

La regresión opcional de respaldo y restauración usa `.venv/bin/python -m scripts.test_rc1_recovery --profile rc2-catalog23`. Abre un volumen independiente en PostgreSQL 55447 y usa API 8013 y web 5186. Antes de ejecutarla, verifica que haya espacio para el respaldo, la nueva base, sus índices y WAL. La ejecución conserva los volúmenes anteriores.

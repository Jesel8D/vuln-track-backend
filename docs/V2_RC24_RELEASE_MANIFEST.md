# Manifiesto técnico RC2.4

Fecha de verificación: 22 de noviembre de 2026, Ciudad de México.

| Repositorio | Commit de partida RC2.3 | Destino de RC2.4 |
|---|---|---|
| Backend | `3ef3abd5ff445cff0c02ebb53ccefc48c085e719` | `feat/v2-rc24-catalog-resilience` |
| Frontend | `7eb025f41c833b35f42a3004e1e3909fcfaa20b4` | `feat/v2-rc24-catalog-maintenance-web` |
| Database | `c4cb588cc73928556bdcab35b44389370739ef6b` | `feat/v2-rc24-catalog-recovery`, `54f681c9c2e9fdcea296bb062b63f6c25fa6c975` |
| Context | `651aa7b9dfd15e0b03f4540f4821f3ba93ab9a7f` | Mismo commit de referencia |

`app/db/v2_source_manifest.json` conserva la correspondencia de SQL013 con Database. La migración `v2_0006_cpe_quarantine` añade exclusivamente la evidencia de cuarentena. El contrato HTTP OpenAPI se conserva byte a byte. El informe local registra los tres hashes publicados después de verificarlos en GitHub.

## Arranque del piloto

Abre Ubuntu con `wsl -d Ubuntu-24.04`. El perfil dedicado es `rc2-catalog24` y su volumen se llama `vulntrack_v2_rc2_catalog24_pgdata`.

```bash
export PATH="/home/mz/.local/opt/node-v24.18.0-linux-x64/bin:$PATH"
cd /home/mz/VulnTrack-RC2.4/vuln-track-backend
bash scripts/setup_rc23_dependencies.sh
export VULNTRACK_RC24_DOCKER_SUBNET=10.254.248.0/28
.venv/bin/python -m scripts.v2_development up --profile rc2-catalog24 \
  --pg-port 55448 --api-port 8014 --web-port 5187 \
  --frontend ../vuln-track-frontend --nvd-mode fixture
```

En este equipo se agotaron las subredes automáticas de Docker. Antes de elegir la subred del piloto se revisaron las rutas de Windows y WSL y todas las subredes del motor. La variable solo afecta al perfil RC2.4. Comprueba solapamientos si la usas en otra máquina. [Piloto](http://127.0.0.1:5187) · [Swagger](http://127.0.0.1:8014/docs)

## Estado técnico

| Área | Clasificación |
|---|---|
| Auditoría de almacenamiento y resguardo cifrado en F: | IMPLEMENTADO Y PROBADO |
| Restauración completa desde respaldo y comparación de datos en RAM | IMPLEMENTADO Y PROBADO |
| Recuperación persistente completa en este equipo | BLOQUEADO |
| Reconstrucción a partir del TAR | IMPLEMENTADO CON LIMITACIONES. Se verificó el TAR completo y se probó el mecanismo de escritura y reanudación con datos reducidos. |
| Cuarentena e idempotencia del único rechazo de la edición | IMPLEMENTADO Y PROBADO |
| Sincronización acotada, deprecación e integridad histórica | IMPLEMENTADO Y PROBADO |
| Regresión del inventario, búsquedas y aplicación de RLS | IMPLEMENTADO Y PROBADO |
| Respaldo en un dispositivo independiente y aceptación académica | PENDIENTE |

[Pruebas](V2_RC24_TEST_REPORT.md) · [Límites](V2_RC24_LIMITATIONS.md) · [Checklist](V2_RC24_ACADEMIC_CHECKLIST.md)

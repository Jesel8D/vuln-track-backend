# VulnTrack Backend — RC4.1 / candidato de entrega

API FastAPI para inventario local con workspaces, roles owner/editor/viewer, dispositivos, aplicaciones, tecnologías y su historial. Identifica productos mediante un catálogo CPE PostgreSQL independiente y de solo lectura. Las consultas CVE habituales son **fixtures capturados**: no prueban vulnerabilidad ni riesgo. CVE externo/NVD live, verificación remota, OWASP ZAP y despliegue público están aplazados.

La documentación de esta instalación está en [el índice vigente](../evolucion-vulntrack/00_INDICE_DOCUMENTACION_VIGENTE.md), [operación](../evolucion-vulntrack/MANUAL_OPERACION_LOCAL.md) y [seguridad](../evolucion-vulntrack/AUDITORIA_FINAL_SEGURIDAD.md). Los documentos anteriores en `docs/` conservan contratos y evidencia histórica; no constituyen permiso de activar integraciones.

## Preparación de producción

La configuración aislada del candidato `release/v1.0.0-rc1` y la guía autosuficiente están en [deploy/production](deploy/production/GUIA_DESPLIEGUE_VULNTRACK_PRODUCCION.md). Compila React, usa Caddy/HTTPS, dos PostgreSQL privados con TLS y un socket Unix para FastAPI. Genera secretos propios y restaura únicamente el catálogo público en volúmenes nuevos. No depende de Context ni de los enlaces locales de documentación de esta laptop. La apertura pública requiere completar las verificaciones del servidor; CVE live y ZAP siguen bloqueados.

## Arquitectura y configuración

Python 3.12, FastAPI, SQLAlchemy/psycopg, PostgreSQL 16 y Alembic. La aplicación usa un rol SQL sin privilegios de administrador y contexto firmado por transacción para RLS. El catálogo se lee con `CPE_CATALOG_READ_URL` independiente. JWT Bearer de vida corta; la contraseña usa Argon2id. Sin refresh ni recuperación de contraseña. Las sesiones del navegador viven en memoria.

El esquema vigente de esta laptop es V1 `0004_mvp_cve` y verificación `v2_0010_cve_cache`; las migraciones posteriores al bootstrap están en este repositorio. No aplicar seeds ni migraciones manuales sobre una base existente para igualar ejemplos antiguos.

El código experimental de egreso se conserva en esta rama y en bundles/imagen, protegido por gates. **No ejecutarlo ni emitir permisos**: la integración real está aplazada. Una API key o variable no autoriza live.

## Operación de la instalación existente

Requiere Docker/Compose, Python 3.12, Node >=22.12 y dependencias ya instaladas. Desde este repositorio:

```sh
.venv/bin/python -m scripts.v2_development status --profile rc3-catalog31
.venv/bin/python -m scripts.v2_development up --profile rc3-catalog31 --frontend ../vuln-track-frontend --nvd-mode fixture
```

Frontend `127.0.0.1:5191`, API `127.0.0.1:8018`, PostgreSQL privado `127.0.0.1:55452`, catálogo `127.0.0.1:55454`. Los archivos efectivos están bajo `.local/` y contienen secretos: no versionar, mostrar ni empaquetar como código. El catálogo debe estar iniciado antes de usarlo. El launcher conserva los volúmenes al detenerse. Consultar el manual antes de restaurar o arrancar una instalación nueva; no reutilizar un volumen ajeno ni borrar datos para reparar un arranque.

Para instalar dependencias en un checkout nuevo:

```sh
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Esto requiere disponer de paquetes o conexión; la operación offline no garantiza una instalación desde cero offline.

## Validación

Las pruebas de integración requieren PostgreSQL **desechable** y variables proporcionadas por `scripts.disposable_v2.DisposableV2`, nunca la base personal. La ejecución reproducible del cierre está en `../evolucion-vulntrack/cierre-fase-5-evidencia/probar-backend.py`. Omite expresamente la prueba que genera material de aprobación sintético. Los conteos finales y límites están en [resultados](../evolucion-vulntrack/RESULTADOS_VALIDACION_FINAL_FASE_5.md).

```sh
.venv/bin/python api-tests/v2/validate.py
.venv/bin/python api-tests/v2/run.py --installation new
.venv/bin/pip check
```

La colección Newman requiere sus dependencias Node en `api-tests/v2/`. El runner crea datos sintéticos en tmpfs y transporte fixture; no ejecuta consultas NVD. No usar pruebas de aceptación sobre la instalación habitual.

## Contratos, límites y licencia

`/docs`, `/redoc` y `/openapi.json` exponen el contrato. V1 sigue por compatibilidad; la interfaz habitual usa V2. Paginación con límites validados y orden determinista; caché y consultas mantienen fuente, cobertura, vigencia y correspondencia histórica independientes. No se generan recomendaciones automáticas. Cero resultados no demuestra ausencia de vulnerabilidades. El logout borra el token local y no revoca un JWT robado antes de su expiración; el limitador es local al proceso. Esta auditoría no habilita exposición pública.

Licencia [MIT](LICENSE). La denominación del conjunto RC4.1-local no cambia la versión interna histórica del paquete Python.

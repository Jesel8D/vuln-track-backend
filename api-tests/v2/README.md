# API V2 estabilizada: colección y pruebas

## Actualización local: cuarto incremento, 24/11/2026

Contrato vigente: **73 operaciones y 110 requests definidos**; 71 operaciones anteriores conservadas, 2 lecturas nuevas de analítica. Los contratos congelados anteriores se conservan; `analytics-contract.json` registra adiciones y los dos filtros opcionales nuevos de GET devices. `validate.py` verifica la evolución exacta, esquemas y ejemplos. La colección se generó y validó; **no se ejecutó Newman en este incremento**.

Nuevos GET autenticados por workspace: `inventory-analytics/distribution` (devices/technologies, vendor/product, top 1–10, otros/desconocidos) y `inventory-analytics/events` (days 30/90 UTC, eventos registrados, incluidas entidades inactivas). Los dos modelos usan response_model estricto; no leen el diccionario público ni resultados CVE. GET devices admite manufacturer_key/model_key exactos con la misma normalización. Sin escrituras, migraciones o paquetes nuevos.

Los ejemplos son sintéticos de contrato y no alimentan las gráficas. La validación sobre inventarios existentes compara 32 respuestas en 4 ámbitos con filas SQL independientes. [Informe completo y límites](../../../evolucion-vulntrack/CUARTO_INCREMENTO_ANALITICA_INVENTARIO.md). El texto de estabilización siguiente es antecedente; sus conteos 39/61 no describen el contrato actual.

39 operaciones reales y 61 solicitudes Postman v2.1, con IDs/tokens automáticos y ejemplos sanitizados. La rama `feat/v2-stabilization` conserva los contratos de `6331564` y corrige workspace adicional, undetermined y títulos CVE. Database requiere SQL007 de `feat/v2-persistent-development-database`.

## Suite completa temporal

Desde Backend, con Docker disponible y sus dependencias locales instaladas:

```bash
.venv/bin/python api-tests/v2/validate.py
.venv/bin/python api-tests/v2/run.py
.venv/bin/python api-tests/v2/run.py --installation new
.venv/bin/python api-tests/v2/probe_known_issues.py
```

Se usa PostgreSQL nuevo tmpfs y API real en loopback. NVD utiliza las capturas verificadas originales, incluido AND y descripción larga. La clave CPE fija se compara por UUID/binding/deprecated, sin elegir el primer resultado. No hay Internet/NVD live/ZAP durante el recorrido. Los secretos se generan en memoria y no se exporta un entorno con contraseñas o tokens.

Para Postman manual temporal, iniciar `.venv/bin/python api-tests/v2/run.py --serve --port 8000`, importar colección y `test.postman_environment.json`, establecer `disposable_confirmed=true` tras comprobar el contenedor propio, e introducir password solo localmente. Ejecutar carpetas 01–10 en orden. `expired_token` y `disabled_base_url` son opcionales en Postman manual: los casos se omiten si faltan; el runner automático sí los ejecuta.

## Uso en desarrollo persistente

Seguir [la guía de persistencia](../../docs/V2_PERSISTENT_DEVELOPMENT.md). Importar **persistent-development.postman_environment.json**, introducir password local privado y establecer `persistent_development_confirmed=true` al identificar esa instalación. No etiquetarla falsamente como desechable: conservar disposable_confirmed=false.

Este modo ejecuta únicamente los positivos 01–09 y omite la carpeta 10 completa (sus tres preparaciones B y 19 negativos). Crea una cuenta UUID nueva y datos propios; no borra tablas ni reinicializa PostgreSQL. Para cuentas existentes usar login y solicitudes individuales; las aserciones de primer uso no suponen un workspace único para toda cuenta existente.

El comportamiento de esa guardia se valida con `run.py --persistent-contract` sobre un PostgreSQL **temporal**: no es la prueba de retención del volumen. La retención real se prueba por separado con `python -m scripts.test_v2_persistence`, incluyendo parada/reinicio y restore a otro volumen.

## Swagger / OpenAPI

En la instalación persistente: http://127.0.0.1:8000/docs, /openapi.json y /redoc. Se comprobaron HTTP y especificación; no se declara una prueba visual de la UI nativa de Postman/Swagger.

En Swagger, registrar usuario único con contraseña privada (el ejemplo la deja vacía), hacer login y pegar solo access_token en Authorize/HTTPBearer. Usar GET workspaces para recuperar IDs. Swagger no encadena IDs: Postman sí.

`openapi.json` es OpenAPI 3.1 validado e idéntico al generador del backend. El baseline comprueba que se conservan los 39 métodos/rutas, parámetros, modelos y autenticación. 17 operaciones tienen response_model; 22 salidas continúan sin modelo estricto, con ejemplos verificados. No se añadieron endpoints de miembros, auditoría o ZAP.

## Flujo y variables

Estado → registro/login/me → workspace personal/adicional → aplicación/destino/tecnología → CPE revisado → consulta CVE → GET de estado/historial/hallazgos → revisión/recomendaciones → legado V1 separado → negativos solo temporales.

Login guarda access_token; se capturan user_id, workspace_id, additional_workspace_id, application_id, target_id, technology_id, cpe_name_id, analysis_id, finding_id, recommendation_id y sus timestamps. V1 usa asset_id/identification_id/asset_analysis_id/asset_finding_id independientes. No definir variables de entorno homónimas que oculten estas capturas de colección.

V2 procesa la página en POST 201; V1 devuelve 202 y usa worker. El polling repite GET sobre el mismo ID, nunca otro POST. Idempotency-Key identifica una intención: conservarla para reconciliar/reintentar el mismo cuerpo. Una repetición completa crea otro usuario y datos; puede alcanzar cuotas normales, por lo que hay que respetar Retry-After.

El entorno local de ejemplo habilita live solo tras `allow_live_nvd=true`. Revisar manualmente producto/versión/deprecated y completar cpe_name_id, confirmed_cpe y cpe_confirmed_manually=true antes de confirmar. No se automatiza esa decisión humana. No usar fixtures para afirmar vulnerabilidades actuales de sistemas reales.

## Instalar y regenerar

```bash
.venv/bin/python -m pip install -r api-tests/v2/requirements-api.lock
npm ci --prefix api-tests/v2 --ignore-scripts --no-fund
.venv/bin/python api-tests/v2/build.py
.venv/bin/python api-tests/v2/validate.py
.venv/bin/ruff check .
```

Las dependencias del backend/venv se preparan según la guía principal. Newman queda local, sin instalación global; se aplican seis actualizaciones transitivas compatibles con la colección. Persisten **10 avisos npm audit (5 altos, 5 moderados, 0 críticos)**; ver [clasificación completa](../../docs/V2_NEWMAN_DEPENDENCIES.md).

## Evidencia

[Matriz](MATRIZ_ENDPOINTS.md), [autenticación](AUTENTICACION.md), [ejecución](EJECUCION.md), [fixtures](FIXTURES.md), [resultados](RESULTADOS.md) y [limitaciones](LIMITACIONES.md). El JSON examples/known-issues.json conserva las observaciones históricas de 6331564, no expectativas actuales de error; probe_known_issues.py ahora ejecuta las regresiones de esas correcciones. Los logs/artefactos privados quedan ignorados en .artifacts.

La ratificación global de V2 sigue pendiente; esta rama no integra MVP-B ni se declara productiva.

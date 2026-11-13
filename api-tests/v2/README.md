# API V2 reproducible para Jesel y Rudi

39 operaciones reales y 61 solicitudes Postman Collection v2.1, con variables, ejemplos sanitizados y pruebas encadenadas. Esta rama parte de Backend `5a34f6439881f40eb9aaa931ff5777b60b62e023`; Database permanece en `0cc4dfd719463fb15eb1689a0f46550d9f204a71` y Frontend en `4514b6840b428152c1cd875c95e3e55ad81c4196`.

**Hay defectos existentes pendientes**: crear un workspace adicional devuelve 404; algunos análisis CVE fallan por incompatibilidad de `undetermined` o de un título truncado con las restricciones SQL. El workspace personal del registro funciona. Ver [LIMITACIONES.md](LIMITACIONES.md): una suite con expectativas de esos errores no significa que dichas funcionalidades funcionen.

## Ejecutar automáticamente desde esta PC

El checkout documental está en `/home/mz/Desktop/vulntrack-registration-v2/vuln-track-api-tests`, rama `test/v2-api-collection`. Docker debe estar activo. Desde una terminal:

```bash
cd /home/mz/Desktop/vulntrack-registration-v2/vuln-track-api-tests
.venv/bin/python api-tests/v2/validate.py
.venv/bin/python api-tests/v2/run.py
.venv/bin/python api-tests/v2/run.py --installation new
.venv/bin/python api-tests/v2/probe_known_issues.py
```

`run.py` crea su propio PostgreSQL en tmpfs, aplica SQL/Alembic exclusivamente allí, inicia dos API reales en loopback con puertos libres y ejecuta Newman local. El segundo servidor tiene registro deshabilitado para comprobar 503. Los secretos se generan en memoria y llegan a Node por stdin, sin argumentos de shell ni exportación de entorno. El helper detiene solo sus contenedores al salir. No hay URL de base persistente como opción.

El runner usa fixtures para las llamadas NVD: no requiere API key, Internet ni dispositivo de destino durante las pruebas. La instalación inicial de dependencias y la imagen PostgreSQL sí pueden necesitar red. Los reportes sanitizados y logs quedan en `.artifacts/`, ignorados por Git. No exportar reportes Newman convencionales con cuerpos de login o entornos resueltos.

## Importar en Postman y ejecutar por orden

1. Preparar la API de fixtures en una terminal y dejarla abierta:

   ```bash
   .venv/bin/python api-tests/v2/run.py --serve --port 8000
   ```

2. En Postman, **Import** → seleccionar `VulnTrack-V2.postman_collection.json` y `test.postman_environment.json`. Elegir el entorno test.
3. Comprobar en la terminal el nombre del contenedor desechable que creó el helper. Establecer `base_url=http://127.0.0.1:8000`, `nvd_mode=fixture` y `disposable_confirmed=true`. La bandera es una declaración del operador, no una prueba técnica de que cualquier servidor sea desechable.
4. Introducir una contraseña propia de 15–128 caracteres **solo en el valor local privado** de `password`; no compartirlo ni exportarlo. Ver [AUTENTICACION.md](AUTENTICACION.md).
5. Abrir Collection Runner, seleccionar todas las carpetas en orden 01–10 y usar 1 iteración. Para uso individual, enviar las mismas solicitudes en ese orden; el polling automático `setNextRequest` actúa en Runner/Newman.
6. `Registrar cuenta única A` genera un username por UUID. Login guarda `access_token`. Los pasos posteriores guardan workspace, aplicación, tecnología, CPE, análisis, hallazgos y demás IDs. La cuenta B comprueba aislamiento.
7. En la sesión manual, introducir `disabled_base_url` que imprime el helper si se desea probar la segunda API. El caso de token expirado se omite si falta `expired_token`; el runner automático sí lo genera y ejecuta. No se presenta la omisión manual como una prueba realizada.
8. Revisar las aserciones y cerrar la terminal con Ctrl+C al terminar: **se eliminan todas las cuentas y datos de esa demostración**.

La colección bloquea URLs distintas de `http://127.0.0.1:PUERTO` y exige confirmar el entorno desechable. No debe apuntar a bases persistentes. Si el puerto 8000 está ocupado, usar `--port 0` y copiar a `base_url` el puerto que imprima el helper.

## Swagger y ReDoc

Con el servidor anterior activo:

- Swagger UI: `http://127.0.0.1:8000/docs`.
- OpenAPI servido: `http://127.0.0.1:8000/openapi.json`.
- ReDoc: `http://127.0.0.1:8000/redoc`.

En Swagger, ejecutar `POST /api/v1/auth/register` con username único y contraseña privada (el ejemplo lleva contraseña vacía). Después ejecutar login, copiar su `access_token`, pulsar **Authorize** y pegar únicamente el token en HTTPBearer. Ejecutar me y GET workspaces. Swagger no encadena IDs automáticamente: esa comodidad está implementada en Postman. Evitar grabar respuestas de login o contraseñas en capturas/ejemplos.

Los cambios del backend son de metadatos OpenAPI: tags, descripciones, errores y ejemplos; no añaden endpoints ni cambian validación, response_model, filtros, permisos, SQL o servicios. `baseline-contract.json` congela parámetros, modelos y autenticación de la base original y `validate.py` los compara.

## NVD y confirmación humana

El candidato de fixture es el UUID documentado `c817e5ba-62c1-41e7-a15c-fb851fea761e`, Cisco RV340 firmware 1.0.0.33. El script busca **ese UUID y su binding exacto**, no la posición del primer resultado. [FIXTURES.md](FIXTURES.md) explica su procedencia y las variantes simuladas.

El entorno local de ejemplo usa `nvd_mode=live`, pero no habilita acceso en vivo automáticamente. Para una revisión manual sobre una API propia desechable, establecer `allow_live_nvd=true`, buscar candidatos, revisar producto/versión/deprecated y escribir `cpe_name_id`, `confirmed_cpe` y `cpe_confirmed_manually=true`. Solo entonces enviar la confirmación. No ejecutar toda la colección de fixtures contra datos reales: títulos/configuraciones, cuotas y número de hallazgos difieren y existen los defectos descritos. NVD en vivo no se ejecutó en esta misión.

V2 procesa la consulta dentro de POST y responde 201 al terminar; la consulta de progreso/resultados usa GET. El flujo heredado V1 acepta 202 y procesa por worker; su polling solo repite GET de la ejecución capturada, nunca crea POST adicionales.

## Preparación en un checkout nuevo

Mantener Database V2 como directorio hermano `vuln-track-database`, en su commit coordinado. El helper comprueba sus fuentes por SHA-256. Para otra ubicación usar `DATABASE_V2_PATH` apuntando al checkout V2 correcto.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.lock
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/python -m pip install -r api-tests/v2/requirements-api.lock
npm ci --prefix api-tests/v2 --ignore-scripts --no-fund
.venv/bin/python api-tests/v2/validate.py
```

Newman 6.2.3 queda dentro de `api-tests/v2/node_modules`, sin instalación global. Se probó con Node 24.12.0/npm 11.6.2 y Python 3.12.3. Su árbol de herramientas presenta avisos npm audit documentados en LIMITACIONES; no forma parte de dependencias ni imagen productivas.

Para regenerar colección, entornos, ejemplos Python y snapshot desde el catálogo y las respuestas sintéticas versionadas:

```bash
.venv/bin/python api-tests/v2/build.py
.venv/bin/python api-tests/v2/validate.py
.venv/bin/ruff check .
```

## Archivos y evidencia

- [MATRIZ_ENDPOINTS.md](MATRIZ_ENDPOINTS.md): todas las rutas, ejemplos, estados y paginación.
- [EJECUCION.md](EJECUCION.md): recorrido, variables y negativos.
- [AUTENTICACION.md](AUTENTICACION.md): secretos, JWT y aislamiento.
- [FIXTURES.md](FIXTURES.md): fuente y diferencias de NVD simulado.
- [RESULTADOS.md](RESULTADOS.md): resultados reales, incidentes y publicación.
- [LIMITACIONES.md](LIMITACIONES.md): defectos y pruebas fuera de alcance.
- `examples/responses.json`: 61 respuestas de prueba sanitizadas, con IDs ficticios y tokens vacíos.
- `examples/known-issues.json`: cuatro reproducciones de defectos existentes.
- `openapi.json`: especificación versionada, idéntica a la generada por la API de esta rama.
- `vendor/postman-collection-v2.1.schema.json`: esquema oficial para validar sin red.

La ratificación global de V2 sigue pendiente. No se mezcló MVP-B ni se modificaron Database, Frontend, Context, main o las ramas de Rudi.

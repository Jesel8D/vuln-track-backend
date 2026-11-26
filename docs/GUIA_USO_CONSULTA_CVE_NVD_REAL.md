# Guía de uso: aplicaciones y consultas CVE reales

## Qué hace este flujo

El módulo registra una aplicación, sus tecnologías y una identificación CPE
confirmada. Después consulta CVE 2.0 de NVD para ese CPE y guarda el resultado
con su fuente, fecha, modo, cobertura y procedencia de caché. La consulta no
escanea el sitio o el servidor de la aplicación: no envía tráfico a ese activo,
no ejecuta ZAP y no comprueba por sí sola que una CVE sea explotable en la
instalación concreta.

Un CPE es la identidad normalizada del producto y versión. NVD devuelve CVE
potencialmente asociadas a esa identidad. El equipo debe revisar cada CVE frente
a la versión instalada, configuración, módulos y mitigaciones antes de tratarla
como aplicable.

## Antes de empezar

1. Usa una cuenta con rol **owner** o **editor** en el workspace. Un viewer
   puede consultar información, pero no crear recursos ni iniciar análisis.
2. El backend debe estar configurado en modo `live` y con `CVE_LIVE_ENABLED=true`.
   El frontend debe compilarse con `VITE_NVD_MODE=live`. La variable del
   frontend solo cambia la interfaz; no activa el backend.
3. La máquina del backend debe poder resolver y conectar por HTTPS a
   `services.nvd.nist.gov:443`, con TLS válido. La API key es opcional y, si se
   usa, debe configurarse solo en backend. Hay cuota y límites de consultas.
4. Debe existir un catálogo CPE **live** con candidatos oficiales. Verifica
   `GET /api/v2/cpe-catalog/status?mode=live` con sesión autenticada. Busca
   `records > 0`, `source: nvd-api` o un feed oficial, y cobertura/fecha de
   sincronización coherentes. El modo live de CVE no descarga por sí solo el
   catálogo CPE.
5. La instancia local de referencia arranca en modo fixture de forma segura.
   Cuando decidas iniciarla para uso real, cambia explícitamente el modo del
   launcher a `--nvd-mode live`. No hace falta configurar un target autorizado
   para consultar CVE por CPE; la autorización de targets corresponde a otros
   análisis remotos.

## Recorrido en la interfaz

### 1. Crear o elegir un workspace y una aplicación

Inicia sesión, abre o crea un workspace y selecciona **Aplicaciones**. Registra
la aplicación con un nombre reconocible y una descripción de su función/entorno
(por ejemplo, producción, pruebas o el equipo responsable). El endpoint de alta
crea la aplicación con estado `active` por defecto. No hay que activar la
aplicación aparte para habilitar la consulta CVE.

La aplicación es el contenedor de inventario. Puede tener varios componentes;
registra cada producto y versión como una tecnología separada para no mezclar
resultados de productos distintos.

### 2. Registrar la tecnología instalada

En la aplicación, añade una tecnología con datos observados en el sistema,
inventario de paquetes, manifiesto firmado, consola de administración o
documentación del proveedor:

| Campo | Qué capturar |
| --- | --- |
| Producto | Nombre del producto identificable (no el nombre de la aplicación propia). |
| Fabricante | Nombre del proveedor como aparece en el producto o la evidencia. |
| Versión | Versión exacta instalada, incluidos sufijos relevantes. No uses `latest`, rangos ni una versión supuesta. |
| Método de detección | `manual` si la persona leyó una fuente; elige otro solo cuando esa detección realmente se hizo. |

Ejemplos de fuentes válidas: salida del gestor de paquetes, inventario del
contenedor desplegado, panel de administración o manifiesto de dependencias
asociado al build. Registra notas/evidencia de esa fuente en la revisión CPE.
No registres credenciales, tokens, secretos ni datos personales.

### 3. Buscar y confirmar el CPE oficial exacto

La tecnología recién creada todavía no está confirmada. En **Identificar CPE**,
busca fabricante y producto usando la fuente `live` y selecciona el candidato
que coincida en tipo de componente, fabricante, producto y **versión exacta**.
El sistema rechaza candidatos deprecados, comodines y versiones distintas.

Antes de confirmar, compara el nombre CPE completo (`cpe:2.3:...`) con el
producto observado. Indica un motivo y evidencia breve, por ejemplo: “versión
verificada en el inventario del build 2026.11.25”. La confirmación queda en la
auditoría con actor, fuente y datos observados. El estado cambia a CPE confirmado
solo si la selección coincide; no fuerces una coincidencia aproximada.

Si no aparece el producto, primero verifica que el catálogo live contenga datos,
que la búsqueda use el nombre/vendor CPE esperado y que el producto tenga una
versión concreta. El catálogo de demostración y el catálogo oficial son fuentes
distintas; una selección fixture no habilita consultas CVE live.

### 4. Ejecutar la consulta CVE

La aplicación debe estar activa, el usuario debe ser owner/editor, el modo debe
ser live y la tecnología debe tener un CPE de versión exacta confirmado desde
fuente live. Entonces se habilita **CONSULTA CVE EN NVD**. Al pulsar, el backend
manda `cpeName`, `startIndex=0` y `resultsPerPage` a la ruta oficial fija:

```text
POST /api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies/{technology_id}/analyses
https://services.nvd.nist.gov/rest/json/cves/2.0
```

El frontend genera una clave de idempotencia para impedir duplicar una misma
solicitud. La ejecución se guarda primero como `queued`, pasa a `running` y
termina como `completed` o `failed`. Una respuesta HTTP `201` entrega el recurso
de la ejecución. La pantalla consulta su estado y, al completar, muestra los
hallazgos guardados.

### 5. Leer resultados y confirmar aplicabilidad

Una ejecución correcta incluye, entre otros campos:

| Dato | Interpretación |
| --- | --- |
| `nvd_mode` | `live` para una consulta identificada como live. |
| `selected_cpe` | CPE exacto consultado. Verifica que corresponda a la tecnología. |
| `status` | `completed` indica que se procesó la respuesta, incluso si hubo cero coincidencias. |
| `total_results` | Coincidencias que informa NVD para la petición. Puede ser `0`. |
| `retrieved_count` / `stored_count` | CVE recibidas y persistidas. La página está limitada; revisa `coverage` y `warning_codes`. |
| `source_timestamp` | Marca de tiempo de la fuente NVD. |
| `cache_usage.resolution` | `provider` indica que se obtuvo una respuesta del proveedor en esta ejecución; `reused` indica reutilización de una respuesta previamente guardada; `failed` indica que no se resolvió. |

Un resultado vacío (`completed`, `total_results: 0`) es válido: significa que la
consulta no encontró asociaciones para ese CPE en la página/consulta ejecutada.
No demuestra que el producto sea seguro. Si la respuesta procede de caché,
conserva la fecha de obtención de origen y su caducidad; volver a pulsar antes
de expirar puede reutilizarla y no genera necesariamente otra llamada a NVD.

Cada hallazgo conserva identificador CVE, descripción, fechas y métricas
disponibles de NVD, además de la referencia a tecnología/CPE. La pantalla permite
revisar aplicabilidad. Usa `potential`, `undetermined` o `not_applicable` según
la evidencia; la acción queda auditada. No marques “aplicable” solo por una
coincidencia CPE.

## Si el botón aparece deshabilitado

Revisa en este orden:

1. **Modo frontend:** el texto debe decir “CONSULTA CVE EN NVD”, no “DE
   DEMOSTRACIÓN”. `VITE_NVD_MODE` se inserta al compilar; recompila/reinicia el
   frontend tras cambiarlo.
2. **Modo backend:** debe ser `NVD_MODE=live` y `CVE_LIVE_ENABLED=true`. Para el
   launcher local usa `--nvd-mode live`; este ajuste configura ambos valores.
3. **Permiso:** la cuenta necesita rol owner/editor y la aplicación debe estar
   `active`.
4. **CPE:** debe haber selección exacta, confirmación actual y fuente `live`.
   Cambiar producto o versión invalida la confirmación anterior.
5. **Consulta en curso:** espera a que termine la ejecución activa para esa
   tecnología.

Si está habilitado pero falla, abre el detalle de ejecución o la respuesta de
la API. Errores comunes:

| Código / resultado | Qué revisar |
| --- | --- |
| `CPE_CONFIRMATION_REQUIRED` / `CPE_PROVENANCE_REQUIRED` | Confirma de nuevo un candidato exacto desde catálogo live. |
| `CVE_LIVE_DISABLED` / `NVD_MODE_REQUIRED` | Configuración backend incompleta o backend antiguo sin reiniciar. |
| `ANALYSIS_IN_PROGRESS` | Hay otra ejecución activa para esa tecnología. |
| `429` o `Retry-After` | Presupuesto/cuota NVD; espera el tiempo indicado, evita reintentos repetidos y configura API key solo en backend si corresponde. |
| `503` / `NVD_PROCESSING_FAILED` | Revisa conectividad de salida, DNS, TLS, disponibilidad NVD y logs sanitizados del backend. No se cambia a fixture automáticamente. |
| `coverage: partial` / `PAGE_BUDGET_REACHED` | Se alcanzó el límite de página del producto; la pantalla conserva el aviso y no debe presentarse como cobertura total. |

## Rutas útiles

Requieren autenticación Bearer y workspace accesible; el análisis y la
confirmación requieren rol de escritura:

```text
GET  /api/v2/workspaces
POST /api/v2/workspaces/{workspace_id}/applications
POST /api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies
GET  /api/v2/workspaces/{workspace_id}/applications/{application_id}/cpe-candidates?technology_id={technology_id}&query={texto}&mode=live
PUT  /api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies/{technology_id}/cpe
POST /api/v2/workspaces/{workspace_id}/applications/{application_id}/technologies/{technology_id}/analyses
GET  /api/v2/workspaces/{workspace_id}/applications/{application_id}/analyses/{analysis_id}
GET  /api/v2/workspaces/{workspace_id}/applications/{application_id}/findings?analysis_id={analysis_id}
GET  /api/v2/cpe-catalog/status?mode=live
```

Los cuerpos exactos y el esquema autenticado están disponibles en Swagger en
`/docs`. No copies UUID de fixtures como si fueran identificadores propios.

## Límite de verificación de esta guía

Se corrigió el launcher local para que `--nvd-mode live` habilite tanto el
cliente CVE como el modo NVD, y esta guía describe el contrato observado en el
código. La instancia no se ha iniciado ni se ha realizado una llamada de red
real desde este entorno. Por ello siguen pendientes de comprobar en tu máquina:
conectividad a NVD, disponibilidad de un catálogo CPE live, respuesta de una CVE
real y persistencia tras consultar. Solo esa ejecución puede confirmar esos
últimos puntos; un fixture o una respuesta de caché no prueba una llamada nueva.

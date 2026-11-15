# Clasificación de avisos Newman — 2026-11-13

Los **19 avisos iniciales son entradas de vulnerabilidad de npm audit**, no 19 deprecaciones ni necesariamente 19 CVE diferentes. Diez paquetes contienen avisos propios y nueve son entradas propagadas por sus dependencias. Newman es la única dependencia directa de este paquete de pruebas; las otras 18 entradas son transitivas. El backend productivo no depende de Newman ni de este árbol node_modules.

| Paquete | Severidad inicial | Alcance / clase | Tras actualización | Referencia o cadena |
|---|---|---|---|---|
| `@faker-js/faker` | high | Transitiva; Aviso propio | Pendiente | [GHSA](https://github.com/advisories/GHSA-qxc2-j82w-r537) |
| `csv-parse` | moderate | Transitiva; Aviso propio | Pendiente | [GHSA](https://github.com/advisories/GHSA-8cw4-87c7-c6xx) |
| `flatted` | high | Transitiva; Aviso propio | Ya no reportada | [GHSA](https://github.com/advisories/GHSA-25h7-pfq9-p65f); [GHSA](https://github.com/advisories/GHSA-rf6f-7fwh-wjgh) |
| `handlebars` | critical | Transitiva; Aviso propio | Ya no reportada | [GHSA](https://github.com/advisories/GHSA-3mfm-83xf-c92r); [GHSA](https://github.com/advisories/GHSA-2w6w-674q-4c4q) |
| `httpntlm` | high | Transitiva; Metavulnerabilidad heredada | Ya no reportada | Cadena transitiva: underscore |
| `jose` | moderate | Transitiva; Aviso propio | Pendiente | [GHSA](https://github.com/advisories/GHSA-hhhv-q57g-882q) |
| `lodash` | high | Transitiva; Aviso propio | Ya no reportada | [GHSA](https://github.com/advisories/GHSA-r5fr-rjxr-66jc); [GHSA](https://github.com/advisories/GHSA-xxjr-mmjv-4gpg) |
| `newman` | high | Directa de la herramienta; Metavulnerabilidad heredada | Pendiente | Cadena transitiva: csv-parse, lodash, postman-collection, postman-collection-transformer, postman-request, postman-runtime, serialised-error |
| `node-forge` | high | Transitiva; Aviso propio | Ya no reportada | [GHSA](https://github.com/advisories/GHSA-554w-wpv2-vw27); [GHSA](https://github.com/advisories/GHSA-5gfm-wpxj-wjgq) |
| `postman-collection` | high | Transitiva; Metavulnerabilidad heredada | Pendiente | Cadena transitiva: @faker-js/faker, lodash, uuid |
| `postman-collection-transformer` | high | Transitiva; Metavulnerabilidad heredada | Ya no reportada | Cadena transitiva: lodash |
| `postman-request` | moderate | Transitiva; Metavulnerabilidad heredada | Pendiente | Cadena transitiva: qs, uuid |
| `postman-runtime` | high | Transitiva; Metavulnerabilidad heredada | Pendiente | Cadena transitiva: handlebars, httpntlm, jose, lodash, node-forge, postman-collection, postman-request, postman-sandbox, serialised-error, uuid |
| `postman-sandbox` | high | Transitiva; Metavulnerabilidad heredada | Pendiente | Cadena transitiva: lodash, postman-collection, uvm |
| `qs` | moderate | Transitiva; Aviso propio | Ya no reportada | [GHSA](https://github.com/advisories/GHSA-6rw7-vpxm-498p); [GHSA](https://github.com/advisories/GHSA-q8mj-m7cp-5q26) |
| `serialised-error` | moderate | Transitiva; Metavulnerabilidad heredada | Pendiente | Cadena transitiva: uuid |
| `underscore` | high | Transitiva; Aviso propio | Ya no reportada | [GHSA](https://github.com/advisories/GHSA-qpx9-hpmf-5gmw) |
| `uuid` | moderate | Transitiva; Aviso propio | Pendiente | [GHSA](https://github.com/advisories/GHSA-w5hq-g745-h8pq) |
| `uvm` | high | Transitiva; Metavulnerabilidad heredada | Ya no reportada | Cadena transitiva: flatted |

## Actualización limitada y comprobada

Se mantiene Newman **6.2.3**, versión estable consultada en el registro. Se fijaron únicamente seis dependencias transitivas dentro de su misma versión mayor: handlebars 4.7.10, node-forge 1.4.3, flatted 3.4.4, qs 6.17.1, underscore 1.13.8 y lodash 4.18.1. Quedaron registradas con package-lock y [overrides de npm](https://docs.npmjs.com/cli/configuring-npm/package-json/); no se ejecutó audit fix --force ni se cambiaron herramientas.

Resultado de audit: **19 → 10 entradas**; antes 6 moderadas/12 altas/1 crítica, después **5 moderadas/5 altas/0 críticas**. Se verificaron los recorridos Newman completos y el modo persistente positivo con estas versiones. Eso demuestra compatibilidad con esta colección revisada, no con cualquier colección o todas las funciones de Newman.

Permanecen avisos propios en faker, csv-parse, jose y uuid, más seis cadenas heredadas. No se impusieron versiones mayores que cambiarían API/compatibilidad de consumidores transitivos no revisados. El riesgo no se considera eliminado: usar exclusivamente esta colección confiable, loopback, fixtures y sin cargar scripts de terceros. No se incorpora la herramienta a la imagen de API ni se instala globalmente.

## Avisos distintos que no forman parte de esos 19

- npm deprecated de uuid antiguos/faker/har-validator: aviso de mantenimiento de librerías heredadas; no es por sí mismo una vulnerabilidad adicional.
- Node DEP0176 (fs.F_OK): deprecación/compatibilidad de API Node usada por la herramienta, no un resultado npm audit.
- Starlette/TestClient/httpx2: deprecación del cliente Python de pruebas; pertenece a otro árbol de dependencias.

Fuentes: npm audit --json y npm view obtenidos en esta ejecución, package-lock versionado y enlaces GHSA de los avisos. Los reportes completos sin secretos quedan en .artifacts y el resumen público en examples/tooling-audit-summary.json. No se declara libre de vulnerabilidades al conjunto.

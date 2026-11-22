# Rendimiento de búsqueda en RC2.3

Medición HTTP autenticada en `127.0.0.1:8012`, con PostgreSQL 16.15 y **1 880 952 CPE oficiales**. Se ejecutó un calentamiento de cada consulta y luego 60 solicitudes, 10 por patrón, con cuatro trabajadores y límite de ocho resultados. Los tiempos incluyen la aplicación y PostgreSQL. Todas las solicitudes devolvieron HTTP 200 con resultados.

| Consulta | Parámetros de la medición | p50 (ms) | p95 (ms) |
|---|---|---:|---:|
| Fabricante por prefijo | `cis`, parte `o` | 44,14 | 60,75 |
| Familia | Apache, `http`, parte `a` | 19,66 | 42,60 |
| Versiones concretas del producto | Canonical, Ubuntu Linux, parte `o` | 12,49 | 18,30 |
| Título descriptivo | `windows server`, parte `o` | 42,78 | 70,01 |
| Referencias de hardware | Dell, `poweredge`, parte `h` | 16,41 | 23,69 |
| CPE íntegro | Cisco RV340, coincidencia canónica y vigente | 13,19 | 35,09 |
| **Total** | **60 solicitudes** | **18,58** | **50,02** |

El estado del catálogo se obtuvo en **15,80 ms** en una solicitud. Antes del resumen, durante la carga, el cálculo de los conteos sobre 390 544 filas tardó 1 328,78 ms en una solicitud. Son observaciones de fases distintas, con diferentes volúmenes y concurrencia.

## Límites de trabajo

La búsqueda usa índices para identificadores exactos, prefijos, familias y texto normalizado. Cada consulta admite hasta 30 resultados por página y expone una ventana de 500 coincidencias. La fila 501 permite señalar que el usuario debe refinar la búsqueda. Las consultas de listado tienen un límite de ejecución SQL de dos segundos. El estado usa el resumen calculado al finalizar la sincronización y el progreso se lee de su recibo transaccional. El navegador consulta PostgreSQL a través de la API local.

El ensayo mide estos filtros con caché caliente en un equipo WSL2. Los tiempos no representan garantías para filtros distintos ni sustituyen una prueba de capacidad multiusuario.

[Conteos del catálogo](V2_RC23_CATALOG_COVERAGE.md) · [Regresión](V2_RC23_TEST_REPORT.md)

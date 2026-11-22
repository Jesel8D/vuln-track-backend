# Importación del diccionario CPE en RC2.3

RC2.3 usa el diccionario oficial de productos de NVD. El feed `nvdcpe-2.0.tar.gz` contiene fragmentos JSON según el contrato de la API de productos. El primer miembro observado fue `nvdcpe-2.0-chunks/nvdcpe-2.0-chunk-00001.json`. Las entradas conservan el UUID y la cadena CPE original. Los criterios CPE Match expresan coincidencias abstractas. Los identificadores CVE y sus configuraciones describen vulnerabilidades y condiciones de aplicabilidad. [Documentación del diccionario](https://nvd.nist.gov/products/cpe) · [Actualización de formatos de NIST](https://www.nist.gov/itl/nvd)

## Preflight

El primer intento se bloqueó en el preflight porque el disco físico C: tenía menos de 1 GB libre. El disco virtual de Ubuntu y el de Docker se alojan allí. El espacio lógico anunciado por el sistema de archivos de WSL tampoco describe el espacio disponible para expandir esos discos. Durante la continuación del 22 de noviembre, el preflight de RC2.3 registró:

| Medida | Resultado |
|---|---:|
| C: disponible | 6 914 379 776 bytes |
| WSL disponible | 1 017 710 047 232 bytes |
| Sistema de archivos del volumen Docker disponible | 1 018 256 527 360 bytes |
| Memoria disponible | 14 023 593 984 bytes |
| Memoria total reportada por Docker | 16 730 943 488 bytes |
| Presupuesto estimado de disco | 6 110 990 354 bytes |
| Presupuesto estimado de memoria | 2 098 032 238 bytes |

PostgreSQL 16.15 estaba listo y la migración era compatible. La estimación de disco contempla el archivo comprimido, seis veces los bytes JSON para almacenamiento e índices con margen de WAL y una reserva de 512 MiB. La importación vuelve a medir los recursos en cada invocación y comprueba el espacio físico tras cada lote.

## Descarga, verificación y reanudación

- El operador elige `preflight`, `stage`, `import` o `stats`. Se exige el perfil RC2.3 y su volumen verificado.
- `stage` descarga y valida el archivo. La URL de origen es fija y usa HTTPS. La descarga parcial se guarda bajo el SHA-256 publicado y se recupera con HTTP Range cuando el servidor devuelve el intervalo correcto.
- El TAR se recorre en streaming. Se comprueban nombres consecutivos, límites por miembro, padding y terminación. Se rechazan enlaces, rutas ajenas y tipos especiales. Los miembros se leen como flujos, sin extraer archivos.
- El verificador valida la estructura de los fragmentos, el conteo total, el tamaño y el SHA-256 de sus JSON concatenados, en orden de archivo. Se exige la coincidencia antes de escribir en PostgreSQL.
- La carga normaliza filas en lotes de 500. COPY usa una tabla temporal y el UPSERT usa modo y UUID. El checkpoint se actualiza en la misma transacción. Al reanudar, se vuelve a verificar el archivo y se recorren las entradas ya procesadas sin volver a escribirlas.
- El diccionario no actualiza dispositivos ni identificaciones confirmadas. Los análisis retienen su CPE y versión originales.

El META de esta edición anunció 85 329 096 bytes comprimidos, 914 798 391 bytes JSON y el SHA-256 `770fb8040e62e9e9249265997b6bdc15b516f4f1b0004bdf0236354e1425f6bd`. La descarga oficial coincidió con esos valores y se verificaron **1 880 953 entradas de origen**. [META oficial](https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.meta) · [Feeds de NVD](https://nvd.nist.gov/vuln/data-feeds)

## Ejecución real

| Medida | Resultado |
|---|---:|
| Descarga y primera verificación | 32,37 s |
| Importación con segunda verificación | 505,96 s |
| Entre el primer recibo y el checkpoint final en PostgreSQL | 478,94 s |
| Memoria máxima RSS del importador | 141 084 KiB |
| Catálogo en PostgreSQL con índices y TOAST | 2 694 914 048 bytes |
| Base PostgreSQL después de la carga | 2 711 510 039 bytes |
| C: disponible al completar el último lote | 3 759 652 864 bytes |
| C: disponible después de reiniciar y generar estadísticas | 3 557 879 808 bytes |

El recibo quedó en `complete` para las **1 880 953 entradas procesadas**. Se materializaron **1 880 952 CPE oficiales**, con un descarte y cero omisiones. La migración aditiva del resumen se aplicó a este volumen y el reinicio conservó el recibo y sus conteos. [Cobertura](V2_RC23_CATALOG_COVERAGE.md)

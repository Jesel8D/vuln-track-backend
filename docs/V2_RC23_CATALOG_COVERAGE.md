# Cobertura del catálogo CPE en RC2.3

Conteo consultado en PostgreSQL después del reinicio del perfil `rc2-catalog23`. La edición de origen se publicó el **20 de noviembre de 2026 a las 23:50:01 UTC−05:00**. El último lote se confirmó el **22 de noviembre de 2026 a las 12:10:31**, hora de Ciudad de México.

| Medida oficial | Valor |
|---|---:|
| Entradas verificadas y procesadas de la edición | 1 880 953 |
| CPE almacenados con fuente `nvd-feed` | 1 880 952 |
| UUID omitidos por duplicado o copia más reciente | 0 |
| Registros descartados por validación | 1 |
| Fabricantes distintos | 25 206 |
| Familias distintas por parte, fabricante y producto | 154 738 |
| Versiones concretas distintas por familia | 1 519 280 |
| CPE de parte `a` | 1 667 187 |
| CPE de parte `h` | 65 065 |
| CPE de parte `o` | 148 700 |
| CPE deprecados | 102 729 |
| Fixture almacenado aparte | 1 |

Las versiones concretas excluyen `*`, `-` y `?`. Las partes se leen del CPE. La interfaz conserva la categoría administrativa que el usuario asigna al dispositivo. El recibo completó su recorrido y la cobertura de almacenamiento se muestra como parcial debido al descarte. La edición describe identificadores registrados en NVD. La cobertura de modelos físicos y de sistemas instalados sigue siendo desconocida, y cada análisis de vulnerabilidades requiere su propia evidencia de aplicabilidad. [Definición del diccionario de NVD](https://nvd.nist.gov/products/cpe)

## Muestra verificada

Estos títulos y nombres se consultaron en PostgreSQL. Las cinco filas estaban vigentes y tenían procedencia `nvd-feed`.

| Uso de la muestra | Título oficial | CPE |
|---|---|---|
| Firmware de red | Cisco Small Business RV340 Firmware 1.0.0.30 | `cpe:2.3:o:cisco:small_business_rv340_firmware:1.0.0.30:*:*:*:*:*:*:*` |
| Software de red | Juniper JUNOS 22.4 R3-S9 | `cpe:2.3:o:juniper:junos:22.4:r3-s9:*:*:*:*:*:*` |
| Sistema operativo | Canonical Ubuntu Linux 24.10 | `cpe:2.3:o:canonical:ubuntu_linux:24.10:*:*:*:-:*:*:*` |
| Software de servidor | Apache Software Foundation Apache HTTP Server 2.4.70 | `cpe:2.3:a:apache:http_server:2.4.70:*:*:*:*:*:*:*` |
| Referencia de hardware | Dell PowerEdge R740 | `cpe:2.3:h:dell:poweredge_r740:-:*:*:*:*:*:*:*` |

El registro descartado fue el UUID `38B903E9-19BB-4C83-BDF4-D90A0E71838D`, posición 133 537 de la edición. La validación de CPE rechazó `premium` en el campo de idioma de `cpe:2.3:a:ipswitch:whatsup:2006:-:professional:premium:*:*:*:*`. El archivo verificado conserva esa entrada de origen.

## Reproducir los conteos

Ejecuta este comando desde el Backend del perfil aislado.

```bash
.venv/bin/python -m scripts.import_cpe_feed stats
```

El comando agrupa los registros por procedencia y parte y calcula las familias, versiones, deprecaciones y el tamaño de las tablas. `/api/v2/cpe-catalog/status` devuelve un resumen por modo y el recibo de importación con su progreso.

[Importación e integridad](V2_RC23_FULL_CPE_IMPORT.md) · [Medición de búsquedas](V2_RC23_SEARCH_PERFORMANCE.md)

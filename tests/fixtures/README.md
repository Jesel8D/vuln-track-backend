# Fixtures CPE verificadas

Capturadas el 2026-11-08 America/Mexico_City (timestamps de origen en UTC
2026-11-09). Sin API key; no se siguieron los enlaces `refs`.

- `nvd_cpe_verified.json`: respuesta completa de
  https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeNameId=C817E5BA-62C1-41E7-A15C-FB851FEA761E
- `nvd_cpe_alternative_verified.json`: respuesta completa de
  https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeNameId=91AA8DDC-A5D4-4FD9-A5EF-5C7B03A5FAE3

Los tests crean variantes **simuladas** para errores, deprecación, vacíos,
paginación y productos incompatibles. No se presentan como respuestas NVD reales.
El transporte HTTP real está bloqueado automáticamente en pytest; solo se permite
MockTransport. La vigencia del diccionario debe revalidarse al confirmar en uso real.

La captura exacta por UUID y una consulta posterior del cliente NVD implementado
respondieron correctamente. Una captura de búsqueda general agotó su timeout;
no se guardó ni se considera evidencia de búsqueda en vivo.

## CVE verificado para MVP-B

`nvd_cve_verified.json`: captura íntegra el 2026-11-08 America/Mexico_City,
timestamp NVD `2026-11-09T05:15:22.760`, sin key, consulta limitada a una página:
https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe%3A2.3%3Ao%3Acisco%3Asmall_business_rv340_firmware%3A1.0.0.33%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A&startIndex=0&resultsPerPage=1

Informó 1 y devolvió 1: CVE-2017-6784, estado Modified, múltiples métricas,
configuraciones AND firmware + hardware. La muestra demuestra que el criterio
firmware por sí solo no basta para descartar las condiciones de hardware:
el evaluador MVP-B devuelve undetermined. No se consultó ningún dispositivo,
referencia ni prueba de explotación. No es una afirmación sobre un activo real.
`tests/cve_support.py` genera variantes simuladas, incluso identificadores de
CVE de prueba y OR simples; no se presentan como otros registros reales.

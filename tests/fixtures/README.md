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

# Integridad del catálogo oficial

La edición del 20 de noviembre de 2026 23:50:01 UTC−05:00 se revalidó desde el TAR conservado. Sus 85 329 096 bytes comprimidos representan 914 798 391 bytes de JSON. El SHA-256 de los JSON concatenados fue `770fb8040e62e9e9249265997b6bdc15b516f4f1b0004bdf0236354e1425f6bd`. El recibo registra **1 880 953 procesados**, **1 880 952 aceptados**, **1 rechazo**, cero omisiones y checkpoint final completo. La restauración conservó los UUID, la procedencia, fechas, estados y huella del catálogo.

## Registro rechazado

- UUID `38b903e9-19bb-4c83-bdf4-d90a0e71838d`, ordinal 133 537.
- CPE literal `cpe:2.3:a:ipswitch:whatsup:2006:-:professional:premium:*:*:*:*`.
- El título oficial es «Ipswitch WhatsUp 2006 Professional Edition Premium», con idioma `en`. El valor `premium` aparece en el séptimo componente del CPE, el campo de idioma, después de `edition=professional`. El enlace de referencia y el título se conservan como JSON.
- El esquema JSON de la API declara `cpeName` y `titles[].lang` como cadenas sin patrón de idioma. El binding de NIST exige para el idioma del CPE los valores lógicos o el código de dos o tres letras con región opcional. El parser local aplica ese requisito y una consulta pública acotada por UUID devolvió la misma cadena con HTTP 200. [Esquema JSON de NVD](https://csrc.nist.gov/schema/nvd/api/2.0/cpe_api_json_2.0.schema) · [NISTIR 7695, §6.2 y figura 6-3](https://doi.org/10.6028/NIST.IR.7695)

La cuarentena conserva el JSON original, el ordinal, la razón, la edición y la fecha. El operador solo puede registrar el caso tras verificar el digest, detectar el mismo error y comprobar el recibo. El identificador inválido permanece ausente de los candidatos, las confirmaciones y las consultas CVE. El rol de aplicación carece de permiso de lectura o escritura sobre la cuarentena. El proceso es idempotente y deja los historiales intactos.

La contabilidad de la edición suma **1 880 952 aceptados + 1 en cuarentena**. La cobertura consultable sigue parcial por el rechazo. Ningún idioma se infiere del nombre comercial.

[Actualizaciones y deprecación](V2_RC24_NVD_MAINTENANCE.md)

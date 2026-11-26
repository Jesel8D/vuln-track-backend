# Consultas CVE reales por CPE confirmado

## Alcance

El backend puede consultar la API CVE 2.0 de NVD para un CPE seleccionado y
confirmado por una persona. El resultado indica CVE potencialmente relacionados;
no demuestra que la versión esté instalada, que el activo sea explotable ni que
haya ocurrido un escaneo. Este flujo no ejecuta ZAP, pruebas activas ni tráfico
hacia los activos inventariados.

La ruta consultada es fija: `https://services.nvd.nist.gov/rest/json/cves/2.0`.
Solo se envían `cpeName`, `startIndex` y `resultsPerPage`; nunca se siguen
referencias recibidas en la respuesta.

## Activación local

La capacidad está apagada por defecto. En el `.env` privado del backend:

```dotenv
NVD_MODE=live
CVE_LIVE_ENABLED=true
# Opcional: clave NVD exclusivamente del backend
NVD_API_KEY=
```

Configura el entorno público de compilación del frontend con
`VITE_NVD_MODE=live` y su URL habitual de API, después recompila/reinicia la
aplicación. La variable del frontend solo cambia la interfaz; no habilita el
backend. El backend exige ambas variables de activación y sigue aplicando
autenticación, rol owner/editor, aislamiento del workspace y confirmación CPE.

El punto de entrada de producción `app/production.py` continúa rechazando
cualquier modo NVD externo y mantiene desactivado el worker. No despliegues CVE
live en producción sin revisar salida de red, configuración del worker y cuota
global compartida para todas las réplicas.

## Protección de la conexión

`app/integrations/nvd_pinned_transport.py` resuelve únicamente el host oficial,
rechaza respuestas DNS no públicas y conecta a una IP validada y fijada para esa
solicitud. Conserva el nombre oficial en `Host` y TLS SNI para validar el
certificado. El transporte usa validación TLS, no lee proxies del entorno, no
admite redirecciones, reintentos del transporte, HTTP/2, hosts ni rutas
configurables. También comprueba que la IP del peer sea la fijada.

`cve_transport.py` conserva parámetros CPE/paginación validados, límite de
respuesta de 2 MiB, límite por ejecución de 10 MiB/15 solicitudes/5 páginas/500
registros/300 s, tiempo máximo HTTP de 10 s, una consulta concurrente y espera
mínima compartida de 7 s por proceso. NVD_API_KEY no se registra y no eleva esos
límites. Los límites de cuota son por proceso; la configuración desplegada debe
mantener una sola API/worker con salida hasta implementar cuota distribuida.

El caché es aislado por workspace y conserva procedencia/frescura. Las
coincidencias se presentan como indicios sujetos a revisión. Un CVE no se
convierte en hallazgo confirmado solo por estar asociado al CPE.

## Verificación pendiente

El cambio habilita el transporte, pero no se ha iniciado Docker ni la instancia
ni se hizo una consulta externa desde esta estación. Por lo tanto, DNS, firewall,
TLS con el servicio actual, cuota de la cuenta y respuesta real siguen pendientes
de verificarse en el entorno del usuario. Mantener la capacidad apagada hasta que
la instancia pueda probarse. La conexión real no debe declararse verificada por
un fixture, un caché o una respuesta simulada.

La validación del esquema oficial local se conserva en
`tests/fixtures/nvd_cve_api_2_2_4.schema.json`; no reemplaza una respuesta real.

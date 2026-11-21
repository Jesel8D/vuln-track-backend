# NVD bajo demanda en RC2

En el launcher el modo predeterminado es fixture. `--nvd-mode live` es una
elección explícita de arranque del perfil. Un despliegue directo de FastAPI
requiere `NVD_MODE=live` para abrir el transporte público. Los fixtures inyectan
MockTransport en CPE y CVE y conservan el AND original para la demo. El aviso
autenticado identifica el modo activo. Cada nueva ejecución V2 guarda su modo.
El historial de aplicaciones identifica como desconocida la procedencia de las
ejecuciones anteriores sin marca. En el dashboard web se puede elegir fixture,
live o procedencia sin registrar.

Se contrastaron las referencias oficiales [CPE 2.0](https://nvd.nist.gov/developers/products),
[CVE 2.0](https://nvd.nist.gov/developers/vulnerabilities) y
[recomendaciones de uso](https://nvd.nist.gov/developers/start-here).
Las únicas URL de transporte son HTTPS en `services.nvd.nist.gov`, rutas
`/rest/json/cpes/2.0` y `/rest/json/cves/2.0`. El cliente fija el origen,
valida TLS, desactiva redirecciones y proxies heredados, acota cuerpo a 2 MiB
y valida esquema/paginación. La clave opcional viaja en el header apiKey,
exclusivo del Backend. Si no existe se aplica el mismo presupuesto conservador.

CPE y CVE comparten cuota de proceso y espaciado de siete segundos.
Se limita la admisión por usuario. 403 y 429 aplican cooldown y respetan
Retry-After. El cliente no reintenta esos estados en la misma operación.
En live puede intentar una segunda vez tras error de transporte o 5xx
transitorio sin una espera de servidor larga. CVE de dispositivos y aplicaciones
V2 toman hasta 100 resultados en una página. Si NVD anuncia más, se conserva
cobertura parcial y su aviso. Se mantienen las reglas de presupuesto del
worker histórico V1. No hay scheduler ni replicación del catálogo.

Para clave opcional, el operador puede crear `.local/rc2/nvd-api-key` desde
una terminal privada con modo0600. El launcher solo la lee cuando el API arranca
en live. Evitar poner claves en comandos visibles o en variables VITE.
El acceso controlado al catálogo NVD es independiente de ZAP y de la verificación
remota de destinos, que permanecen bloqueados. La etiqueta «NVD en vivo» describe
el modo de la nueva consulta, y cada fila de historial indica su propia fuente.

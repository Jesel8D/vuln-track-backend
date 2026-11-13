# Fixtures NVD y ausencia de escaneo

La procedencia original está documentada en [tests/fixtures/README.md](../../tests/fixtures/README.md). Las capturas se obtuvieron el 2026-11-08 en America/Mexico_City, con timestamps de origen del 2026-11-09. No se renuevan ni se presentan como datos actuales.

- CPE original: [nvd_cpe_verified.json](../../tests/fixtures/nvd_cpe_verified.json), UUID `C817E5BA-62C1-41E7-A15C-FB851FEA761E`, binding `cpe:2.3:o:cisco:small_business_rv340_firmware:1.0.0.33:*:*:*:*:*:*:*`.
- CVE original: [nvd_cve_verified.json](../../tests/fixtures/nvd_cve_verified.json), CVE-2017-6784, con condiciones AND firmware/hardware y descripción larga.

`run.py` reemplaza exclusivamente el transporte HTTP de los clientes NVD por MockTransport, que solo reconoce el origen services.nvd.nist.gov y las dos rutas de APIs usadas. Auth, SQLAlchemy, Alembic, workspace HMAC, RLS, worker y endpoints siguen siendo los reales. No hay rutas de prueba añadidas ni respuestas de autenticación interceptadas.

El perfil positivo predeterminado es una **variante SIMULADA**: sustituye las configuraciones CVE por OR con el CPE literal verificado y cambia la descripción por un título corto expresamente etiquetado. Así produce applicability potential y permite revisar hallazgos/recomendaciones. No se presenta esa variante como otra respuesta real de NVD ni demuestra aplicabilidad a un sistema real.

El original AND produce undetermined en el evaluador, pero SQL V2 lo rechaza; la descripción original truncada a 500 termina en espacio y también viola un CHECK. `probe_known_issues.py` comprueba ambos fallos por separado, además del bloqueo del workspace adicional y la revisión undetermined. Ver [examples/known-issues.json](examples/known-issues.json). No se han corregido quitando controles ni se han ocultado con la variante positiva.

El reloj de cuotas NVD del transporte simulado avanza para no esperar tiempos externos. No prueba cuotas/spacing de NVD real. El registro del helper usa 10 intentos/IP/min y 100 totales/min para este recorrido; no cambia los valores normales 3/20 de la API. El worker asíncrono de activos V1 se activa únicamente en este servidor desechable.

No se siguen referencias de los CVE, no se consulta ningún dispositivo y no se ejecuta ZAP. El destino de ejemplo `http://127.0.0.1:8080` se guarda como inventario y se marca rechazado; no se realiza solicitud HTTP hacia él ni se finge una aprobación de propiedad.

Los ejemplos guardados sustituyen UUID privados y fechas por valores sintéticos coherentes, usernames por api_example y tokens por vacío. El UUID CPE y CVE públicos se conservan. Las respuestas son ilustrativas de los fixtures y no evidencia sobre activos de Jesel, Rudi u otros usuarios.

Los hashes dentro de la evidencia ilustrativa no deben usarse para verificar un registro reconstruido a partir de estos ejemplos sanitizados: UUID y fechas se sustituyeron para publicación. Las verificaciones de integridad reales pertenecen a las respuestas procesadas durante las pruebas, no a esa representación modificada.

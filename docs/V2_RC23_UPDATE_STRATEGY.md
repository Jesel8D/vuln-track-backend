# Actualizaciones incrementales

La carga inicial incorpora una edición de CPE desde el TAR oficial. El operador puede mantener familias seleccionadas mediante la API CPE 2.0. La sincronización sigue siendo explícita y respeta el presupuesto compartido del cliente live. Los parámetros `--modified-from` y `--modified-through` requieren zona horaria y una ventana de hasta 120 días. Se recomienda cerrar intervalos antes de avanzar al siguiente y solapar un margen breve. [API de productos NVD](https://nvd.nist.gov/developers/products)

El recibo registra el filtro, la ventana, el total devuelto, la página, los nuevos UUID, los originales modificados, las deprecaciones incorporadas y los descartes. Un registro revalidado puede conservar exactamente los mismos datos. El UPSERT preserva las filas locales más recientes. Los fallos conservan el último offset y las páginas ya confirmadas.

En RC2.3 se probó una ventana real de dos minutos alrededor de la modificación NVD más reciente de Cisco Small Business RV340 Firmware. NVD devolvió 4 entradas, todas revalidadas. Hubo 0 nuevos UUID, 0 cambios de contenido y 0 deprecaciones incorporadas. Las regresiones simularon reanudación tras HTTP 429 y deprecación con reemplazo.

Para una nueva edición, se compara el SHA-256 del META con los recibos ya completados. La adquisición de un feed nuevo es una operación de catálogo. Las consultas CVE siguen siendo independientes y requieren una identidad confirmada.

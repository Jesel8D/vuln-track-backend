# Registro asistido de dispositivos

1. En Dispositivos, elegir tipo funcional router, switch o servidor. Registrar fabricante, modelo físico y ubicación según el inventario de la organización.
2. Seleccionar el tipo de componente. Firmware y sistema operativo muestran CPE con parte `o`, software `a` y hardware `h`. La parte describe el componente y la categoría de dispositivo se selecciona de forma independiente.
3. Elegir fuente NVD oficial sincronizada o captura NVD de demostración. Cada selector consulta únicamente la API de VulnTrack. Buscar fabricante, producto y versión. Las listas usan debounce de 275 ms, paginación y teclado.
4. Seleccionar un CPE exacto. Comparar el código completo y el título. Revisar estado deprecado y reemplazos. Los CPE deprecados pueden consultarse como referencia y su confirmación queda bloqueada.
5. Marcar que el producto y la versión corresponden a lo observado. Escribir el motivo y guardar. Si el catálogo cambió durante el proceso, la API solicita volver a seleccionar. El formulario conserva sus datos ante errores de búsqueda o guardado.
6. En el detalle, abrir el historial y usar la consulta CVE solo con un CPE confirmado en el modo activo. Las cifras y condiciones de aplicabilidad requieren revisión humana.

Si el equipo o el componente están fuera del alcance, usar **Registrar sin CPE**. Se pueden indicar fabricante, producto y versión del componente cuando se conozcan. Las omisiones se guardan como null. El activo queda **Pendiente de identificación CPE** y la consulta CVE permanece bloqueada hasta una confirmación válida.

Dentro del formulario se conserva la selección al cerrar, buscar o paginar un desplegable. Cambiar de fuente, fabricante o familia invalida las selecciones dependientes. El formulario presenta carga, vacío, error con reintento y aviso de última sincronización. El catálogo se vuelve a consultar desde PostgreSQL al vencer el caché de UI.

## API

Los GET bajo `/api/v2/cpe-catalog` incluyen `status`, `vendors`, `products`, `versions`, `candidates` y `candidates/{cpe_name_id}`. Manejan `mode=live|fixture`. Los resultados de listas tienen `items`, `page` y `mode`. Filtros por fabricante, familia, parte y versión dependen de la ruta.

El alta usa `POST /api/v2/workspaces/{workspace_id}/devices`. El modo asistido añade `catalog_selection` con `cpe_name_id`, `expected_cpe_name`, `expected_nvd_modified`, `mode`, `confirmed: true` y `reason`. Enviar `Idempotency-Key` con UUID. La respuesta 201 incluye el dispositivo e `current_identification`. El contrato manual sigue aceptando registros sin ese objeto. Los ejemplos, límites y estados HTTP están en OpenAPI.

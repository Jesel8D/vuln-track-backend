# Inventario de dispositivos RC2

Desde el menú Dispositivos se registran routers, switches y servidores, con
búsqueda por fabricante/modelo y filtros de tipo y estado. La ficha distingue
el equipo físico del fabricante y producto principal consultado. El producto
se declara manualmente y puede ser firmware, sistema operativo, software o
hardware. Versión desconocida se guarda como null y bloquea confirmación y
consulta, aunque se pueden buscar candidatos.

Ejemplo de alta con sesión de owner/editor:

```http
POST /api/v2/workspaces/{workspace_id}/devices
Content-Type: application/json
```

```json
{
  "device_type": "router",
  "manufacturer": "Cisco",
  "model": "RV340",
  "component_kind": "firmware",
  "product_vendor": "cisco",
  "product": "small_business_rv340_firmware",
  "version": "1.0.0.33",
  "site_label": "Laboratorio ficticio"
}
```

La respuesta201 contiene el UUID, los datos validados, el workspace, el creador,
el estado active y las fechas. No se aceptan workspace, creador, credenciales de
equipo, IP ni notas sensibles en el contrato de entrada. Las notas son de texto
libre y el operador debe evitar datos sensibles.

| Operación relativa al dispositivo | Resultado |
|---|---|
| GET colección con q, device_type, status, offset y limit | Lista paginada con estado CPE |
| GET detalle | Ficha y CPE vigente o null |
| PATCH /status | Active o retired, sin borrar historial |
| GET /cpe-candidates | Catálogo paginado y deprecación |
| POST /identifications | Evento humano con UUID de catálogo, motivo e ID vigente esperado |
| GET /identifications | Historial paginado de eventos |
| POST /analyses con Idempotency-Key | Consulta201 y snapshot persistente |
| GET /analyses o /analyses/{run_id} | Historial y estado, fuente y cobertura |
| GET /analyses/{run_id}/findings | CVE, CVSS, evidencia y revisión |
| PATCH /findings/{finding_id} | Una revisión con motivo, evidencia y fecha esperada |
| POST/GET /findings/{finding_id}/recommendations | Crear medida manual o leerlas, estado pending |

La API revalida UUID y deprecación desde NVD y compara parte, vendor, producto y
versión observada. Los términos se normalizan en palabras y exigen coincidencia
exacta en su orden. Para fabricantes con alias de catálogo, registrar el nombre
conocido del fabricante del producto por separado, conservando el fabricante
físico del inventario. CPE incorrecto devuelve409. La selección queda pendiente
hasta que una persona la confirma. Cambiar entre fixture y live exige confirmar
de nuevo el CPE del dispositivo en el modo vigente. No se ejecutan solicitudes
a la URL de una aplicación ni a un equipo registrado.

El fixture usado para el recorrido es CVE-2017-6784 con condiciones AND.
La evidencia incompleta mantiene la aplicabilidad indeterminada. Una medida
manual pending registra una propuesta de seguimiento. El detalle conserva el
historial de su equipo y el dashboard de aplicaciones mantiene su propio alcance.

Guion de revisión local de 12 minutos. Dedicar 3 min a aplicación, tecnología y
confirmación CPE, 4 min a router, identificación y consulta, 3 min a revisión,
medida e historial y 2 min a dashboard y servidor con versión desconocida. Usar
una cuenta ficticia y explicar en pantalla la procedencia del resultado.

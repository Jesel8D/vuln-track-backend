# Contrato de revisiones de dispositivos

Todas las rutas se sirven bajo `/api/v2/workspaces/{workspace_id}/devices/{device_id}`, con sesión Bearer y acceso al workspace. El detalle conserva su forma anterior y agrega `record_version`, `identity_generation` y `cpe_review_state`. `current_identification` representa solo la generación actual.

| Operación | Resultado |
|---|---|
| `PATCH /` | Cambia los campos autorizados presentes, con versión esperada y motivo. Devuelve el detalle actualizado. |
| `GET /revisions` | Lista paginada de revisiones, de la más reciente a la más antigua. |
| `GET /revisions/compare?from_version=1&to_version=4` | Compara dos estados y marca si hubo cambio de notas en el intervalo. |
| `POST /reidentification` | Confirma el candidato del catálogo local tras cotejar el UUID, modo, nombre, fecha NVD, versión del registro e identificación esperada. |

## Ejemplos de edición

Traslado administrativo.

```json
{"expected_record_version":1,"site_label":"Sala de redes","reason":"Traslado administrativo"}
```

Corrección física.

```json
{"expected_record_version":2,"model":"RV340 corregido","confirm_sensitive":true,
 "reason":"Etiqueta física comprobada"}
```

Cambio tecnológico.

```json
{"expected_record_version":3,"version":"1.0.1.16","confirm_sensitive":true,
 "reason":"Versión verificada en el equipo"}
```

La versión desconocida se envía como `null`. Las notas y etiquetas son opcionales. Los campos omitidos conservan su valor. Las notas se guardan solo en el registro actual. El historial registra que cambiaron y omite su texto. El motivo es obligatorio. Si el cliente repite un intento con una versión que ya avanzó, recibe `409 DEVICE_VERSION_CONFLICT`; puede consultar el estado antes de decidir otro cambio.

La colección Postman incluye el detalle anterior, confirmación, consulta previa, cambio de firmware, rechazo de nueva consulta antes de confirmar y reidentificación. Los ejemplos se ejecutan con datos sintéticos o capturas públicas identificadas como fixture.

[Arquitectura](V3_DEVICE_EDITING_ARCHITECTURE.md) · [Concurrencia](V3_CONCURRENCY_AND_AUDIT.md)

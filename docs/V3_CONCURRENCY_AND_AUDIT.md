# Concurrencia y auditoría

La edición obtiene el candado transaccional por dispositivo que ya compartían identificación y análisis. Valida `expected_record_version` bajo ese candado y condiciona el `UPDATE` a la misma versión. PostgreSQL valida el contexto de workspace y obtiene el actor de la sesión firmada. El trigger asigna hora, versión, generación, campos modificados y motivo e inserta revisión y evento de auditoría antes de confirmar el cambio. Si falla cualquier escritura, el estado y la revisión se revierten juntos.

El rol de aplicación solo lee revisiones. La política requiere owner, editor o viewer del workspace. La edición y la nueva confirmación requieren owner o editor. La FK compuesta mantiene la pertenencia del actor y de la identificación histórica. Las instantáneas excluyen el texto de notas. Las solicitudes no admiten actor, timestamp, versión de destino ni generación aportados por el cliente.

| Caso | Comportamiento |
|---|---|
| Dos editores guardan desde la misma revisión | Una respuesta 200 y una respuesta 409. El ganador tiene una única revisión. |
| Cambios administrativos simultáneos | Conservan su CPE. Un borrador previo detecta conflicto antes de modificar campos. |
| Análisis iniciado antes de editar | Conserva la instantánea tomada antes de consultar NVD. |
| Reintento de la consulta histórica | La misma clave idempotente permite recuperar el resultado. Una clave nueva exige una identificación vigente. |
| Ruta histórica de estado | Serializa el cambio aislado de estado y lo audita con un motivo de compatibilidad. El nuevo formulario usa el PATCH versionado y solicita motivo humano. |

El cliente permite cargar la versión actual, comparar los valores y comenzar otro borrador. El seguimiento combina el historial inmutable, la identidad tecnológica de cada consulta y el evento de auditoría.

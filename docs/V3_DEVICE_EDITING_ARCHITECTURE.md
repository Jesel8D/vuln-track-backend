# Arquitectura de edición y contrato de RC3

| Capa | Fuente RC2.4 | Regla RC3 |
|---|---|---|
| Identidad administrativa | `devices`, ubicación, etiqueta, notas y estado | Editar con versión esperada. El CPE conserva vigencia. |
| Identidad física | `devices`, tipo, fabricante y modelo | Requiere confirmación del cambio. La referencia física puede revisarse. No existe una FK al catálogo físico. |
| Identidad tecnológica | `devices`, tipo de componente, fabricante, producto y versión | Un cambio abre una generación nueva. La generación anterior conserva sus evidencias. |
| Identificación vigente | `identifications`, UUID, nombre, modo y procedencia | Para ser vigente debe pertenecer a la generación tecnológica actual. |
| Identificaciones históricas | `identifications` y recibos de alta | Se conservan las filas, claves y valores anteriores. |
| Consultas y evaluaciones | `runs`, `findings`, revisiones y recomendaciones | Cada consulta conserva la identificación y la versión con las que se creó. Las consultas nuevas guardan una instantánea tecnológica. |
| Auditoría y acceso | Contexto HMAC, RLS, propietarios y editores | Solo los escritores editan. PostgreSQL registra el actor, el momento y ambas versiones en la misma transacción. |

El contrato sigue en `/api/v2`. Se añaden edición, historial, comparación y confirmación desde el catálogo local. Los perfiles RC2.4 y anteriores siguen usando sus worktrees y volúmenes. El piloto RC3 usa un catálogo acotado.

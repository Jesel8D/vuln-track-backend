# Reidentificar después de un cambio tecnológico

Un cambio en componente, fabricante tecnológico, producto o versión incrementa la generación. El dispositivo pasa a `needs_review` hasta que un editor u owner confirme un candidato de esa generación. Un cambio de ubicación o etiqueta conserva la identificación. Si cambia fabricante o modelo físico, la interfaz solicita revisar la referencia física cuando exista.

En el piloto, el recorrido usa Cisco RV340, versión inicial `1.0.0.33` y versión posterior `1.0.1.16`, ambas capturadas del catálogo observado. Elige **Buscar nueva identidad**, selecciona la fuente, fabricante, producto y versión, revisa el CPE y confirma explícitamente con motivo. La aplicación comprueba la versión del registro, el CPE completo y el momento de última modificación del candidato. PostgreSQL asocia el evento a la generación actual. Un CPE deprecado, incompatible o desactualizado se rechaza. Con versión desconocida se puede guardar el dispositivo y consultar referencias, y se bloquea la confirmación específica.

Las consultas históricas conservan CPE, versión observada, fecha, modo, cobertura, hallazgos y revisiones. Las consultas nuevas también guardan fabricante, producto, componente y versión de registro en la transacción de inicio. En los datos anteriores a RC3, se presenta el producto derivado del CPE original y se marca esa procedencia. Una consulta que ya empezó puede terminar sobre su instantánea si se edita el dispositivo mientras espera a NVD. El historial distingue la generación evaluada de la vigente.

La coincidencia requiere evaluación humana. Cuando se vuelve a confirmar, el usuario decide si procede otra consulta. El historial previo conserva las recomendaciones registradas.

[Contrato HTTP](V3_DEVICE_REVISION_CONTRACT.md)

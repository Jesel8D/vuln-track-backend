# Registro asistido de RC3.1

1. Elige Router, Switch o Servidor. Abre **Consultar referencias CPE de hardware** para buscar un fabricante y un modelo físico de parte `h`. Seleccionar la referencia rellena la identidad administrativa del equipo. Usa **No encuentro mi equipo** para volver al campo manual.
2. Elige firmware, sistema operativo, software o hardware. La parte CPE filtra el catálogo tecnológico de forma independiente del equipo físico.
3. Abre **Buscar fabricante CPE** con la flecha. Aparece una primera página aunque el filtro esté vacío. Escribe para filtrar, usa las flechas para resaltar, Enter para elegir y Escape para cerrar. **Limpiar** elimina la elección e invalida los campos dependientes.
4. Busca el producto dentro del fabricante. Cada opción muestra el título disponible y el identificador del producto. Luego selecciona una versión concreta y un CPE exacto. Cambiar de fabricante limpia producto, versión y CPE. Cambiar de producto limpia versión y CPE. Cambiar de versión limpia el CPE.
5. Revisa el nombre, UUID, CPE íntegro, estado, fuente y fecha NVD. Confirma que el producto y la versión corresponden al equipo observado, escribe el motivo y guarda. Cambiar el equipo o la selección reinicia la confirmación.
6. Para un equipo sin identificación, elige **Registrar sin identificación CPE**, captura el producto o versión que conozcas y guarda. Una versión vacía queda como desconocida. El dispositivo queda pendiente y la consulta específica permanece bloqueada.

El componente compartido React también se usa en **Buscar nueva identidad** después de editar un componente. La confirmación explícita crea una identificación de la generación actual. Las consultas anteriores conservan sus instantáneas. [Interacción de teclado de referencia](https://www.w3.org/WAI/ARIA/apg/patterns/combobox/) · [Guion de prueba](V3_RC31_LOCAL_RUN.md)

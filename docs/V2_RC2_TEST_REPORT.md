# Resultados de RC2 del 21 de noviembre de 2026

| Grupo | Resultado de esta misión |
|---|---|
| Backend completo existing y new | 769 aprobadas por ruta, cero fallidas y cero omitidas. Una deprecación Starlette/httpx por ruta |
| SQL existing y new | 134 comprobaciones por bootstrap. Son 120 de RC1 más 14 para dispositivos |
| Regresión frontend | 98 pruebas en nueve archivos, TypeScript, ESLint y build aprobados |
| Registro navegador en bases desechables | 6 aprobadas en existing y 6 en new |
| Navegador RC2 persistente | Los 9 casos de aplicaciones, aislamiento, seguridad, UX y errores pasaron. La prueba de dispositivos pasó al repetirla tras corregir los selectores del test |
| Navegador de recuperación | 1 aprobado tras reinicio de RC2 y 1 en el restore |
| OpenAPI y Postman | 59 operaciones, 86 solicitudes definidas, 28 cuerpos validados y 64 ejemplos positivos |
| Newman | Existing 333 aserciones / 90 HTTP. New 333 / 90. Contrato persistente en tmpfs 210 / 55. Cero fallos. El número HTTP depende del polling |
| Seguridad Phase 2A, 2B y 2C | 27, 45 y 51 comprobaciones de laboratorio respectivamente |
| Upgrade/rollback legado | 9 comprobaciones después de corregir el protocolo de stdout |
| Recuperación RC2 | 13 comprobaciones, con igualdad de DTO de aplicación y dispositivo e aislamiento después de restore |
| Persistencia de verificación previa | 7 comprobaciones aprobadas |
| Humo NVD live | Resolución CPE válida y una página CVE válida de un resultado. Sin clave, desde el cliente de RC2. Ninguna URL de aplicación o dispositivo solicitada |

El recorrido Chromium registró router, switch y servidor, bloqueó la
confirmación con versión desconocida y guardó identificación, ejecución,
revisión y medida del router. Las vistas de dispositivos pasaron sin
desbordamiento y sin observaciones de axe en 375, 768, 1280 y 1440 px.
Las pruebas de SQL/API confirmaron el rechazo de incompatibilidades de
fabricante, producto, versión y parte CPE, pertenencia al workspace, roles y
carrera de confirmación. La prueba de cambio de modo usó transporte simulado.
Se verificaron fallos NVD en los tests unitarios y la regresión NVD anterior.

Durante la primera ejecución, el auxiliar de preparación de hallazgos omitía
pasar el registro CVE a la función de aplicabilidad. La regresión reprodujo el
503 y los dos recorridos de aplicaciones con AND/OR lo verificaron después de
corregirlo. La prueba de dispositivos también ajustó selectores de formulario y
un reloj simulado de la cuota. Las suites finales aquí registradas son las
ejecuciones aprobadas. Los tests de navegador de aplicaciones y dispositivos
se contabilizan por separado, ya que el dispositivo se repitió de forma
dirigida conservando el dataset de la suite anterior.

El backup privado reproducido se restauró en
`vulntrack_v2_rc2_restore_a73ea593_pgdata` y su SHA-256 fue
`e8a539d9f9ef6b63fc1f9128a58773be6f93cec5a14b777de0617db03b05e27d`.
Se comprobó que tiene modo0600, queda fuera de Git, conserva el CPE y todas
las filas esperadas y rechaza el JWT previo en la copia. La copia quedó detenida
y el volumen retenido. El dump no forma parte de la entrega.

CodeQL no estuvo disponible en PATH. Se deja la reejecución pendiente y
se conserva la evidencia del probe corregido. Los logs brutos, accesos, dumps
y snapshots de contexto de navegador quedan privados.

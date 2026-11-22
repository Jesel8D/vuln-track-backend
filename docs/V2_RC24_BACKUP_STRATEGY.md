# Estrategia de respaldo de RC2.4

| Elemento | Reproducibilidad | Conservación |
|---|---|---|
| CPE, título, UUID y deprecaciones del feed | Reconstruible para la misma edición si se conserva el TAR | TAR oficial comprimido y manifiesto con digest del JSON, digest del TAR, tamaño, fecha y conteo |
| Recibos, actualizaciones API y cuarentena | La edición congelada no reconstruye por sí sola los cambios incrementales | Respaldo PostgreSQL completo |
| Usuarios, membresías, inventarios, identificaciones, consultas, hallazgos, revisiones, recomendaciones y auditoría | Datos privados irreemplazables | Respaldo PostgreSQL completo cifrado, con custodia y retención propias |
| Rol de conexión, contraseña PostgreSQL y clave JWT | Configuración privada de la instalación | Regenerar en el destino. Conservar por separado cualquier secreto que la política local exija retener. |

Se inspeccionaron las claves foráneas de la base restaurada. En RC2.3 la referencia física dentro de `vulntrack_catalog` era de `sync_pages` a `sync_runs`. La identificación de dispositivo y el recibo de alta conservan UUID, CPE y evidencia en sus propias filas o JSON. La ausencia de una FK directa a `products` no elimina la dependencia lógica de los selectores, el resumen y los recibos. RC2.4 añade la FK de cuarentena a la edición del feed. Una exportación selectiva sigue condicionada a probar conservación de dependencias, permisos, resúmenes y trazabilidad en el destino.

## Respaldo ejecutado

Se leyó la copia RAM de RC2.3 mientras el contenedor original seguía detenido. `pg_dump -Fc` produjo un archivo transaccional. Su salida entró por un pipe a GnuPG AES-256. La ruta de archivo persistente solo recibió texto cifrado. Se verificaron tamaño, SHA-256 y autenticación completa antes de entregar el archivo a PostgreSQL. El destino de restauración se preparó con roles propios y ejecutó `pg_restore --single-transaction --exit-on-error`. [Respaldo lógico PostgreSQL](https://www.postgresql.org/docs/16/app-pgdump.html) · [Copia de archivos y WAL](https://www.postgresql.org/docs/16/backup-file.html)

El respaldo y el TAR quedaron en F:. La clave se guardó en un archivo Linux privado, separado del respaldo. Para protección ante pérdida del SSD se propone otra copia cifrada en un medio independiente y custodia separada de la clave. El manifiesto y ambas copias permiten comprobar tamaño e integridad sin divulgar filas ni contraseñas.

[Guía y comandos](V2_RC24_RESTORE_GUIDE.md) · [Preflight](V2_RC24_STORAGE_REPORT.md)

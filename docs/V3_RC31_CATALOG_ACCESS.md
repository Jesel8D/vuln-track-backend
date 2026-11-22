# Acceso al catálogo de RC2.3

## Instalación verificada

RC3.1 usa **13 CPE oficiales locales y dos registros fixture** del piloto RC3. RC2.3 conserva el volumen con la edición amplia y su contenedor original está detenido. El inventario previo de roles muestra el login operativo y roles de aplicación. La activación del catálogo completo está pendiente de autorización para arrancar el servidor histórico y aprovisionar un login limitado. No se usó el login operativo para leer esa base.

El adaptador SQLAlchemy lee el modo oficial mediante un pool dedicado. El modo fixture, las escrituras de dispositivos y los historiales siguen en la base propia de RC3.1. El adaptador integra los mismos endpoints y consultas de catálogo para búsqueda, detalle, selección y reidentificación. La respuesta de estado indica si está usando `local` o `external_readonly`.

## Activación después de autorización

1. Verifica que `vulntrack-v2-rc2-catalog23-postgres` sea el contenedor original, que monta `vulntrack_v2_rc2_catalog23_pgdata` y que su puerto PostgreSQL se publica solo en loopback. Comprueba capacidad física en C:. Arranca ese contenedor si se autoriza. El mismo volumen queda bajo un solo servidor PostgreSQL.
2. Como operador, ejecuta `dev/v2/catalog_reader.operator.sql` en la base `vulntrack_v2_development` de ese contenedor. El rol se crea sin login. Define su contraseña única mediante `\password vulntrack_catalog_reader` en una sesión psql interactiva y después habilita `LOGIN` solo para ese rol. Conserva la credencial fuera de Git y de los comandos con argumentos visibles. [Roles de PostgreSQL](https://www.postgresql.org/docs/16/sql-createrole.html) · [Privilegios PostgreSQL](https://www.postgresql.org/docs/16/sql-grant.html)
3. En el perfil RC3.1, guarda la URL PostgreSQL con psycopg en `.local/rc3-catalog31/catalog-reader.url` con propietario del launcher y permisos `0600`. Usa el login limitado, la base indicada y `127.0.0.1:55446`. El secreto permanece en Backend. Reinicia solamente RC3.1 para recargar la configuración.
4. Valida `GET /api/v2/cpe-catalog/status?mode=live` como usuario autenticado. Debe indicar `external_readonly` y el conteo real de la edición. Revisa los filtros Cisco, Juniper, Dell, Canonical y Apache, paginación y tiempos. Verifica `mode=fixture` por separado. Compara los conteos y recibos de la fuente antes y después.
5. Para regresar a la muestra, retira la URL del perfil y reinicia RC3.1. El catálogo e inventario locales siguen disponibles. Para revocar acceso a la fuente, el operador deshabilita el login y cierra únicamente las sesiones de ese rol.

Un error de acceso, permiso, timeout o fuente no disponible se muestra como error de catálogo. El usuario puede reintentar, cambiar a fixture o guardar manualmente. La respuesta oficial nunca pasa a la muestra local de forma implícita cuando la configuración externa falla. [Seguridad](V3_RC31_SECURITY.md)

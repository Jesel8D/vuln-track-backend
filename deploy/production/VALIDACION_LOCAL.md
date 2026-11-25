# Validación del candidato de despliegue

Fecha local: 24 de noviembre de 2026; registros UTC incluyen 25 de noviembre.
Alcance: laboratorio separado en esta laptop, HTTPS con CA local, datos de inventario sintéticos, catálogo público restaurado en volúmenes nuevos. Ningún despliegue AWS ni consulta NVD. Los secretos, cuentas de prueba, logs completos y dumps privados permanecen fuera del repositorio.

## Cambios imprescindibles

No apareció `fix/pre-ec2-security-gates` en las referencias locales/remotas de los cuatro repositorios revisados; tampoco una infraestructura de producción equivalente. Se reutilizaron Dockerfile, migraciones, bootstrap SQL canónico, RLS, contratos, lector CPE y respaldo oficial existentes. Se añadieron Compose/Caddy, operaciones explícitas de instalación/recuperación y entrada privada de configuración. El lector admite únicamente el host Docker `catalog:5432` con `verify-full` y CA fija, además del loopback ya permitido. El build público usa el mismo origen y bloquea las consultas CVE también en la interfaz. No se amplió el producto.

## Resultados de esta misión

- Construcción de las dos imágenes: satisfactoria. Hubo un fallo transitorio DNS de Docker Hub; el reintento pasó.
- 43 pruebas unitarias pertinentes: 8 del límite del lector CPE y 35 de CORS.
- 2 pruebas de integración con PostgreSQL desechable: lector y asociación CPE de aplicaciones.
- Frontend: tipos/lint/build y 181 pruebas React satisfactorios. Advertencia de tamaño de chunk, sin fallo de build.
- Contratos: 73 operaciones, 110 solicitudes, 34 cuerpos y 86 ejemplos; contrato OpenAPI conservado.
- 36 comprobaciones sobre la instalación de producción: HTTPS verificado, cuentas sintéticas, roles, aislamiento por workspace, inventario/CPE/historial, límites, bloqueo CVE, persistencia tras reinicio y cierre de registro/rotación JWT.
- Chromium: tres roles con assets compilados, cero solicitudes externas, cero errores JavaScript y tres comprobaciones axe sin infracciones; vista móvil sin desbordamiento.
- 17 controles de infraestructura: solo proxy publicado en loopback, bases y API sin puertos publicados, procesos principales sin root, API/proxy con filesystem de solo lectura y capacidades eliminadas, redes SQL internas, TLS SQL efectivo y rechazo de CA incorrecta, CORS exacto, redirección HTTP y límite de cuerpo.
- Recuperación privada: dump sintético de producción restaurado en otro proyecto y volúmenes nuevos, 37 tablas con todas las huellas de filas idénticas, migraciones verificadas a v10, credenciales nuevas y API disponible. El proxy se niega a arrancar sin recibo de restauración CPE de ese proyecto. No se duplicó otra vez el catálogo completo en este segundo laboratorio.
- Recuperación CPE: paquete oficial completo verificado, cinco huellas idénticas, 1,880,952 aceptados, un registro inválido en cuarentena y cero fixtures. Sin descarga de NVD.
- Instalación habitual: 109 filas/37 tablas, columnas, conteos por workspace, cinco huellas CPE y paquetes/respaldos anteriores intactos. Cero escrituras de inventario en esa instalación.

La prueba detectó dos defectos de preparación y ambos se corrigieron: el fallback SPA absorbía `/docs` (se convirtió en `handle` exclusivo con 404), y `--no-owner` en recuperación privada cambiaba propietarios de seguridad (se conserva propiedad/ACL y se verifica el esquema). El destino del intento fallido se detuvo y conservó; se probó la corrección en otro volumen vacío, sin eliminar datos.

## Seguridad y límites del dictamen

`npm audit` del lockfile: cero advisories reportados. Se consultaron los JSON oficiales de PyPI para las 37 versiones fijadas: cero advisories no retirados reportados. No equivale a demostrar ausencia universal de vulnerabilidades. Las imágenes están fijadas por digest; consultar el manifiesto de entrega para el resultado y alcance del análisis de imágenes.

JWT dura 300 segundos, sin refresh ni revocación individual en servidor; logout limpia memoria del navegador. La rotación explícita del secreto invalida todos los tokens y se probó. Limitadores en memoria por proceso: este despliegue fija un único worker y una única réplica; no escalar sin resolver almacenamiento compartido. El proxy reemplaza la IP declarada por el cliente; el intento de evadir límites con X-Forwarded-For falso fue rechazado.

Pendiente exclusivamente de EC2: sistema operativo/arquitectura y recursos reales, advisories vigentes de host/imágenes, DNS, SG/firewall efectivo, certificado público/renovación, observabilidad, copias cifradas externas y simulacro de recuperación del servidor. NO-GO público hasta resolverlos. CVE live, ZAP, escaneos remotos y fase 6 permanecen fuera del alcance.

Context no se publica: no se encontró licencia ni autorización de redistribución comprobada. Esta guía independiente permite desplegar sin su contenido.

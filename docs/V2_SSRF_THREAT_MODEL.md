# Modelo de amenazas SSRF y contrato de ejecución futura

## Límite de confianza

El usuario autenticado y cualquier URL, referencia, ID, respuesta DNS o Location
son entradas no confiables. Pertenecer a un workspace no concede acceso a la red
del servidor. Registrar una URL no autoriza una conexión. Una IP pública tampoco
prueba permiso de análisis.

El inventario únicamente almacena metadatos. NVD conserva sus clientes de origen
fijo y sus fixtures de pruebas; esta fase no conecta destinos arbitrarios a esos
clientes. No existe executor ZAP ni una ruta de lanzamiento de análisis web.

Se sigue la defensa en profundidad de la [guía SSRF de OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html):
validación de aplicación y restricciones independientes de red, con redirecciones
deshabilitadas. Las segundas todavía no están implementadas; no se presenta el
filtro de URL como una solución completa de SSRF.

## Política local implementada

`app/services/web_target_policy.py`, versión `web-public-v1`, no abre conexiones.
Se emplean urllib.parse, ipaddress y el IDNA ya bloqueado en las dependencias.

| Entrada/amenaza | Control implementado |
|---|---|
| Esquemas/puertos | HTTPS/443 por defecto; inventario HTTP/80 explícito para compatibilidad; ningún puerto adicional |
| Credenciales, host vacío o ambiguo | Rechazo de userinfo incluso vacío, autoridad codificada, barras invertidas, puerto vacío/con ceros iniciales, punto final y nombres locales |
| Unicode e IDNA | IDNA estricto, host ASCII canónico, rechazo de separadores Unicode alternativos, normalización ambigua y controles |
| IP no pública | Rechazo de loopback, privada, CGNAT, link-local, no especificada, multicast, documentación, reservada y metadatos cloud |
| IPv4 alternativa | Rechazo de entero, octal, hexadecimal, abreviada y host codificado |
| IPv6 | Solo unicast pública; rechazo de zona, IPv4 mapeada, 6to4, Teredo, traducción y rangos especiales/documentales |
| Parser y request-target | Sin fragmentos, controles crudos/codificados, doble barra inicial, backslash o segmentos de punto ambiguos; tamaño canónico acotado |
| DNS | Resolutor inyectado; sin resolutor real de red en esta fase; entre 1 y 16 respuestas y todas deben ser públicas |
| Respuesta mixta | Una sola IP prohibida invalida el conjunto completo |
| Rebinding/rotación | Revalidación vuelve a resolver y rechaza cambios de IP; no reutiliza ciegamente un resultado anterior |
| TOCTOU | Plan inmutable de hasta 5 segundos; falta el transporte que imponga la conexión a esa IP |
| Redirecciones | Se rechazan todas, incluidas relativas, mismo origen, cambios de host y protocolo |
| Entorno/reintentos/TLS | El plan exige trust_environment=false, sin reintentos automáticos, sin redirects y verificación TLS; falta imponerlo en transporte real |

El registro aplica únicamente controles estáticos y canonicalización, sin DNS ni
HTTP. Puede existir un nombre público que después resuelva a una IP privada: una
validación de registro no puede autorizar conexiones posteriores. Las filas
históricas no se reescriben; readiness las bloquea si no cumplen la política.

El plan retiene URL/origen, puerto, direcciones validadas, Host y nombre TLS/SNI.
**IMPLEMENTADO CON LIMITACIONES:** se prueban sus datos y revalidación con
resolutores simulados. No hay socket, transporte, proxy o cliente que pueda
ejecutar ese plan. Por ello siguen bloqueadas todas las ejecuciones, también con
evidencia local válida. No hay excepción global para localhost o redes privadas.

## Obligaciones de la Fase 2: transporte y red

**PENDIENTE / BLOQUEADO para ZAP:** un adapter probado debe seleccionar solo una IP
del conjunto validado, conectar directamente a ella sin una segunda resolución
implícita y conservar el Host y SNI originales con verificación de certificado
contra ese nombre. Validar también la dirección remota del socket. Cada conexión
y cada reintento debe revisar autorización vigente y revocación, DNS y presupuesto.
No se debe entregar una URL de usuario a httpx/requests/ZAP confiando en que la
validación previa fija su resolución. Un plan vencido o un cambio de DNS exige
rechazo/nueva evaluación, nunca fallback.

El resolver futuro necesita timeout, presupuesto de respuestas/cadena CNAME,
ambas familias IP y manejo explícito de TTL/errores. Las pruebas actuales no
implementan ni certifican ese servicio. La red debe bloquear independientemente
host, LAN, servicios internos, metadatos, IPv6 de transición, DNS/proxies no
autorizados y cualquier egreso que no corresponda al destino verificado.

## Contrato operativo propuesto, todavía sin executor

Estos requisitos no son contenedores ya creados ni una aprobación global:

| Control requerido | Preparación para Fase 2 |
|---|---|
| Aislamiento | Contenedor por trabajo/workspace, imagen fijada por digest y verificada |
| Privilegios | Usuario no root, cap-drop ALL, no-new-privileges, raíz de solo lectura, tmpfs acotado, sin modo privilegiado |
| Montajes | Sin socket Docker, HOME, credenciales de API/SQL/HMAC/JWT o directorios de otros trabajos |
| Red | Sin host networking; gateway/ACL independiente que limite IP/puerto y todas las rutas de egreso; probar también IPv6 |
| Recursos | CPU/memoria/PID, tiempo, cantidad de requests y tamaño de respuesta obligatoriamente acotados; valores por aprobar |
| Concurrencia | Cuotas globales y por workspace, cola/lease, admisión atómica e idempotencia |
| Revocación/cancelación | Revalidación al despachar y por conexión; cancelar al revocar, vencer o perder membresía; matar solo recursos propios |
| Recuperación | Watchdog y limpieza idempotente tras timeout/caída, conservación privada de evidencia necesaria, sin borrar datos de usuario |
| Logs | Límites de bytes/retención; IDs/códigos y origen sanitizado; omitir tokens, cookies, query strings y cuerpos sensibles |
| Auditoría | Actor, workspace, target, versión de permiso, evidencia, política, IP efectiva, inicio/fin/cancelación y causa; acceso autorizado |
| Pruebas de red | Demostrar bloqueo aunque un proceso intente eludir el validador: host/privadas/metadatos, redirects, rebinding y proxies |

No se añaden endpoints de ejecución, workers web, imágenes ZAP o comandos de
escaneo. El worker NVD existente permanece separado.

## Riesgos residuales y aprobación

La política pública es conservadora y puede rechazar destinos legítimos; no se
ofrece al usuario un bypass. IDNA no elimina homógrafos ni acredita titularidad.
Un dominio puede cambiar de dueño y DNS puede cambiar entre comprobación y
conexión; sin transporte y red independientes no se garantiza la protección.
No se han probado esas garantías con paquetes reales de un executor.

[ZAP Baseline](https://www.zaproxy.org/docs/docker/baseline-scan/) ejecuta un spider
y después reporta análisis pasivo: genera requests y puede provocar efectos en
la aplicación. No se describe como operación sin impacto. La [documentación
Docker de ZAP](https://www.zaproxy.org/docs/docker/) no sustituye las restricciones
de salida y los permisos anteriores.

Jesel y Rudi deben acordar consentimiento/alcance, método de prueba de control,
presupuestos, aislamiento, política de red y retención. **ZAP NO está autorizado
para activarse** hasta implementar y verificar esas condiciones en otra fase.

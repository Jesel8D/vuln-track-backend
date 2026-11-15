# Lista independiente: antes de una futura fase ZAP

**ZAP BLOQUEADO. Ninguna casilla de pruebas autoriza por sí sola una ejecución.**
La misión Fase 2A autoriza componentes y laboratorio, no escaneos. Esta lista no
modifica D-001/D-002 ni convierte propuestas de diseño en aprobaciones de equipo.

## A. Controles implementados

- [x] Separar declaración, evidencia técnica y permiso de ejecución.
- [x] Política estricta de URL/IP, todas las respuestas DNS, revalidación y TTL.
- [x] Componente HTTPS con IP fijada, Host/SNI/certificado originales y TLS ≥1.2.
- [x] Sin proxies, cookies, redirecciones ni reintentos; respuesta/tiempo acotados.
- [x] Referencia LOCAL de desafíos aleatorios, hash, propósito, scope y caducidad.
- [x] Consumo único/concurrencia, revocación, nueva comprobación de scope y audit.
- [x] Botón deshabilitado, sin endpoint de ZAP/verificación remota habilitado.
- [x] Laboratorio de red independiente con worker sin capacidades/privilegios.
- [x] Procedimiento de actualización y rollback emparejado, sin SQL nuevo.

## B. Controles probados técnicamente

- [x] Regresiones Backend/SQL/Postman con JWT, roles y RLS reales en PostgreSQL propio.
- [x] Contexto PostgreSQL no persiste tras commit/rollback y reutilización de pool.
- [x] URLs adversariales, conjuntos DNS mixtos, rebinding y planes caducados.
- [x] TCP/TLS reales IPv4/IPv6 sin getaddrinfo durante conexión.
- [x] Host/SNI originales; hostname incorrecto, CA no confiable y certificado expirado rechazados.
- [x] Redirecciones, exceso de tamaño/cabeceras, codificación ambigua, timeout y cancelación.
- [x] Desafío aleatorio de propósito único verificado por HTTPS REAL del laboratorio.
- [x] Token incorrecto/repetido, cambio de scope, auditoría fallida y revocación en carrera.
- [x] Sondas que saltan Python bloqueadas por red; canarios TCP/UDP reciben cero tráfico.
- [x] UID, capacidades, no-new-privileges, raíz de solo lectura y cgroups inspeccionados.
- [x] OOM real de sonda propia de 32 MiB; limpieza solo de contenedores etiquetados propios.
- [x] React, navegador desktop/móvil y accesibilidad en los estados ensayados.
- [x] Cambio estable → Fase 1 → Fase 2A → estable, reinicio y restore en volúmenes distintos.

Estas marcas se limitan a los resultados locales documentados; no prueban
egreso público seguro, un producto listo para producción ni cualquier destino.

## C. Controles pendientes

- [ ] Repositorio duradero de desafíos/evidencia y consumo único entre procesos.
- [ ] SQL incremental, modelos/migraciones, RLS y auditoría atómica del nuevo flujo.
- [ ] Adaptador DNS operativo autorizado con límites de tiempo/respuestas y sin bloqueo del event loop.
- [ ] Rate limits, cuotas de desafíos, renovación, revocación y recuperación tras caídas.
- [ ] Integrar verificación mediante JWT + scope transaccional actualizado, sin aceptar evidencia del cliente.
- [ ] Egreso público selectivo independiente, DNS del runner controlado y bloqueo completo de redes internas.
- [ ] Probar transporte en ese despliegue real, incluyendo IPv6/rutas/proxies del entorno objetivo.
- [ ] Runner aislado por trabajo/workspace sin acceso a host, Docker, aplicación o PostgreSQL.
- [ ] Presupuesto total de solicitudes, CPU/memoria/tiempo, concurrencia y rechazo por capacidad.
- [ ] Cancelación/revocación durante cualquier ejecución, limpieza/reconciliación tras fallos.
- [ ] Logs/evidencia limitados y sanitizados, retención, backup/restore operativo y accesos de revisión.
- [ ] Política de permiso de análisis independiente de la prueba de control del dominio.
- [ ] Ensayo de actualización personal acordado; no realizarlo como efecto de un push.
- [ ] Threat model y prueba adversarial integrados de toda la cadena antes de habilitar un endpoint.

No marcar estas casillas con resultados de tests unitarios o del namespace
network-none: son garantías de un despliegue futuro todavía inexistente.

## D. Decisiones que requieren aprobación del equipo

- [ ] Método y alcance de control: HTTPS por origen, DNS TXT o revisión administrativa documentada.
- [ ] Quién puede aprobar permiso de análisis; separación respecto de declarar propiedad.
- [ ] Vigencias de desafíos/evidencia/permiso, renovación, revocación y tratamiento de cambios de dominio.
- [ ] Esquema y retención; coordinación Database/Backend conforme D-002.
- [ ] Arquitectura de egreso/aislamiento, privilegios del controlador y plataforma de despliegue soportada.
- [ ] Límites operativos, controles de abuso, responsables y requisitos de observabilidad/revisión.
- [ ] Autorización explícita posterior de una fase ZAP Baseline y de cada alcance de prueba real.

Responsables de decisiones: Jesel y Rudi. No hay aprobación conjunta nueva
registrada aquí. Incluso si todas las pruebas futuras pasan, **ZAP NO está
autorizado para activarse sin esa decisión posterior explícita**.

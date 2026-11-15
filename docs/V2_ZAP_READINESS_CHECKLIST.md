# Checklist independiente antes de cualquier fase ZAP — estado Fase 2B

**ZAP BLOQUEADO. Las pruebas locales no autorizan análisis ni verificaciones remotas.**
La misión autoriza ramas y laboratorio; D-001/D-002 y las aprobaciones pendientes
Jesel/Rudi no se modifican. Los resultados de Fase 2A siguen siendo antecedentes.

## A. Controles implementados

- [x] Separar declaración, prueba técnica y elegibilidad de ejecución.
- [x] SQL008 persistente con dos tablas, digests y scope/versión de destino inmutables.
- [x] FORCE RLS en tablas nuevas, FK compuestas, roles mínimos y funciones auditadas.
- [x] Emisión idempotente, token mostrado una vez, consumo único y revocación.
- [x] TTL, lease, un pending por destino y cuota transaccional por workspace.
- [x] ORM/Alembic separado sin cambiar el head legado; adopción exacta, sin stamp ciego.
- [x] API real de emisión/lectura/revocación; verify devuelve 503 sin red ni intentos.
- [x] DNS TCP acotado y seleccionado por operador; IDNA, A/AAAA, CNAME y rebinding.
- [x] Reutilizar HTTPS fijado a IP con Host/SNI/TLS originales y sin proxies/redirects/retries.
- [x] React valida contrato y scope; no acredita fixtures; Baseline siempre disabled.
- [x] Laboratorio con política de red independiente y worker sin secretos de aplicación.

## B. Controles probados técnicamente

- [x] Migración desde SQL007 y bootstrap/adopción limpia en PostgreSQL desechable.
- [x] RLS real, roles, IDs ajenos, membresía, concurrencia, rollback y pool reutilizado.
- [x] Inscripción sin privilegios nuevos; API sin acceso a digests ni funciones del laboratorio.
- [x] Rechazar drift de RLS, ACL, propietarios/roles, search_path y objetos desconocidos.
- [x] Emisión repetida sin reproducir tokens, cuotas y revocación idempotente.
- [x] Consumo y finalización únicos; cambios de URL/declaración/membresía/tiempo invalidan pruebas.
- [x] Auditoría fallida no deja desafío ni evidencia confirmada.
- [x] Evidencia de laboratorio persistida sin convertirla en control real de dominio.
- [x] Datos y fechas sobreviven reinicio completo y restore en OTRO volumen nuevo.
- [x] Código estable/Fase 2A y sus verificadores de catálogo toleran la extensión sin borrarla.
- [x] DNS/TLS reales solo con fixtures propios; sin resolución silenciosa al conectar.
- [x] Sondas que saltan Python bloqueadas; canarios privados/DB/metadatos/DNS sin tráfico.
- [x] Recursos, UID, capacidades, raíz read-only, cancelación, FD y OOM controlado comprobados.
- [x] Regresiones Backend, SQL, React, navegador responsive/Axe y Postman.

Estas marcas solo describen el alcance local ensayado. No certifican producción,
firewall Windows ni una plataforma con egreso público selectivo.

## C. Controles pendientes

- [ ] DNS operativo desplegado y autorizado, con canal/operación/revisión definidos.
- [ ] Egreso público por IP/puerto/origen validado, independiente de Python y comprobado.
- [ ] Probar cambios dinámicos de destino, DNS y rutas en ese despliegue real.
- [ ] Productor de evidencia operativa confiable, sin aceptar pruebas del cliente o del laboratorio.
- [ ] Permiso operativo vigente de análisis, separado de acreditar control del dominio.
- [ ] Nuevo diseño/migración explícita antes de permitir transición SQL a verified.
- [ ] Runner por job/workspace sin acceso a host, Docker, aplicación o PostgreSQL.
- [ ] Scheduler duradero, presupuesto de solicitudes, concurrencia, cancelación/revocación y reconciliación.
- [ ] Retención, revisión de auditoría, saneamiento y operación de backups fuera de la PC.
- [ ] Ventana y ensayo de actualización personal autorizados por separado.
- [ ] Revisión adversarial integrada de la plataforma futura, incluida recuperación tras caídas.

La API sigue bloqueando todas las comprobaciones remotas mientras el egreso
público no esté demostrado. Un laboratorio network-none no satisface esa casilla.

## D. Decisiones que requieren aprobación del equipo

- [ ] Método/alcance de control por origen y límites de subdominios, ruta, esquema y puerto.
- [ ] Quién concede permiso operativo, revisores y separación de declaración/prueba/ejecución.
- [ ] Ratificar TTL, lease, cuotas, intentos, renovación, revocación y retención.
- [ ] Arquitectura del DNS/egreso, privilegios del controlador y plataforma soportada.
- [ ] Política de evidencia operativa y migraciones coordinadas Database/Backend según D-002.
- [ ] Responsables de operación y revisión de seguridad, límites y respuesta a fallos.
- [ ] Decisión explícita posterior de una fase ZAP Baseline y del alcance real de cada prueba.

No se registra aprobación conjunta nueva. Incluso con todas las pruebas futuras
aprobadas, **ZAP NO está autorizado para activarse por defecto**.

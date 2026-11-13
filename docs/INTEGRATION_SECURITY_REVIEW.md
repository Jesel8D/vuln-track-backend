# Revisión técnica de seguridad de integración V1.2

Antecedente V1.2 conservado. La revisión de registro/RLS/JWT V2 y su evidencia
actual está en [SELF_SERVICE_REGISTRATION.md](SELF_SERVICE_REGISTRATION.md) y
[SELF_SERVICE_REGISTRATION_RESULTS.md](SELF_SERVICE_REGISTRATION_RESULTS.md).

Alcance: herramientas de coordinación, SQL propuesto y contrato de clientes sobre la
API V1.1. Estado **PROPUESTA**, no auditoría independiente ni aprobación de producción.
No se cambian decisiones de Context. No se implementaron clientes, NVD, ZAP ni escaneos.

| Riesgo revisado | Control/evidencia | Límite residual |
|---|---|---|
| Fuga entre usuarios | Identidad activa en servidor; created_by impuesto por API; filtro SQL antes de contar/paginar; 404 ajeno/NULL; tests reales en ambas rutas | Login SQL es privado/confiable; no hay RLS para conexiones arbitrarias |
| Fuga por idempotencia | PK por actor; visibilidad antes de hash/expiración; snapshot solo autorizado; carreras autenticadas con rollback | Retención/24 h y reconciliación pendientes; no prueba de corte TCP durante commit |
| JWT/contraseñas | Argon2id; firma/issuer/audience/exp/usuario activo; hash deferred; errores sin entrada; no-store/nosniff | Sin revocación individual, refresh ni logout servidor; web debe decidir almacenamiento contra XSS |
| CORS/transporte de clientes | V1.3 añade lista explícita validada, Bearer y HTTPS remoto; sin wildcard/cookies | Lista vacía por defecto; orígenes de despliegue requieren revisión, CORS no autoriza recursos |
| Baseline falso | Catálogo por revisión + ORM; adopción solo sin revisión o 0002, validación antes/después y transacción | Requiere mantenimiento y credencial privilegiada, nunca login API |
| Carrera entre herramientas de esquema | Advisory lock común a Alembic/adopción; SHARE de tablas durante adopción; timeout probado | Serialización cooperativa, no defensa frente a DBA hostil o DDL externo no coordinado |
| Drift de triggers | Se detectó que pg_get_triggerdef no revela habilitación; se añadió tgenabled y rechazo probado | El verificador no certifica toda configuración/grants del servidor |
| Divergencia SQL/ORM | Patch de fuente original fijada, manifiesto hashes, dos rutas con mismo catálogo/ORM y pruebas API | Revisión y commits coordinados en Database/Context todavía pendientes |
| Pérdida histórica | NULL sin backfill, sin DELETE ni reasignación; IDs/datos preservados; downgrade bloqueado | Asignación histórica futura requiere autorización/auditoría propias |
| Contenido sensible | Cuerpos limitados, extras rechazados, errores redactados, sin tokens en URLs | Validar texto no detecta secretos en notas; límites HTTP del proxy/retención deben operarse |

No se amplió privilegio de API para propiedad. El permiso SELECT(password_hash) sigue
separado y solo se concede al login temporal después de la integridad SQL original en
pruebas. La propuesta de bootstrap no activa demo ni agrega contraseñas por defecto.

Los nuevos tools no aceptan una base persistente como destino del runner. La herramienta
administrativa de adopción sí opera sobre la URL indicada explícitamente: su uso futuro
necesita aprobación/identificación de destino y copia restaurada; --confirm-proposal no
significa aprobación. Durante esta misión solo se usaron contenedores tmpfs nuevos.

No se configuraron credenciales GitHub ni se hizo push/merge. Publicación futura mediante
SSH desde equipo autorizado y PR revisado, conservando historial y sin force.

## Continuación V1.3

CORS ahora es configurable y se prueba sobre el flujo HTTP autenticado, también en
errores y preflight. No está abierto por defecto ni concede acceso a activos ajenos.
JWT refuerza audiencia escalar y tipos/orden de claims temporales, conservando HS256.
No hay sesiones nuevas ni migraciones. Ver CORS.md y JWT_SECURITY_REVIEW.md para
configuración, evidencia y propuesta no implementada de revocación individual.

# Decisiones abiertas y aceptación

D-001/D-002 permanecen intactas. La misión autoriza materializar el stack backend;
las propuestas históricas de Context no cambian de estado por haberse implementado código.

| Elemento | Estado de entrega | Revisión necesaria |
|---|---|---|
| FastAPI, configuración, PostgreSQL, modelos, pool | Implementado y probado | Operación compartida/capacidad |
| Baseline Alembic | Implementado y probado en base desechable | Backup/restauración y revisión de cada instalación antes de reconocerla |
| Login/me, Argon2id y JWT | Implementado y probado | Provisionar login, grant de hash y cuenta nueva; ratificar política JWT provisional |
| Servicio alta/detalle/listado | Implementado y probado bajo fixtures | Bloqueado en runtime por permisos por recurso |
| Idempotencia concurrente | Servicio probado en PostgreSQL | Prueba API autorizada/móvil y pérdida real de transporte pendientes |
| Autorización productiva | Denegación segura probada | No existe relación que permita acceso positivo en V1 |
| Imagen Docker y arranque | Ver docs/TEST_RESULTS | Revisión de plataforma y despliegue |
| Frontend/móvil/NVD/ZAP | Fuera de esta misión | Sin cambios ni ejecuciones |

**PENDIENTE crítica:** aprobar relación/política de permisos de activos. Ajuste mínimo
**PROPUESTO**, todavía no implementado ni aplicado: `assets.created_by uuid NULL REFERENCES
vulntrack.users(id) ON DELETE RESTRICT`, índice según consultas y regla de lectura propia
para cuentas activas. La API asignaría creador desde identidad, nunca desde el cuerpo.
Los activos históricos permanecerían sin creador y no visibles hasta revisión humana;
no inferirlos de análisis o registros idempotentes. Creación solo con cuenta activa,
lectura filtrada por creador. Revisar si las necesidades académicas exigen compartir
activos, en cuyo caso una ACL explícita sería mejor. Preparar migración revisable solo
tras autorización, probar una copia y extender guard Alembic por versión.

Otras decisiones pendientes: retención de solicitudes y snapshots, ventana 24 h,
reconciliación tras vencimiento, aprobación del contrato/normalización, política de altas,
recuperación y revocación individual; sesiones opacas requieren una tabla nueva. Login
requiere permiso adicional de lectura de hash documentado, nunca administrador API.
Antes de producción: HTTPS, limitador compartido, revisión de notas sensibles,
backup/restauración probados, carga, límites de conexiones HTTP y rotación de secretos.

**No se cumplen todavía todos los criterios de aceptación de Backend V1**. La barrera
es explícita y no se ha reducido seguridad para completar una demostración.

# Estado de propuesta Backend V1.1

La misión autoriza implementación revisable y pruebas desechables de propiedad individual,
**no aprobación arquitectónica formal ni integración definitiva**. D-001/D-002 intactas.

| Elemento | Implementación/prueba | Pendiente |
|---|---|---|
| created_by UUID nullable, FK RESTRICT, índice por owner/fecha/id | Migración y ORM probados en PostgreSQL | Aprobación y coordinación Database |
| Activos históricos | Conservados NULL y ocultos | Procedimiento explícito/auditado de asignación, sin inferencias |
| Crear/leer/listar propios | API con login/JWT/política reales, pruebas positivas y negativas | Revisión humana y release coordinada |
| Idempotencia y concurrencia con propietarios | Probadas a través de API y PostgreSQL | Transporte TCP real durante commit, móvil |
| JWT y credenciales | V1 conservado, usuarios activos y versión verificados | Revocación individual/sesiones, operación de altas/recuperación |
| Baseline/migración | Verificación por revisión, rollback DDL, drift y stamp indebido probados | Copia restaurada y revisión de cada destino antes de uso persistente |
| Bootstrap futuro Database | Fragmento SQL equivalente probado | Cambios en SQL/SCHEMA/tests/diagrama de Database y reconocimiento de bootstrap V1.1 |

Sin administración global, acceso a terceros ni endpoints de asignación/actualización/
eliminación. NULL no es público. La cuenta técnica es confiable y privada; autorización
es de API, no RLS para conexiones SQL arbitrarias. Esto debe mantenerse como frontera.

Antes de integrar: aprobar explícitamente política de propietario único y su relación,
retención idempotente (24 h provisional), normalización/contrato, política de sesiones,
operación de cuentas, backups/restauración, HTTPS y limitación compartida por réplicas.
La aprobación deberá registrarse en Context por responsables; este trabajo no lo edita.

La propuesta funciona y está probada, pero **no se declara lista para producción**.
GitHub sigue sin recibir estos commits; no se intentó push ni se tocaron credenciales
en la misión V1.1. Recuperar/publicar manualmente desde el bundle verificado.

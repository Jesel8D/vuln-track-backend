# Registro idempotente: implementado en el servicio

La ruta de API se versiona `/api/v1/assets`; el ámbito almacenado sigue siendo exactamente
`POST /assets` porque lo exige el CHECK de Database V1. Clave validada como UUID canónico de 36 caracteres por
Pydantic, cliente genera una por operación lógica. No es deduplicación de inventario.

1. Exigir permiso de creación antes de abrir transacción. Actualmente denegado en runtime.
2. Huella SHA-256 del JSON canónico ordenado del cuerpo validado: NFC, recorte, null
   explícito para opcionales, UTF-8 y versión de canonicalización 1, método/ruta incluidos.
3. En una sola transacción, buscar resultado previo; si no existe, insertar activo UUID,
   leer timestamp servidor y construir snapshot completo; insertar solicitud con FK al
   activo, hash y respuesta 201. Commit antes de retornar.
4. Dos ausencias concurrentes pueden insertar activos provisionales. La PK real de la
   solicitud decide el ganador. Solo se trata SQLSTATE 23505 **de esa PK** como colisión
   idempotente. La transacción perdedora revierte también su activo; abre otra transacción
   READ COMMITTED y recupera el snapshot ganador. No basta el SELECT inicial.
5. Al repetir, comprobar nuevamente autorización, huella, vigencia y visibilidad del activo;
   devolver mismo cuerpo, 201 y Location. Otro payload: 409. Lock/statement timeout: 503
   transitorio, cliente reintenta la misma clave. Las operaciones no esperan servicios externos.

Database fija por defecto 24 h desde inserción de la fila; esa ventana sigue **PROPUESTA**,
no aprobación global. Tras caducar: 409 IDEMPOTENCY_EXPIRED y reconciliación explícita;
no borrar ni reutilizar la clave automáticamente. No existe endpoint de reconciliación
ni tarea de limpieza. Retención y eliminación requieren decisión antes de producción.
Dos claves diferentes crean dos activos, aunque el cuerpo sea igual.

Evidencia PostgreSQL 16.15: dos threads/conexiones, barrera en before_insert de la solicitud
que fuerza a ambas transacciones a pasar el SELECT inicial antes de competir. Se verifica
mismo snapshot, una fila de activo y una solicitud. Otras pruebas comprueban claves distintas,
ámbito por usuario, conflicto de payload, fallo inyectado tras insertar activo y antes de
commit (cero filas), reintento recuperado, respuesta descartada tras commit y expiración.
Los tests no simulan una desconexión TCP real a mitad del commit: esa prueba queda pendiente.

Estas garantías se verificaron en el servicio con permisos sintéticos de fixture. El flujo
móvil → API autorizado → PostgreSQL sigue bloqueado por propiedad/ACL; no se reclama una
idempotencia operativa de extremo a extremo hasta resolverlo.

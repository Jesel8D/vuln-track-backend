# Idempotencia autenticada y propiedad — PROPUESTA V1.1

Se mantiene el algoritmo transaccional V1 y el contrato de snapshots. Ruta HTTP
`/api/v1/assets`, ámbito persistido exactamente `POST /assets` por el CHECK real.
Clave UUID canónica de 36 caracteres; ámbito PK `(user_id,method,route,idempotency_key)`.
Huella SHA-256 de JSON canónico versionado (1), NFC/strip, opcionales null, método/ruta.
No incluye un propietario del cliente: el actor ya forma parte del ámbito persistido.

1. Autenticar usuario activo y usar su UUID validado. El cliente no envía created_by.
2. En una transacción READ COMMITTED, buscar registro previo. Si falta, insertar activo
   con created_by=actor y la solicitud/snapshot, confirmando ambos juntos.
3. En una carrera, la PK de solicitud determina el ganador. SQLSTATE 23505 de esa PK
   revierte **también** el activo perdedor y su propietario; después se recupera el snapshot
   confirmado en una transacción nueva. No basta el SELECT inicial.
4. En replay, comprobar visibilidad por propiedad **antes** de comparar hash/expiración.
   Si el activo ya no pertenece al actor o es histórico sin dueño: 404 sin snapshot,
   incluso si existe un registro técnico previo para ese usuario. No infiere propiedad.
5. Misma clave/cuerpo/actor devuelve idéntico 201, cuerpo y Location. Payload distinto:
   409. Usuario B con la misma clave tiene otro ámbito y puede crear su propio activo,
   pero nunca recibe el de A. Consultarlo directamente devuelve 404.

24 h desde inserción sigue siendo ventana PROPUESTA. Una clave vencida no se borra ni
reutiliza automáticamente: 409 para el propietario, reconciliación pendiente. Expiración
no cambia propiedad ni revela recursos de terceros. Distintas claves pueden crear activos
idénticos: no se implementa deduplicación de inventario. Lock/pool/statement timeout: 503,
reintentar misma clave/cuerpo; nunca abrir transacción esperando un servicio externo.

Pruebas V1.1: login y política reales, dos peticiones HTTP concurrentes con barrera en
inserción de solicitud para forzar ambas lecturas de ausencia. Una alta/solicitud/owner
confirmados; replay del ganador. Se prueban distintas claves, misma clave con payloads
distintos (201/409), dos usuarios con misma clave, FK, rollback antes de commit y retry,
revocación de propiedad, baja de cuenta, históricos y expiración. Se comprueba el vínculo
persistido Asset.created_by = solicitud.user_id para cada alta concurrente.

La pérdida de respuesta se simula descartando un resultado ya confirmado y repitiendo:
no es una desconexión TCP real durante commit. Esa prueba de transporte y la integración
móvil siguen pendientes. No se usan políticas sintéticas como evidencia V1.1.

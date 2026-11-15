# Autorización de destinos — Fase 1

## Qué existe y qué acredita

`application_targets` pertenece a una aplicación mediante FK compuesta
`(workspace_id, application_id)`. Registrar una URL crea una declaración `pending`,
no una autorización para conectarse. El alta genera `target.created` en la misma
transacción.

Owner/editor pueden declarar `approved` con referencia y vencimiento futuro de
hasta un año. Viewer solo puede leer. Es una **declaración del miembro del
workspace**, sin prueba de titularidad legal o control técnico del dominio.
Ni una casilla ni un ticket introducido por ese miembro constituyen verificación.
No existe un administrador global nuevo.

La API conserva los estados SQL publicados: `pending`, `approved`, `rejected`,
`expired`. Las lecturas derivan `expired` al vencer una aprobación; no reescriben
el registro. Una retirada usa el PATCH existente con `rejected`, referencia del
motivo y `expected_updated_at`. Cuando el estado anterior era `approved`, esta
fase registra `target.authorization.withdrawn`; los rechazos desde otros estados
conservan `target.authorization.rejected`. Los eventos anteriores no se alteran.
El estado `rejected` por sí solo no permite distinguir rechazos de retiradas
históricas: la interfaz dice «rechazada o retirada».

## Modelo de verificación y respuesta real

**IMPLEMENTADO CON LIMITACIONES:** `ControlEvidence` es un contrato interno
inmutable para una futura salida de verificador confiable. Vincula workspace,
aplicación, destino, origen canónico, versión de la declaración, método, digest
de evidencia, instante de verificación, expiración y revocación. Las validaciones
locales rechazan IDs/orígenes/versiones distintos, evidencia incompleta, futura,
vencida o revocada. No es una capacidad ejecutable ni un modelo de petición.

**PENDIENTE:** productor confiable, persistencia de evidencias, desafío remoto,
revisión administrativa y su API. Actualmente ningún endpoint acepta evidencia
ni marca un destino como verificado. `public_target` siempre evalúa sin evidencia.
No se convirtió ninguna aprobación histórica en verificación.

Las respuestas existentes de alta, listado y actualización añaden
`analysis_readiness`, con política, estado de autorización derivado,
`control_verified`, `url_policy_allowed`, `execution_enabled` y motivos de bloqueo.
No cambian los campos históricos ni se añaden endpoints de ejecución.

| Concepto | Representación en esta fase |
|---|---|
| Destino registrado | SQL `pending`; readiness `registered` |
| Autorización solicitada | Contrato `requested`; falta un flujo persistido de solicitud |
| Verificación pendiente | Declaración `approved` completa y vigente; `verification_pending` |
| Control verificado | Contrato local `verified`; no existe productor/registro real todavía |
| Rechazo | SQL `rejected`; no autoriza operaciones protegidas |
| Revocación | Retirada de declaración como `rejected` y evento `withdrawn`; revocación de evidencia prevista por el contrato local |
| Expiración | `expired` derivado de vigencia; evidencia vencida deja de acreditar control |
| Datos incompletos | Readiness `incomplete`; falla cerrado |

Incluso la evidencia válida construida por una prueba local deja
`execution_enabled=false`: faltan transporte con IP fijada, aislamiento y executor.
No hay un flag de entorno que lo active. La interfaz valida ese `false` literal,
los motivos obligatorios y la consistencia de estados. Requiere el Backend de
esta fase; ante una respuesta antigua/incompleta muestra error de contrato y
mantiene el botón deshabilitado.

## Aislamiento y auditoría

**IMPLEMENTADO Y PROBADO:** JWT identifica al usuario; el contexto HMAC firmado
se instala con SET LOCAL dentro de cada transacción. Las políticas RLS y FK
compuestas impiden trasladar destinos entre aplicaciones/workspaces. La API
comprueba membresía y roles en PostgreSQL, no en IDs o roles enviados por React.
Una aplicación archivada no admite estas escrituras.

La fila se bloquea con FOR UPDATE y se compara `expected_updated_at`: dos
actualizaciones concurrentes con la misma versión tienen un ganador y un 409.
Alta/actualización y evento son atómicos; un fallo al insertar auditoría revierte
la declaración. Las conexiones reutilizadas no conservan el contexto tras commit
o rollback. No se desactiva RLS ni se conceden privilegios nuevos.

La API no ofrece lectura de auditoría ni gestión de miembros. El login de API no
puede seleccionar `audit_events`; la revisión operativa requiere un operador
autorizado. Los eventos actuales conservan actor, objeto, acción y fecha, pero no
son un almacén completo del contenido histórico de referencias o pruebas.

## Mecanismos evaluados y decisiones pendientes

- DNS TXT: desafío aleatorio de un solo uso, vinculado al origen/recurso, con
  expiración, protección de repetición y auditoría de evidencia. Debe resolver
  mediante un servicio acotado y no confundir control DNS con permiso legal.
- Archivo HTTP: ruta fija de desafío, respuesta pequeña, sin credenciales ni
  redirecciones, IP previamente validada y fijada manteniendo Host/SNI/TLS.
  Está bloqueado hasta disponer de ese transporte y su red de salida.
- Verificación administrativa: rol/revisor de alcance limitado y evidencia
  documentada; no basta con que el owner se apruebe a sí mismo. No se implementó
  un rol administrador global ni un endpoint de auto-verificación.

Jesel y Rudi deben decidir método, revisores, alcance por origen/ruta, caducidad,
renovación, revocación y retención. Si requieren nuevos datos, Database debe
preparar SQL incremental y Backend coordinar modelos/Alembic/catálogo según D-002,
con ensayos desechables. No hace falta modificar el esquema para mantener esta
fase cerrada; no hay migración SQL en estas ramas.

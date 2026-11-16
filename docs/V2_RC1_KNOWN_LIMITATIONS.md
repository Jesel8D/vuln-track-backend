# RC1 — limitaciones y decisiones pendientes

**IMPLEMENTADO CON LIMITACIONES:** candidato de desarrollo local para revisión
académica controlada. No equivale a producción ni a entrega final aprobada.

- NVD corre en fixture. El aviso visible lo identifica; la captura no es actual
  ni demuestra vulnerabilidades en una aplicación real. El CPE identifica un
  producto; su elección requiere confirmación explícita.
- La captura CVE-2017-6784 contiene condiciones AND y hardware adicional. El
  resultado se conserva **undetermined**, incluso después de revisión manual.
  La recomendación es una medida ficticia redactada por el usuario. Nunca se
  convierte automáticamente en vulnerabilidad confirmada o reparación efectiva.
- La URL example.com es solo una referencia guardada en el inventario. El
  recorrido no la solicita ni usa enlaces externos. No hay descubrimiento de
  tecnologías, escaneo de URL, NVD live ni ZAP en la demostración.
- Declarar autorización no prueba control técnico del dominio. Se pueden emitir,
  consultar y revocar desafíos persistentes, pero verify responde 503. La
  evidencia de laboratorio nunca habilita verified ni Baseline. Egreso público,
  verificación remota y todo escaneo permanecen **BLOQUEADOS**.
- El gateway de Fase 2C es un laboratorio de redes internas, con componentes
  confiables y fixtures propios. No certifica una plataforma pública, un gateway
  comprometido ni el aislamiento de toda la VM/host. Sus latencias medidas no
  son SLA. No se modificó el firewall global ni el daemon Docker.
- La sesión JWT queda solo en memoria. Recargar o abrir otra pestaña requiere
  login; logout limpia UI/caché pero no revoca individualmente el JWT servidor.
  Reinicio conserva claves; restore genera nuevo secreto JWT e invalida tokens
  anteriores. No hay recuperación de contraseña ni refresh tokens.
- Workspaces tienen roles owner/editor/viewer; no hay administración pública de
  miembros ni administrador global en estas pantallas. Los controles de SQL/API
  no se sustituyen por la selección del cliente.
- Los esquemas de algunas respuestas V2 en OpenAPI siguen siendo permisivos;
  los ejemplos no son validadores nuevos. Se mantienen los validadores estrictos
  del cliente y el contrato existente de 44 operaciones.
- Las consultas tienen presupuestos/cuotas y cobertura explícita; completed no
  significa catálogo exhaustivo ni sistema seguro. El dashboard cuenta abiertos
  del último análisis por tecnología; una revisión puede reducir ese contador
  sin eliminar el CVE ni confirmar su aplicabilidad.
- Pruebas de interfaz en Chromium Linux, anchos 375/768/1280/1440 y axe. No se
  probaron Safari, Firefox, lector de pantalla real, todos los dispositivos o una
  aplicación móvil nativa. Las suites UI históricas V1 no corresponden al router
  actual V2 y se conservaron sin ejecutarlas como si fueran V2.
- El dump y la configuración privada son sensibles: contienen hashes de usuarios
  y claves de contexto. Se verificaron permisos 0600 y exclusión Git; no se
  publicaron. El backup local no sustituye copia externa cifrada, rotación,
  recuperación ante pérdida de disco ni operación de producción.
- Hay avisos transitivos del runner Newman y una deprecación Starlette/httpx en
  pytest. Se registran en logs privados; no se cambiaron dependencias bloqueadas
  para ocultarlos. Esta misión no es una auditoría nueva de dependencias.
- Los repositorios originales y development permanecen en sus commits anteriores.
  Revisar la RC1 no implica actualizar esa instalación. Cualquier actualización
  personal requiere una misión/ventana posterior autorizada y su backup.

**PENDIENTE:** ratificar alcance web V2 frente a dispositivos V1, responsabilidad
de Jesel/Rudi, definición de móvil, rúbrica académica y entrega final. La única
recomendación técnica posible aquí es GO para revisión local del candidato;
esas decisiones humanas no se dan por aprobadas.

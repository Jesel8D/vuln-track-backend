# Revisión JWT y propuesta de revocación — V1.3

Se conserva identidad local y JWT HS256. No se agregaron tablas, migraciones, sesiones,
refresh o logout servidor. La propiedad de activos y el resto de decisiones pendientes
no se consideran aprobados por este trabajo.

## Comprobaciones implementadas y probadas

- Firma mediante PyJWT con lista fija **HS256**. Tokens none, HS384 y HS512 se rechazan,
  aunque estén firmados con el secreto correcto; clave incorrecta y texto malformado: 401.
- Secreto operativo externo, aleatorio, al menos 32 bytes; no compartir con React/React
  Native, repositorio ni documentación. Cada ambiente debe tener su propio secreto.
- Claims obligatorios: sub, iat, nbf, exp, iss, aud, jti, ver. Subject/jti UUID; issuer
  vulntrack, audiencia estrictamente escalar vulntrack-api; sin aceptar listas de audiencias.
- V1.3 refuerza tipos temporales: enteros reales, sin booleanos/cadenas/flotantes;
  iat <= nbf < exp y duración positiva hasta TOKEN_TTL_SECONDS (máximo 900 s).
  PyJWT comprueba expiración y tiempos futuros, sin leeway configurado. Servidores
  deben mantener reloj correcto; clientes usan expires_in para UX y 401 como autoridad.
- Antes de abrir sesión de datos, JWT inválido/expirado se rechaza. Después se consulta
  usuario activo y versión updated_at exacta. Desactivar, cambiar el usuario o rotar
  TOKEN_SECRET invalida los tokens correspondientes; no existe revocación individual.
- Máximo de token aceptado 2048 caracteres. No ponerlo en query/path ni asumir que
  decodificar su payload en el cliente valida firma o permisos.

La revisión detectó que algunas representaciones temporales convertibles por PyJWT
podían pasar su validación básica. Se endurecieron sin cambiar el emisor propio, que
ya emitía enteros/audiencia escalar. No hay cambio de transporte ni ruptura de tokens
emitidos correctamente por este backend.

## Errores y logs

Respuesta genérica 401/WWW-Authenticate Bearer, sin distinguir usuario/token/revocación.
No se serializa el input de Pydantic ni excepciones con SQL/valores. Los logs técnicos
conservan tipo, SQLSTATE o ubicaciones, no tokens/cuerpos/secreto. Pruebas caplog pasan
credenciales incorrectas y tokens válidos/inválidos/expirados y verifican ausencia de
sus valores. Uvicorn se documenta y se ejecuta sin access log para no conservar URLs
introducidas por clientes. Esa evidencia no certifica logs de un proxy/APM futuro;
configurar redacción también allí. Nunca capturar Authorization ni cuerpos de login.

## Almacenamiento de cliente — recomendación, no cliente implementado

React: preferir token en memoria; refrescar página puede requerir nuevo login. No usar
localStorage/IndexedDB como si protegieran frente a XSS. No hay refresh automático ni
cookie HttpOnly en esta API; adoptar alguno exigiría un diseño nuevo aprobado (incluido
CSRF si corresponde). Bearer explícito, credentials omit para cross-origin.

React Native: si debe persistir, usar un almacenamiento seguro de plataforma basado en
Keychain/Keystore con una biblioteca revisada; no AsyncStorage, archivos comunes, logs,
URLs ni analítica. La selección de biblioteca/plataforma queda para el cliente futuro.

En ambos: HTTPS remoto, limpiar token y caché al salir/cambiar cuenta, proteger notas y
formularios pendientes, y mantener intentos idempotentes vinculados al mismo actor.
Variables VITE_ o EXPO_PUBLIC_ solo para configuración pública como URL base, nunca
TOKEN_SECRET ni credenciales de base. Logout local no invalida un JWT copiado.

## Propuesta futura de revocación individual — NO implementada

Alternativa mínima conservando JWT: registro persistente de revocaciones identificadas
por una huella de (issuer,jti), con sujeto y expiración derivados **del token verificado**.
No guardar JWT ni Bearer completos. Consultarlo en cada acceso junto al estado del
usuario; mantenerlo hasta exp para no revalidar prematuramente un token revocado.
Operación atómica/idempotente, permisos mínimos, auditoría sin tokens y política de
limpieza/retención aprobada. Fallo del almacén debe negar acceso, no permitir por defecto.

Esto requiere aprobación, coordinación D-002, diseño de esquema/privilegios y contrato
para revocar. **No existe hoy una ruta de logout/revocación que un cliente pueda llamar.**
No se creó tabla, ORM, migración ni tarea de limpieza. Tampoco se introduce Redis ni
un sistema alternativo de sesiones. Otra alternativa sigue siendo la propuesta de
sesiones opacas revocables de Context, que necesita evaluación separada.

Pruebas exigibles antes de habilitar esa evolución: dos tokens del mismo usuario,
revocar uno sin afectar al otro, reintento de revocación, expiración/limpieza, replay,
concurrencia, almacén caído y separación entre usuarios/entornos. Hasta entonces, un
JWT robado puede usarse hasta expirar o invalidación de usuario/secreto. El TTL corto
limita esa ventana, no sustituye revocación ni protección del cliente.

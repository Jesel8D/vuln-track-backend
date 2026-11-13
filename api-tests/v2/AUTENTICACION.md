# Autenticación y secretos locales

Registro y login conservan `/api/v1/auth/register` y `/api/v1/auth/login` incluso en V2. El cuerpo de login es JSON username/password, no OAuth password form. Registro devuelve id/username, sin token; login devuelve access_token/token_type/expires_in y Cache-Control no-store. Las solicitudes privadas heredan `Authorization: Bearer {{access_token}}` de la colección.

Los entornos versionados dejan password y expired_token vacíos; los tokens de colección también están vacíos. Introducir la contraseña en el valor **local** del entorno activo y mantenerlo sin compartir. Marcar el tipo secret oculta visualmente el valor, pero no sustituye decidir dónde se guarda ni revisar una exportación. La documentación oficial explica el alcance de [valores locales de variables](https://learning.postman.com/docs/use/send-requests/variables/variables/) y el [Vault local](https://learning.postman.com/docs/use/postman-vault/manage-vault-secrets), que no sincroniza sus secretos al Cloud de Postman. El flujo validado aquí fue Newman, no la integración Vault de la aplicación.

No se necesita guardar claves JWT/HMAC, contraseña SQL ni API key NVD en Postman. No introducir secretos en URL, ejemplos, Git o VITE_*. Las variables capturadas por scripts cambian los valores locales de colección; no compartir ni exportar esa copia después de probar sin vaciar tokens. `run-newman.cjs` evita exportar el entorno o el reporte estándar con credenciales: recibe secretos por stdin y solo escribe respuestas sanitizadas.

La API valida firma HS256, iss/aud, iat/nbf/exp, jti, usuario activo y su versión; por defecto la sesión dura hasta 900 s. Login nuevo reemplaza la variable; no hay endpoint de refresh ni logout/revocación individual. Cerrar Postman no revoca un JWT emitido.

El runner firma un JWT estructuralmente válido y ya expirado con su clave **efímera**, sin revelar la clave. El caso exige 401. Para Postman manual, usar un token privado emitido por esa misma API que haya expirado y guardarlo localmente en expired_token; si está vacío, ese único caso se omite. Un texto malformado no se presenta como prueba de expiración.

La cuenta A tiene su workspace personal owner; B es otra cuenta real de registro. La colección comprueba que B no enumera A y que recibe 404 al acceder al workspace/aplicación/activo de A. Ese 404 oculta existencia; no se intenta saltar RLS, cambiar GUC ni asumir roles SQL. Owner de workspace no es administrador global; el alta rechaza `is_admin` y otros campos internos.

Antes de una repetición completa, el primer registro crea otro username UUID y limpia las variables del flujo. Para continuar con la misma cuenta después de expirar el token, ejecutar solo login y después me; no volver a registrar el mismo username deliberadamente salvo para probar el 409 de duplicado.

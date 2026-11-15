# Contrato de verificación persistente — Fase 2B

Prefijo: /api/v2/workspaces/{workspace_id}/applications/{application_id}/targets/{target_id}/verifications.
Requiere SQL008, JWT Bearer y contexto HMAC de workspace. Objetos ajenos se ocultan
como 404. No se cambia el contrato de las 39 operaciones anteriores.

| Operación | Cuerpo | Respuesta |
|---|---|---|
| GET prefijo | Ninguno | 200 ChallengeList, hasta 20 registros recientes |
| POST prefijo | ChallengeIssue: expected_updated_at con zona horaria; Header Idempotency-Key UUID obligatorio | 201 IssueResult nuevo; 200 repetición con instructions=null |
| GET /{challenge_id} | Ninguno | 200 ChallengeRead y metadatos de evidencia |
| POST /{challenge_id}/revoke | ChallengeVersion: expected_version entero positivo | 200 ChallengeRead; repetición revocada sin nuevo evento |
| POST /{challenge_id}/verify | ChallengeVersion | 503 VERIFICATION_EGRESS_UNAVAILABLE para pending vigente; sin red ni intentos |

Lectura: owner/editor/viewer. Escritura: owner/editor. Emisión requiere aplicación
activa, URL HTTPS pública canónica y declaración vigente. Revocación también
funciona en aplicaciones archivadas. El servicio no recibe URL, método, resolver,
token, evidencia o estado del cliente: extra=forbid en los cuerpos Pydantic.

ChallengeRead contiene IDs del scope, origen y método, state persistido y
effective_state derivado, scope_invalidated, versión, contador, fechas reales,
result_code y evidencia de laboratorio limitada a IDs/procedencia/resultado/fechas.
No contiene digests, IP, certificado, cuerpo, request_key ni referencias privadas.
control_verified, remote_verification_available y execution_enabled son false
en este contrato. verified es estado SQL reservado y no acredita confianza al
leerlo: el servicio actual no tiene productor de verificación operativa.

IssueResult incluye challenge, created e instructions. Solo created=true entrega
URL fija /.well-known/vulntrack-verification/{id} y cuerpo aleatorio de propósito
único. Middleware aplica Cache-Control: no-store; no guardar ese cuerpo en logs,
entornos Postman, query cache o localStorage. El servidor almacena solo su digest.
No se puede recuperar el token: revocar y emitir otro si se perdió la respuesta.

Conflicto de versión/idempotencia o segundo pending: 409. Destino no elegible o
payload inválido: 422. JWT ausente/inválido: 401. Membresía/scope no disponible:
404. Cuota workspace agotada: 429 con Retry-After. SQL008 ausente o dependencia
no disponible: 503. Los errores contienen solo code/message/request_id saneados.
Llamar verify no es una cola ni una aceptación 202 y no consume el intento.

La evidencia de laboratorio solo puede producirla el rol NOLOGIN separado, nunca
el login API. Match de fixture se almacena como LABORATORY_MATCH_ONLY, sin
verified_at y sin habilitar análisis. Fechas de expiración efectiva o invalidación
no se inventan como eventos persistidos: state/effective_state se distinguen.

OpenAPI y la colección cubren cinco operaciones nuevas, emisión repetida, bloqueo
503, revocación y casos ajenos/forjados. El baseline previo permanece intacto;
verification-contract.json fija únicamente los contratos añadidos. La colección
contiene 71 solicitudes definidas y redacta cuerpos de desafío antes de guardar
ejemplos/informes. Los ejemplos publicados usan tokens vacíos, no pruebas reales.

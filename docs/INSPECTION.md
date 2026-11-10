# Inspección y trazabilidad (30-10-2026)

No había checkout en /workspace: .git estaba vacío y git status fallaba.
Se comprobó acceso HTTPS y se clonó el backend en /workspace/vuln-track-backend.
Base limpia main: b5e71f24ee10793a87b161a3aba3f1b3b19c6d07.
Se creó feat/backend-v1-assets antes de modificar archivos. No se identificó una
rama administrada por Cloud en este workspace. No se tocó main ni el frontend.

Referencias públicas clonadas solo para lectura:
- Database, feat/postgresql-database-v1: b493fd17e9290ca94fa085d49230073ed1837e1a.
- Context, dev/jesel: d481061e5ecb53b9a033086481add37f04d8c549.

El primer acceso sin permisos de red no alcanzaba el proxy. Los comandos con acceso
habilitado y las comprobaciones posteriores sí accedieron; no se modificaron proxy,
TLS ni políticas de seguridad. Los checkouts de referencia quedaron limpios.
No hubo credenciales GitHub configuradas ni mecanismo de PR asociado al checkout;
la entrega es una rama/commit local, sin push, merge ni cambios remotos.

Los documentos conceptuales anteriores a Database V1 dicen que atributos/relaciones
están pendientes. Para los mappings se priorizó el SQL materializado y el diccionario
SCHEMA del commit de Database indicado. No se tomó un documento PROPUESTA como
aprobación. D-001/D-002 se respetan. No se reutiliza user_id técnico como propiedad.

Todos los archivos prioritarios están disponibles. Inventario inspeccionado y SHA-256
para identificar exactamente las fuentes (no contiene secretos operativos):

## Context

| Archivo | SHA-256 |
|---|---|
| `README.md` | `0ce96d064040a0cda4c5f3257ee32f3265b6f59b8733f36c58401bcbdab6fe4d` |
| `AGENTS.md` | `7812c068442fd5f38651408ca41128215f481e5fa95b4f68b10afaa49efc38d8` |
| `context/project.json` | `34adb0cd8cb64dd51115d339be09be8c4b6196b49797e668f1cb88593edb06b2` |
| `context/decisions.json` | `7dabfd14865f7463452da56ecf4fc110f8929e6ad75d047ad10d9e3181d047ab` |
| `docs/PROJECT_CONTEXT.md` | `342f7c1aec776ce758e68fc4c50400dc058b4f7b96cd3e9ccaf7c8bf15cdf68d` |
| `docs/REQUIREMENTS.md` | `d666b2b3532a004b2942f9198d13f0902011fb03f54bae8b9817d8e532bbd61b` |
| `docs/ARCHITECTURE.md` | `6160a298f35eec4b1845a034bab3b3897255d74ff65e7cea0899c550afa4c47f` |
| `docs/API_CONTRACT.md` | `749b503491adaf5be6e474f41153039cc9e533c24d19a43abdac04d6987004c2` |
| `docs/DATA_MODEL.md` | `a7034bbe161c5979582d1b593dd06e86473b4c3e6140e8bad915fd5a29885381` |
| `docs/SECURITY_BOUNDARIES.md` | `a8dca4c28edb0dbe7b61ac164e8f81c6639eacdbbffd6a49bd3131e064542204` |
| `docs/IMPLEMENTATION_MASTER_PLAN.md` | `15329ffdb9a363291a9d65702850fcd1b68adac07c73dc0799d55796b7420d32` |
| `docs/DEVELOPER_WORK_DISTRIBUTION.md` | `381155c3fb8ad9b0bf86e9dbd8c54b59987efcb9faf67aa09c7a942550d59c09` |
| `docs/TEST_STRATEGY.md` | `e47774568b781da08686dc5a2582fe7ab43906378b0ab9a402ef4f950ba57739` |
| `docs/TECHNICAL_RISK_REGISTER.md` | `f02d417acbbbe6204e30a218335235558bd20ced31a9f05479c2241e4157a9f6` |
| `docs/ASSET_CONTRACT_PROPOSAL.md` | `305029113c1af963f12203d42150e02b915411c19c07f13d4053bb8aae8abed0` |
| `docs/DATA_MODEL_PROPOSAL.md` | `98e56ad480aa54bcf8c81279d8b9456852c5ef11985598fae3e539f6c079f300` |
| `docs/IDENTITY_AND_ACCESS_PROPOSAL.md` | `6585606a334594fd580d1387747fd72f0e08fa6e92c458f7669d109a1787d2a6` |
| `docs/INTEGRATION_SECURITY_REVIEW.md` | `4959fb473bca7cb7a4baf8e7bc0696ca6571d40de9161f60b5dbea45ff37896d` |
| `docs/DATABASE_V1_PROGRESS.md` | `9d1c44c66a7e1da1a4c3ed0eb35b942cdb1d2487c8f18107fb43c32a2294bec2` |
| `docs/DECISIONS_AND_OPEN_QUESTIONS.md` | `54cc8a39777e3a7d7a1a0a16281efba8e7aff5d37b19677e3bbe2b6efa52678d` |

## Database

| Archivo | SHA-256 |
|---|---|
| `README.md` | `c672c507769511c5df23fe677808a2bfa70b88b34ccbcf61a2a5a250552d2b1c` |
| `compose.yaml` | `430a02e137779c4af6649304c4f49dde339a74f4e984284fa5c1de78b2396e04` |
| `.env.example` | `a6035caee3311614435552a32872c941e758697b94d29edbdfd130ce7bfb6e8b` |
| `sql/001_schema.sql` | `fd2984a80911cd094283d9c9b1f503a7a0db87b921f9169c2a8362a8941b9297` |
| `sql/002_privileges.sql` | `46f0b4f0093fa579ee27e4e8e348d97d8fe5db515b6bbbef1aa7a479f67a3f2e` |
| `sql/003_queries.sql` | `71c316170fd642f385c5730ebfb9f80654d08eb477d4029807242f9f29fc9fee` |
| `seed/001_demo.sql` | `ab2a079cfaf7f1800beb6103f1a34d5f480df2defd9c180f974342f49db097ef` |
| `tests/001_integrity.sql` | `cc9b373a3895e857ab2c6acb8e7f1e897786d7c1c2a165bb512e1ce079be1193` |
| `tests/run.sh` | `016b4d496b02486ca6d4afe3c935143e34566ae1dc9e3f4054248acc8455cecc` |
| `docs/SCHEMA.md` | `362c90a8def181e717ad4e7796412f73515b3913f28f45782d115157cd30cd0a` |
| `docs/PROVISIONAL_DECISIONS.md` | `e5f4076db7b090a09eb5d8bd69cc23215a42be641e62585bc8eac5f13bc23676` |
| `docs/TEST_RESULTS.md` | `60a4f61cf2beef4655b4ce1832233512ac70b53e1d019db83e4506c3beeba2fd` |

## Continuación V1.1

Se verificaron otra vez rama limpia y existencia de 578f74a antes de modificar código.
Se leyeron SQL/privilegios, modelos, verificador, autenticación, servicios idempotentes,
fixtures y pruebas. Las referencias locales conservan los commits arriba identificados
sin cambios. La autorización de esta misión permite preparar propiedad y migraciones
para ensayo desechable; no cambia el estado pendiente de aprobación ni autoriza aplicar
DDL persistente. No se repitieron accesos de publicación ni operaciones de credenciales.

## Preparación de integración V1.2

Inicio verificado en 8546b48650b93ac4b4135dcdf32fa51d8a5454c4, misma rama limpia.
Se revisaron Alembic, ORM, catálogo/SQL/privilegios/seed reales, autenticación, middleware,
servicios y tests; se repitieron 56 pruebas antes de cambios. Las referencias mantienen
los mismos commits y checkouts limpios, sin nuevas operaciones de publicación. El patch
propuesto se deriva exclusivamente de 001_schema.sql fijado y se aplica en copia temporal.
Ambas rutas se probaron en servidores nuevos tmpfs; no hubo SQL contra persistentes.

## Preparación web/móvil V1.3

Inicio comprobado en 3d23a1afdf5fae1321c90abf91ea874408977dfa, misma rama limpia.
Se revisaron CORS (antes ausente), Settings, JWT, dependencias y contratos reales.
Suite previa: 71 aprobadas con PostgreSQL. Se mantienen rutas y esquema 0002; no se
modifican migraciones, modelos ni repositorios externos. CORS queda vacío por defecto;
se ensayan perfiles explícitos de pruebas y Docker únicamente sobre bases desechables.

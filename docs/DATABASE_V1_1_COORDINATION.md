# Contrato de coordinación Database V1.1 / Backend V1.1 — preparación V1.2

**PROPUESTA pendiente de aprobación formal.** Se autoriza preparar, revisar y probar
en PostgreSQL desechable, no integrar definitivamente ni modificar datos persistentes.
No se editaron Database ni Context. D-002 permanece APROBADA: Database posee
bootstrap/SQL/seed/infraestructura; Backend posee ORM y migraciones Alembic. V1.2
prepara la integración; no introduce una tercera revisión de esquema ni nuevos endpoints.

## 1. Referencias y diferencia exacta

Database: rama `feat/postgresql-database-v1`, commit
`b493fd17e9290ca94fa085d49230073ed1837e1a`. Context: `dev/jesel`,
`d481061e5ecb53b9a033086481add37f04d8c549`. Backend inicial de esta misión:
`8546b48650b93ac4b4135dcdf32fa51d8a5454c4`.

| Elemento | Database V1 real | Esquema propuesto que necesita Backend |
|---|---|---|
| Tablas | users, assets, analysis_runs, findings, asset_registration_requests | Las mismas cinco |
| assets.created_by | No existe | UUID nullable, sin default |
| FK de propietario | No existe | assets_created_by_fkey → vulntrack.users(id), ON DELETE RESTRICT |
| Índice de propietario | No existe | assets_owner_created_id_idx (created_by, created_at, id) |
| FKs de dominio | Cinco, restrictivas | Seis, todas restrictivas |
| Resto de columnas/checks/PK/UNIQUE/triggers/funciones | SQL original | Sin cambios |
| Privilegios de propiedad | SELECT/INSERT sobre tabla assets | Los mismos, sin UPDATE/DELETE/DDL para API |

No hay cascada de borrado ni generación SQL de propietario. ON UPDATE conserva NO ACTION
por defecto. Los IDs siguen siendo UUID, no enteros ni username. El índice compuesto
atiende búsqueda por owner y orden/paginación estable, además del acceso para la FK.
No se elimina el índice global existente `(created_at,id)`.

## 2. Definición SQL propuesta

Equivalencia de estado final de la migración 0002, **no ejecutar además de Alembic**:

```sql
ALTER TABLE vulntrack.assets
    ADD COLUMN created_by uuid NULL,
    ADD CONSTRAINT assets_created_by_fkey FOREIGN KEY (created_by)
        REFERENCES vulntrack.users(id) ON DELETE RESTRICT;
CREATE INDEX assets_owner_created_id_idx
    ON vulntrack.assets (created_by, created_at, id);
```

La migración Alembic añade los objetos en una transacción, no recrea tablas. Usa índice
normal, no CONCURRENTLY, para conservar atomicidad. Copias grandes requieren medir
bloqueos/tiempo y revisar el plan antes de una integración aprobada.

## 3. Históricos, seeds e identidad

NULL es necesario para conservar registros existentes sin inventar propietario.
No hay UPDATE/backfill ni deducción desde análisis o solicitudes idempotentes.
NULL nunca concede acceso ordinario. La API establece propietario únicamente desde
current_user y rechaza created_by del cliente. No hay administrador global, endpoint
de asignación ni reasignación. Cualquier asignación histórica futura necesita autorización,
trazabilidad y una operación distinta explícita.

El seed original omite created_by y sigue funcionando sin cambios: tres activos sin dueño,
usuario demo inactivo/sin hash utilizable, dos análisis y un hallazgo sintético. Se prueba
también repetirlo. No se reactiva demo ni se le asigna contraseña.

La autenticación local necesita provisionar un login API dedicado y concederle lectura
de password_hash. Eso sigue separado de la propiedad: el parche **no** amplía el grupo
vulntrack_app ni crea usuarios funcionales. Las pruebas originales de privilegios V1 se
corren antes de conceder ese permiso solo al login de prueba temporal.

## 4. Paquete revisable para Database

En `docs/proposals/`:

| Archivo | Naturaleza |
|---|---|
| database-v1.1-bootstrap.patch | Patch mínimo sobre sql/001_schema.sql original, para instalaciones nuevas |
| database-v1.1-manifest.json | Commit y SHA-256 de entrada/patch/salida para reproducibilidad |
| database-v11-ownership.sql | Fragmento equivalente informativo heredado de V1.1; probado en copias, no un segundo migrador |

SHA-256 entrada V1:
`fd2984a80911cd094283d9c9b1f503a7a0db87b921f9169c2a8362a8941b9297`.
Salida propuesta:
`70d775f97eca5f1bee815dff28f66d3c45edecb49294c03e5bc3bc145386608a`.

Validar/materializar sin modificar el checkout Database:

```bash
source .venv/bin/activate
python scripts/database_proposal.py --database-v1 ../vuln-track-database
review_dir="$(mktemp -d)"
python scripts/database_proposal.py --database-v1 ../vuln-track-database \
  --output "$review_dir/001_schema.sql"
git -C ../vuln-track-database apply --check \
  "$PWD/docs/proposals/database-v1.1-bootstrap.patch"
```

El generador aplica el patch únicamente en una copia temporal, verifica hashes y no
sobrescribe el archivo de salida. No ejecutar `git apply` sin --check en Database durante
esta misión. Si cambia el commit o SQL, detener integración y revisar; no actualizar hashes
para ocultar divergencia. Este paquete no copia/reemplaza Compose ni el bootstrap completo.

Después de aprobación, los responsables de Database deberán preparar allí una rama/PR
con el patch, actualización de SCHEMA/decisiones/diagrama/README y pruebas para seis FKs,
NULL histórico e integridad de propietario. El SQL original de pruebas espera cinco FKs:
no se proclama compatible sin cambios con V1.1. Se conserva y ejecuta intacto para V1;
Database deberá agregar/versionar pruebas V1.1 explícitamente. No alterar asserts para
ocultar pérdida de integridad.

## 5. Instalaciones existentes: solo Alembic

Estados de entrada admitidos: V1 exacto sin versión o con `0001_database_v1`; destino
`0002_asset_owner`. Para V1.1 ya reconocido, upgrade head es repetible y no rehace DDL.
Esquema/revisión desconocidos o múltiples detienen la operación. No aplicar el patch
bootstrap ni reaplicar 001 a volúmenes con datos.

Procedimiento futuro, **solo tras aprobación y primero en una copia restaurada**:
identificar instancia/volumen/revisión; backup y restauración verificada; parar escrituras;
provisionar URL de mantenimiento de esa copia en el shell, nunca en el proceso API.

```bash
read -rsp 'URL de mantenimiento de la COPIA: ' MIGRATION_DATABASE_URL; echo
export MIGRATION_DATABASE_URL
alembic current
alembic -x ownership_proposal=1 upgrade head
alembic check
unset MIGRATION_DATABASE_URL
```

El parámetro reconoce ejecución de una propuesta, no acredita aprobación formal ni
autoriza bases persistentes. El guard valida antes/después en una transacción; timeout
(lock 5 s/sentencia 60 s) o fallo revierte DDL y revisión. Downgrade que perdería propiedad
está bloqueado: resolver mediante restauración o una migración hacia adelante revisada.

## 6. Instalaciones completamente nuevas

**Ruta A, disponible sin cambiar Database:** bootstrap V1 original → Alembic 0001/0002.
El runner predeterminado la ejercita desde un servidor vacío. Es también la ruta de
actualización para bases V1 existentes; se prueba preservar datos de un template V1.

**Ruta B, propuesta para el futuro bootstrap Database V1.1:** 001 con el patch aprobado →
002 original → seed original opcional → reconocimiento explícito verificado. No ejecutar
0002 sobre una columna que el bootstrap ya creó, ni declarar el historial sin comprobarlo.
El bootstrap se prueba en un servidor completamente nuevo y dedicado; 002 crea un rol
global NOLOGIN y no está diseñado para repetirse sobre un clúster que ya lo tenga.

La nueva herramienta `app.db.adopt_schema` comprueba catálogo V1.1 y ORM exactos antes
de registrar 0002 en public.alembic_version. No añade columnas ni toca filas de negocio.
Acepta solo ausencia de revisión o 0002 correcto (idempotente); jamás reemplaza 0001 u
otra revisión. Repite validación después de registrar, dentro de la misma transacción.

En la **copia de prueba con bootstrap V1.1**, tras cargar SQL/privilegios:

```bash
read -rsp 'URL de mantenimiento de la COPIA nueva: ' MIGRATION_DATABASE_URL; echo
export MIGRATION_DATABASE_URL
python -m app.db.adopt_schema --confirm-proposal
alembic check
alembic -x ownership_proposal=1 upgrade head
unset MIGRATION_DATABASE_URL
```

No usar `alembic stamp head` directamente: continúa bloqueado cuando no coincide el
esquema/revisión. El reconocimiento interno de versión tiene validación previa explícita,
no es un stamp ciego ni un atajo para V1. Una base con created_by pero revisión 0001 es
un estado inconsistente que exige revisión; no se reetiqueta automáticamente.

## 7. Procedimiento reproducible verificado, solo desechables

Desde Backend con dependencias instaladas y el checkout Database V1 original accesible:

```bash
DATABASE_V1_PATH=../vuln-track-database python scripts/test_postgres.py -q
DATABASE_V1_PATH=../vuln-track-database python scripts/test_postgres.py --bootstrap-v11 -q
```

Cada comando crea un contenedor nuevo, contraseña aleatoria y tmpfs, con puerto solo
localhost. No acepta una base externa como destino. Primero aplica SQL original o el
patch materializado según ruta, sin editar las referencias. Ruta A ejecuta además las
55 aserciones originales V1 sin cambios antes de migrar. Ruta B verifica seis FKs mediante
catálogo/ORM, repite seed y comparte las pruebas reales de login/activos/autorización/
idempotencia. Solo excluye en esa ruta el test que necesita específicamente V1 sin migrar,
ya cubierto en la suite completa. Ver números exactos en TEST_RESULTS.md.

Validaciones: tablas, tipos/nulabilidad/defaults, PK/FK/UNIQUE/checks, índices, funciones,
triggers y su estado habilitado, datos históricos/seed, revisión Alembic, políticas de
usuario, owner y replay concurrente. Fallos de adopción no dejan revisión falsa; locks
serializan herramientas cooperantes y agotan espera de forma segura. La API no migra al
arrancar; readiness devuelve 503 si aún falta la columna.

## 8. Fuente de verdad y protocolo de integración (D-002)

No hay dos migradores: instalaciones existentes usan Alembic, instalaciones vacías
pueden usar el bootstrap coordinado y reconocerlo tras validación. El patch es una
propuesta derivada del SQL original, no un segundo bootstrap mantenido independientemente.
Ambas rutas deben producir el mismo catálogo verificable y ORM; si difieren, el release
se bloquea. No ejecutar el fragmento ALTER informativo además de ninguna ruta.

Antes de integrar: responsables aprueban decisión en Context, revisan PRs de ambos repos,
fijan commits/hashes, conservan backup, ensayan ambas rutas y coordinan despliegue API/DB.
Database no se modifica/publica desde esta misión. No hay merge automático, secretos en
Git ni cambios de main. Una aprobación futura debe registrarse, no inferirse de tests.

## 9. Riesgos y decisiones pendientes

Propietario único, política de históricos, retención/24 h idempotente y política JWT siguen
pendientes. El catálogo no certifica todo el servidor, grants futuros ni restauraciones;
la cuenta SQL es confiable y privada, no existe RLS para clientes SQL arbitrarios.
La serialización es cooperativa: requiere ventana de mantenimiento y evitar DDL externo
concurrente, no protege frente a un administrador hostil. Medir locks/índice en copias
representativas. El helper de adopción necesita credencial de mantenimiento, nunca API.
CORS web, TLS remoto, límites compartidos, backup/restauración, carga y desconexión TCP
durante commit siguen pendientes. No se declara preparación para producción.

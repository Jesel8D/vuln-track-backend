"""Generate the versioned collection/spec from the real app; no database connection."""

import importlib
import json
import pprint
import secrets
import subprocess
import sys
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from app.core.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402

HERE = Path(__file__).resolve().parent
BASE = "/api/v2/workspaces/{{workspace_id}}"
APP = BASE + "/applications/{{application_id}}"
TECH = APP + "/technologies/{{technology_id}}"
RUN = APP + "/analyses/{{analysis_id}}"
FIND = APP + "/findings/{{finding_id}}"
ASSET = "/api/v1/assets/{{asset_id}}"
ARUN = ASSET + "/analyses/{{asset_analysis_id}}"
AFIND = "/api/v1/findings/{{asset_finding_id}}"
CPE_ID = "c817e5ba-62c1-41e7-a15c-fb851fea761e"
CPE = "cpe:2.3:o:cisco:small_business_rv340_firmware:1.0.0.33:*:*:*:*:*:*:*"
REQUESTS = []


def add(
    folder,
    name,
    method,
    path,
    *,
    body=None,
    status=200,
    capture="",
    pre="",
    auth="inherit",
    headers=None,
    error=None,
    description="",
    fixture=False,
):
    REQUESTS.append(
        dict(
            folder=folder,
            name=name,
            method=method,
            path=path,
            body=body,
            status=status,
            capture=capture,
            pre=pre,
            auth=auth,
            headers=headers or {},
            error=error,
            description=description,
            fixture=fixture,
        )
    )


SET = "pm.collectionVariables.set"
UUID = "pm.variables.replaceIn('{{$guid}}')"
add("01 · Estado", "Health", "GET", "/health", auth="noauth")
add("01 · Estado", "Readiness", "GET", "/ready", auth="noauth")
credentials = {"username": "{{username}}", "password": "{{password}}"}
add(
    "02 · Autenticación",
    "Registrar cuenta única A",
    "POST",
    "/api/v1/auth/register",
    body=credentials,
    status=201,
    auth="noauth",
    pre="".join(
        (
            "const id = ",
            f"{UUID}",
            ".replace(/-/g, '');\n",
            f"{SET}",
            "('username', 'api_' + id);\n",
            f"{SET}",
            "('username_b', 'other_' + id);\n['access_token','workspace_id','a",
            "pplication_id','technology_id','target_id','analysis_id','findin",
            "g_id','recommendation_id','asset_id','asset_analysis_id','asset_",
            "finding_id','identification_id','cpe_name_id','confirmed_cpe'].f",
            "orEach(k => pm.collectionVariables.unset(k));\nif (!pm.variables.",
            "get('password')) throw new Error('Introducir password privado en",
            " el entorno local');",
        )
    ),
    capture=f"{SET}('user_id', data.id);",
    description=(
        "Cada envío inicia otra cuenta de prueba única. Solo en PostgreSQL desechable identificado."
    ),
)
add(
    "02 · Autenticación",
    "Login A y guardar token",
    "POST",
    "/api/v1/auth/login",
    body=credentials,
    auth="noauth",
    capture="".join(
        (
            "pm.test('JWT Bearer', () => { pm.expect(data.token_type).to.eql(",
            "'bearer'); pm.expect(data.access_token).to.be.a('string').and.no",
            "t.empty; pm.expect(data.expires_in).to.be.within(60,900); });\n",
            f"{SET}",
            "('access_token', data.access_token); pm.test('no-store', () => p",
            "m.expect(pm.response.headers.get('Cache-Control')).to.include('n",
            "o-store'));",
        )
    ),
)
add(
    "02 · Autenticación",
    "Identidad A",
    "GET",
    "/api/v1/auth/me",
    capture=(
        "pm.test('Identidad A', () => pm.expect(data.id).to.eql(pm.collec"
        "tionVariables.get('user_id')));"
    ),
)
add(
    "03 · Workspaces",
    "Workspace personal A y membresía",
    "GET",
    "/api/v2/workspaces",
    capture="".join(
        (
            "const own = data.items.filter(x => x.role === 'owner'); ",
            "pm.test('Un workspace personal', () => ",
            "pm.expect(own).to.have.lengthOf(1)); ",
            f"{SET}",
            "('workspace_id', own[0].workspace_id);",
        )
    ),
)
add(
    "03 · Workspaces",
    "Detalle workspace A",
    "GET",
    BASE,
    capture=(
        "pm.test('Creador A', () => pm.expect(data.created_by).to.eql(pm."
        "collectionVariables.get('user_id')));"
    ),
)
add(
    "03 · Workspaces",
    "Workspace adicional: bloqueo RLS conocido",
    "POST",
    "/api/v2/workspaces",
    body={"name": "Workspace API adicional"},
    status=404,
    error="RESOURCE_NOT_FOUND",
    description=(
        "INCIDENCIA EXISTENTE: el contrato anuncia 201 pero la "
        "implementación devuelve 404 (SQLSTATE 42501) durante INSERT "
        "RETURNING bajo RLS antes de la membresía inicial. No se cambia "
        "la política ni se elude RLS. El registro sí crea workspace "
        "personal."
    ),
    pre=f"{SET}('workspace_key', {UUID});",
    headers={"Idempotency-Key": "{{workspace_key}}"},
)
add(
    "04 · Aplicaciones",
    "Crear aplicación de laboratorio",
    "POST",
    BASE + "/applications",
    body={
        "name": "Laboratorio API V2",
        "description": "Fixture aislado; no representa un sistema público",
    },
    status=201,
    capture=f"{SET}('application_id', data.id);",
)
add(
    "04 · Aplicaciones",
    "Listar aplicaciones",
    "GET",
    BASE + "/applications",
    capture=(
        "pm.test('Contiene aplicación A', () => pm.expect(data.items.map("
        "x=>x.id)).to.include(pm.collectionVariables.get('application_id'"
        ")));"
    ),
)
add("04 · Aplicaciones", "Dashboard", "GET", BASE + "/dashboard")
add(
    "05 · Destinos autorizados",
    "Registrar destino local sin escanear",
    "POST",
    APP + "/targets",
    body={"url": "http://127.0.0.1:8080", "label": "Laboratorio local (solo inventario)"},
    status=201,
    capture="".join(
        (
            f"{SET}",
            "('target_id', data.id); ",
            f"{SET}",
            "('target_updated_at',data.updated_at); ",
            f"{SET}",
            "('target_original_updated_at',data.updated_at); ",
            "pm.test('Pendiente de autorización', () => ",
            "pm.expect(data.authorization_status).to.eql('pending'));",
        )
    ),
)
add("05 · Destinos autorizados", "Listar destinos de aplicación", "GET", APP + "/targets")
# Rejection is deliberate: no forged approval/ownership statement.
add(
    "05 · Destinos autorizados",
    "Rechazar autorización de prueba",
    "PATCH",
    APP + "/targets/{{target_id}}/authorization",
    body={
        "authorization_status": "rejected",
        "authorization_expires_at": None,
        "authorization_reference": "Fixture: no autoriza escaneos",
        "expected_updated_at": "{{target_updated_at}}",
    },
    capture=f"{SET}('target_updated_at',data.updated_at);",
)
add(
    "05 · Destinos autorizados",
    "Listar destinos del workspace",
    "GET",
    BASE + "/targets?limit=100&offset=0",
)
add(
    "06 · Tecnologías y CPE",
    "Registrar tecnología de fixture",
    "POST",
    APP + "/technologies",
    body={
        "product": "small_business_rv340_firmware",
        "vendor": "cisco",
        "version": "1.0.0.33",
        "detection_method": "manual",
    },
    status=201,
    capture=f"{SET}('technology_id',data.id);",
)
add("06 · Tecnologías y CPE", "Listar tecnologías", "GET", APP + "/technologies")
add(
    "06 · Tecnologías y CPE",
    "Buscar candidatos CPE V2",
    "GET",
    APP
    + ("/cpe-candidates?query=cisco&product_query=small_business_rv340_firmware&limit=10&offset=0"),
    capture="".join(
        (
            "if (pm.variables.get('nvd_mode') === 'fixture') { const ",
            "candidate = data.items.find(x => x.cpe_name_id.toLowerCase() ===",
            " '",
            f"{CPE_ID}",
            "'); pm.test('UUID de fixture verificado', () => { ",
            "pm.expect(candidate).to.be.an('object'); ",
            "pm.expect(candidate.cpe_name).to.eql('",
            f"{CPE}",
            "'); pm.expect(candidate.deprecated).to.eql(false); }); ",
            f"{SET}",
            "('cpe_name_id',candidate.cpe_name_id); ",
            f"{SET}",
            "('confirmed_cpe',candidate.cpe_name); }",
        )
    ),
    description=(
        "En modo real NO selecciona candidato. Revisar producto, versión,"
        " UUID y deprecated, luego definir cpe_name_id, confirmed_cpe y "
        "cpe_confirmed_manually=true."
    ),
)
CONFIRM_PRE = (
    "if (pm.variables.get('nvd_mode') !== 'fixture' && pm.variables.g"
    "et('cpe_confirmed_manually') !== 'true') throw new Error('Se req"
    "uiere revisión humana del CPE');\nif (!pm.variables.get('cpe_name"
    "_id')) throw new Error('Falta UUID CPE verificado');"
)
add(
    "06 · Tecnologías y CPE",
    "Confirmar CPE revisado",
    "PUT",
    TECH + "/cpe",
    body={"cpe_name_id": "{{cpe_name_id}}", "expected_selected_cpe": None},
    pre=CONFIRM_PRE,
)
add(
    "07 · NVD, análisis e historial",
    "Consultar CVE V2 (POST único)",
    "POST",
    TECH + "/analyses",
    status=201,
    pre=f"{SET}('analysis_key', {UUID});",
    headers={"Idempotency-Key": "{{analysis_key}}"},
    capture="".join(
        (
            f"{SET}",
            "('analysis_id',data.id); pm.test('Procesamiento V2 terminado', ",
            "() => pm.expect(data.status).to.eql('completed'));",
        )
    ),
    description=(
        "V2 responde 201 al finalizar la página. No es la cola 202 de "
        "activos. Repetir solo con la misma clave para reconciliar, no "
        "para polling."
    ),
)
add(
    "07 · NVD, análisis e historial",
    "Estado V2 (solo GET)",
    "GET",
    RUN,
    capture=(
        "pm.test('Misma ejecución', () => pm.expect(data.id).to.eql(pm.co"
        "llectionVariables.get('analysis_id')));"
    ),
)
add(
    "07 · NVD, análisis e historial",
    "Historial V2 (solo GET)",
    "GET",
    APP + "/analyses?limit=20&offset=0",
    capture=(
        "pm.test('Una ejecución V2', () => { "
        "pm.expect(data.page.total).to.eql(1); pm.expect(data.items[0].id"
        ").to.eql(pm.collectionVariables.get('analysis_id')); });"
    ),
)
add(
    "08 · Hallazgos y recomendaciones",
    "Resultados y hallazgos V2",
    "GET",
    RUN + "/findings?limit=20&offset=0",
    capture="".join(
        (
            "if (data.items.length) { ",
            f"{SET}",
            "('finding_id',data.items[0].id); ",
            f"{SET}",
            "('finding_updated_at',data.items[0].updated_at); } ",
            "pm.test('Fixture tiene hallazgo', () => { if ",
            "(pm.variables.get('nvd_mode') === 'fixture') ",
            "pm.expect(data.items).to.have.lengthOf(1); });",
        )
    ),
)
FIND_PRE = "if (!pm.variables.get('finding_id')) { pm.execution.skipRequest(); }"
add(
    "08 · Hallazgos y recomendaciones",
    "Revisar hallazgo del fixture",
    "PATCH",
    FIND,
    body={"applicability": "potential", "expected_updated_at": "{{finding_updated_at}}"},
    pre=FIND_PRE,
    capture="pm.test('Revisado', () => pm.expect(data.status).to.eql('reviewed'));",
)
add(
    "08 · Hallazgos y recomendaciones",
    "Crear recomendación de prueba",
    "POST",
    FIND + "/recommendations",
    body={
        "recommendation": (
            "Revisar el aviso del fabricante y contrastar inventario antes de actuar."
        ),
        "source_url": None,
        "assigned_to": None,
        "due_at": None,
    },
    status=201,
    pre=FIND_PRE,
    capture="".join(
        (
            f"{SET}",
            "('recommendation_id',data.id); ",
            f"{SET}",
            "('recommendation_updated_at',data.updated_at);",
        )
    ),
)
add(
    "08 · Hallazgos y recomendaciones",
    "Listar recomendaciones",
    "GET",
    FIND + "/recommendations",
    pre=FIND_PRE,
)
add(
    "08 · Hallazgos y recomendaciones",
    "Actualizar recomendación",
    "PATCH",
    APP + "/recommendations/{{recommendation_id}}",
    body={"status": "in_progress", "expected_updated_at": "{{recommendation_updated_at}}"},
    pre=FIND_PRE,
)
asset = {
    "device_type": "router",
    "manufacturer": "Cisco",
    "model": "RV340",
    "version": "1.0.0.33",
    "site_label": "Laboratorio local",
    "inventory_label": None,
    "notes": "Fixture heredado V1, separado de aplicaciones V2",
}
add(
    "09 · V1 heredado (contrato separado)",
    "Crear activo V1",
    "POST",
    "/api/v1/assets",
    body=asset,
    status=201,
    pre=f"{SET}('asset_key',{UUID});",
    headers={"Idempotency-Key": "{{asset_key}}"},
    capture=f"{SET}('asset_id',data.id);",
)
add(
    "09 · V1 heredado (contrato separado)",
    "Listar activos V1",
    "GET",
    "/api/v1/assets?limit=20&offset=0",
)
add("09 · V1 heredado (contrato separado)", "Detalle activo V1", "GET", ASSET)
add(
    "09 · V1 heredado (contrato separado)",
    "Buscar candidatos CPE V1",
    "GET",
    (
        "/api/v1/cpe-candidates?query=cisco&product_query=small_business_"
        "rv340_firmware&limit=10&offset=0"
    ),
)
add(
    "09 · V1 heredado (contrato separado)",
    "Identificar CPE del activo V1",
    "POST",
    ASSET + "/cpe-identifications",
    body={
        "state": "confirmed",
        "cpe_name_id": "{{cpe_name_id}}",
        "component_kind": "firmware",
        "expected_current_id": None,
        "reason": ("Fixture de firmware documentado; no selección automática de candidato real"),
    },
    status=201,
    pre=CONFIRM_PRE + f"\n{SET}('identification_key',{UUID});",
    headers={"Idempotency-Key": "{{identification_key}}"},
    capture=f"{SET}('identification_id',data.id);",
)
add(
    "09 · V1 heredado (contrato separado)",
    "Historial CPE del activo V1",
    "GET",
    ASSET + "/cpe-identifications?scope=history&limit=20&offset=0",
)
add(
    "09 · V1 heredado (contrato separado)",
    "Aceptar análisis asíncrono V1",
    "POST",
    ASSET + "/analyses",
    body={"identification_id": "{{identification_id}}"},
    status=202,
    pre=f"{SET}('asset_analysis_key',{UUID}); {SET}('poll_count',0);",
    headers={"Idempotency-Key": "{{asset_analysis_key}}"},
    capture="".join(
        (
            f"{SET}",
            "('asset_analysis_id',data.id); pm.test('Location de ejecución', ",
            "() => pm.expect(pm.response.headers.get('Location')).to.include(",
            "data.id));",
        )
    ),
)
add(
    "09 · V1 heredado (contrato separado)",
    "Progreso V1 (polling GET limitado)",
    "GET",
    ARUN,
    capture="".join(
        (
            "pm.test('Misma ejecución', () => pm.expect(data.id).to.eql(pm.co",
            "llectionVariables.get('asset_analysis_id'))); if ",
            "(['queued','running'].includes(data.status)) { const ",
            "n=Number(pm.collectionVariables.get('poll_count')||0)+1; ",
            f"{SET}",
            "('poll_count',n); pm.test('Polling ",
            "acotado',()=>pm.expect(n).to.be.below(30)); if(n<30) ",
            "pm.execution.setNextRequest(pm.info.requestId); } else { pm.test",
            "('Completado',()=>pm.expect(data.status).to.eql('completed')); }",
        )
    ),
)
add(
    "09 · V1 heredado (contrato separado)",
    "Historial análisis V1",
    "GET",
    ASSET + "/analyses?limit=20&offset=0",
    capture="pm.test('GET no creó ejecuciones',()=>pm.expect(data.page.total).to.eql(1));",
)
add(
    "09 · V1 heredado (contrato separado)",
    "Resultados V1",
    "GET",
    ARUN + "/findings?limit=20&offset=0",
    capture="".join(
        (
            "if(data.items.length){ ",
            f"{SET}",
            "('asset_finding_id',data.items[0].id); ",
            f"{SET}",
            "('asset_finding_updated_at',data.items[0].updated_at); }",
        )
    ),
)
AF_PRE = "if (!pm.variables.get('asset_finding_id')) pm.execution.skipRequest();"
add("09 · V1 heredado (contrato separado)", "Detalle hallazgo V1", "GET", AFIND, pre=AF_PRE)
add(
    "09 · V1 heredado (contrato separado)",
    "Revisar hallazgo V1",
    "PATCH",
    AFIND,
    body={
        "status": "reviewed",
        "applicability": "undetermined",
        "expected_updated_at": "{{asset_finding_updated_at}}",
        "reason": "Revisión del fixture documentado",
        "evidence": ("El firmware no basta para establecer la condición hardware del fixture AND."),
    },
    pre=AF_PRE,
)
# Independent identity B exercises RLS via HTTP, without SQL bypass or role tampering.
bcred = {"username": "{{username_b}}", "password": "{{password}}"}
add(
    "10 · Seguridad negativa",
    "Registrar cuenta única B",
    "POST",
    "/api/v1/auth/register",
    body=bcred,
    status=201,
    auth="noauth",
)
add(
    "10 · Seguridad negativa",
    "Login B",
    "POST",
    "/api/v1/auth/login",
    body=bcred,
    auth="noauth",
    capture=f"{SET}('access_token_b',data.access_token);",
)
add(
    "10 · Seguridad negativa",
    "Workspace personal B",
    "GET",
    "/api/v2/workspaces",
    auth="b",
    capture="".join(
        (
            "pm.test('No enumera A',()=>pm.expect(data.items.map(x=>x.workspa",
            "ce_id)).not.to.include(pm.collectionVariables.get('workspace_id'",
            "))); ",
            f"{SET}",
            "('foreign_workspace_id',data.items[0].workspace_id);",
        )
    ),
)
add(
    "10 · Seguridad negativa",
    "Sin token",
    "GET",
    "/api/v1/auth/me",
    auth="noauth",
    status=401,
    error="INVALID_CREDENTIALS",
)
add(
    "10 · Seguridad negativa",
    "Token inválido",
    "GET",
    "/api/v1/auth/me",
    auth="invalid",
    status=401,
    error="INVALID_CREDENTIALS",
)
add(
    "10 · Seguridad negativa",
    "Token expirado firmado localmente",
    "GET",
    "/api/v1/auth/me",
    auth="expired",
    status=401,
    error="INVALID_CREDENTIALS",
    pre="if (!pm.variables.get('expired_token')) pm.execution.skipRequest();",
    description=(
        "Runner genera JWT expirado con su clave efímera. En Postman "
        "requiere token expirado real privado; no fabricar ni exponer "
        "claves."
    ),
)
add(
    "10 · Seguridad negativa",
    "Usuario inexistente",
    "POST",
    "/api/v1/auth/login",
    body={"username": "absent_{{$randomUUID}}", "password": "{{password}}"},
    auth="noauth",
    status=401,
    error="INVALID_CREDENTIALS",
    pre=f"pm.variables.set('absent_username','absent_'+{UUID}.replace(/-/g,''));",
)
REQUESTS[-1]["body"]["username"] = "{{absent_username}}"
add(
    "10 · Seguridad negativa",
    "Registro duplicado",
    "POST",
    "/api/v1/auth/register",
    body=credentials,
    auth="noauth",
    status=409,
    error="REGISTRATION_UNAVAILABLE",
)
add(
    "10 · Seguridad negativa",
    "Registro inválido",
    "POST",
    "/api/v1/auth/register",
    body={"username": "@@", "password": "{{password}}"},
    auth="noauth",
    status=422,
    error="VALIDATION_ERROR",
)
add(
    "10 · Seguridad negativa",
    "Autoconcesión de admin rechazada",
    "POST",
    "/api/v1/auth/register",
    body=credentials | {"is_admin": True},
    auth="noauth",
    status=422,
    error="VALIDATION_ERROR",
)
add(
    "10 · Seguridad negativa",
    "Workspace ajeno B visto por A",
    "GET",
    "/api/v2/workspaces/{{foreign_workspace_id}}",
    status=404,
)
add(
    "10 · Seguridad negativa",
    "Aplicación A leída por B",
    "GET",
    APP + "/analyses?limit=20&offset=0",
    auth="b",
    status=404,
    error="RESOURCE_NOT_FOUND",
)
add(
    "10 · Seguridad negativa",
    "Activo A leído por B",
    "GET",
    ASSET,
    auth="b",
    status=404,
    error="ASSET_NOT_FOUND",
)
add(
    "10 · Seguridad negativa",
    "Análisis inexistente",
    "GET",
    APP + "/analyses/00000000-0000-4000-8000-000000000099",
    status=404,
    error="ANALYSIS_NOT_FOUND",
)
add(
    "10 · Seguridad negativa",
    "UUID inválido",
    "GET",
    "/api/v2/workspaces/no-es-uuid",
    status=422,
    error="VALIDATION_ERROR",
)
add(
    "10 · Seguridad negativa",
    "Paginación inválida",
    "GET",
    APP + "/analyses?limit=101&offset=0",
    status=422,
    error="VALIDATION_ERROR",
)
add(
    "10 · Seguridad negativa",
    "Tecnología inválida",
    "POST",
    APP + "/technologies",
    body={"product": "firmware", "version": "", "detection_method": "zap"},
    status=422,
    error="VALIDATION_ERROR",
)
add(
    "10 · Seguridad negativa",
    "Conflicto concurrente autorización destino",
    "PATCH",
    APP + "/targets/{{target_id}}/authorization",
    body={
        "authorization_status": "rejected",
        "authorization_reference": "Otra revisión obsoleta",
        "authorization_expires_at": None,
        "expected_updated_at": "{{target_original_updated_at}}",
    },
    status=409,
    error="TARGET_AUTHORIZATION_CONFLICT",
)
add(
    "10 · Seguridad negativa",
    "Conflicto concurrente revisión hallazgo",
    "PATCH",
    FIND,
    body={"applicability": "potential", "expected_updated_at": "{{finding_updated_at}}"},
    pre=FIND_PRE,
    status=409,
    error="FINDING_REVIEW_CONFLICT",
)
add(
    "10 · Seguridad negativa",
    "Conflicto idempotencia activo",
    "POST",
    "/api/v1/assets",
    body=asset | {"model": "Otra intención"},
    headers={"Idempotency-Key": "{{asset_key}}"},
    status=409,
    error="IDEMPOTENCY_CONFLICT",
)
add(
    "10 · Seguridad negativa",
    "ZAP no admitido por contrato de análisis V1",
    "POST",
    ASSET + "/analyses",
    body={"kind": "zap_baseline"},
    pre=f"pm.variables.set('invalid_analysis_key',{UUID});",
    headers={"Idempotency-Key": "{{invalid_analysis_key}}"},
    status=422,
    error="VALIDATION_ERROR",
    description=(
        "No existe endpoint de ZAP. Este cuerpo se rechaza antes de "
        "ejecutar análisis; no autoriza ni inicia escaneos."
    ),
)
add(
    "10 · Seguridad negativa",
    "Registro deshabilitado en segunda API de fixture",
    "POST",
    "/api/v1/auth/register",
    body=credentials,
    auth="noauth",
    status=503,
    error="REGISTRATION_DISABLED",
    pre="if (!pm.variables.get('disabled_base_url')) pm.execution.skipRequest();",
    description=(
        "Solo runner: segunda instancia con REGISTRATION_ENABLED=false. "
        "No se cambia la configuración del servidor durante solicitudes."
    ),
)
REQUESTS[-1]["base"] = "{{disabled_base_url}}"


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def main():
    app = create_app(
        Settings(
            _env_file=None,
            database_url="postgresql+psycopg://docs@127.0.0.1/docs",
            token_secret=secrets.token_urlsafe(48),
            cve_worker_enabled=False,
        )
    )
    spec = app.openapi()
    # Request examples use empty secrets; validation supplies ephemeral local values.
    operations = {}
    for path, methods in spec["paths"].items():
        for method, op in methods.items():
            operations[(method.upper(), path)] = op
    folders = {}
    synthetic = (
        json.loads((HERE / "examples/responses.json").read_text())
        if (HERE / "examples/responses.json").exists()
        else {}
    )
    for req in REQUESTS:
        path = req["path"].split("?")[0]
        import re

        canonical = re.sub(
            r"\{\{([^}]+)\}\}",
            lambda m: (
                "{"
                + (
                    "run_id"
                    if m[1] in {"analysis_id", "asset_analysis_id"}
                    else "finding_id"
                    if m[1] == "asset_finding_id"
                    else m[1]
                )
                + "}"
            ),
            path,
        )
        op = operations.get((req["method"], canonical))
        if (
            op
            and (
                req["status"] < 300 or req["name"] == ("Workspace adicional: bloqueo RLS conocido")
            )
            and req["body"] is not None
            and "requestBody" in op
        ):
            example = dict(req["body"])

            def doc_value(key, value):
                if key == "password":
                    return ""
                if not isinstance(value, str) or "{{" not in value:
                    return value
                if key in {"expected_updated_at"}:
                    return "2026-11-13T12:00:00Z"
                if key in {"username"}:
                    return "api_example"
                if key == "cpe_name_id":
                    return CPE_ID
                return "00000000-0000-4000-8000-000000000001"

            example = {k: doc_value(k, v) for k, v in example.items()}
            op["requestBody"]["content"]["application/json"]["examples"] = {
                "local": {
                    "summary": ("Ejemplo; sustituir variables y secretos locales antes de enviar"),
                    "value": example,
                }
            }
        raw = req.get("base", "{{base_url}}") + req["path"]
        test = "".join(
            (
                "pm.test('HTTP ",
                f"{req['status']}",
                "', () => pm.response.to.have.status(",
                f"{req['status']}",
                "));\nconst data = pm.response.json();\n",
            )
        )
        test += "pm.test('JSON',()=>pm.expect(data).to.be.an('object'));\n"
        if req["status"] >= 400:
            test += (
                "pm.test('Error sanitizado',()=>{pm.expect(data).to.have.pro"
                "perty('error'); ['code','message','request_id'].forEach(k=>"
                "pm.expect(data.error[k]).to.be.a('string').and.not.empty);}"
                ");\n"
            )
            if req["error"]:
                test += "".join(
                    (
                        "pm.test('Código de ",
                        "error',()=>pm.expect(data.error.code).to.eql('",
                        f"{req['error']}",
                        "'));\n",
                    )
                )
            if req["status"] == 401:
                test += (
                    "pm.test('Bearer requerido',()=>pm.expect(pm.response.headers.get"
                    "('WWW-Authenticate')).to.eql('Bearer'));\n"
                )
            if req["status"] in {429, 503}:
                test += (
                    "pm.test('Retry-After',()=>pm.expect(pm.response.headers.get('Ret"
                    "ry-After')).to.match(/^[0-9]+$/));\n"
                )
        else:
            test += (
                "pm.test('Sin envelope de error',()=>pm.expect(data).not"
                ".to.have.property('error'));\n"
            )
        test += req["capture"]
        request = {
            "method": req["method"],
            "header": [{"key": "Accept", "value": "application/json"}],
            "url": raw,
            "description": req["description"]
            or (op or {}).get("description", "Caso negativo sobre una ruta real"),
        }
        if req["body"] is not None:
            request["body"] = {
                "mode": "raw",
                "raw": json.dumps(req["body"], ensure_ascii=False, indent=2),
                "options": {"raw": {"language": "json"}},
            }
            request["header"].append({"key": "Content-Type", "value": "application/json"})
        for k, v in req["headers"].items():
            request["header"].append({"key": k, "value": v})
        if req["auth"] == "noauth":
            request["auth"] = {"type": "noauth"}
        elif req["auth"] != "inherit":
            token = {
                "b": "{{access_token_b}}",
                "invalid": "invalid-token",
                "expired": "{{expired_token}}",
            }[req["auth"]]
            request["auth"] = {
                "type": "bearer",
                "bearer": [{"key": "token", "value": token, "type": "string"}],
            }
        events = [
            {
                "listen": "test",
                "script": {
                    "type": "text/javascript",
                    "exec": ("(function(){\n" + test + "\n})();").splitlines(),
                },
            }
        ]
        if req["pre"]:
            events.insert(
                0,
                {
                    "listen": "prerequest",
                    "script": {
                        "type": "text/javascript",
                        "exec": ("(function(){\n" + req["pre"] + "\n})();").splitlines(),
                    },
                },
            )
        item = {
            "id": str(uuid5(NAMESPACE_URL, req["name"])),
            "name": req["name"],
            "request": request,
            "event": events,
            "response": [],
        }
        if req["name"] in synthetic:
            sample = synthetic[req["name"]]
            item["response"] = [
                {
                    "name": "Ejemplo sintético sanitizado",
                    "originalRequest": request,
                    "status": "Example",
                    "code": sample["status"],
                    "header": [{"key": "Content-Type", "value": "application/json"}],
                    "body": json.dumps(sample["body"], ensure_ascii=False, indent=2),
                }
            ]
        folders.setdefault(req["folder"], []).append(item)
    variables = {
        "username": "",
        "username_b": "",
        "access_token": "",
        "access_token_b": "",
        "workspace_id": "",
        "foreign_workspace_id": "",
        "application_id": "",
        "asset_id": "",
        "technology_id": "",
        "cpe_name_id": "",
        "confirmed_cpe": "",
        "analysis_id": "",
        "asset_analysis_id": "",
        "finding_id": "",
        "asset_finding_id": "",
        "identification_id": "",
        "target_id": "",
        "recommendation_id": "",
        "user_id": "",
    }
    collection = {
        "info": {
            "_postman_id": str(uuid5(NAMESPACE_URL, "vulntrack-v2-api-collection")),
            "name": "VulnTrack · API V2 y legado separado",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "description": (
                "Solo entorno desechable identificado. Orden completo: estado → "
                "registro/login → workspace → aplicación/tecnología → CPE "
                "revisado → CVE → hallazgos/recomendaciones → legado V1 separado "
                "→ negativos. Secretos solo locales. Leer README. ZAP no existe "
                "como endpoint y sigue deshabilitado."
            ),
        },
        "auth": {
            "type": "bearer",
            "bearer": [{"key": "token", "value": "{{access_token}}", "type": "string"}],
        },
        "variable": [{"key": k, "value": v, "type": "string"} for k, v in variables.items()],
        "event": [
            {
                "listen": "prerequest",
                "script": {
                    "type": "text/javascript",
                    "exec": [
                        (
                            "if (pm.variables.get('disposable_confirmed') !== 'true') throw "
                            "new Error('Usar solo entorno desechable identificado; establecer"
                            " disposable_confirmed=true tras verificarlo');"
                        ),
                        (
                            "const base = pm.variables.get('base_url'); if "
                            "(!/^http:\\/\\/127\\.0\\.0\\.1:\\d+$/.test(base || '')) throw new "
                            "Error('Esta colección de pruebas solo acepta loopback HTTP con "
                            "puerto explícito');"
                        ),
                        (
                            "if (pm.variables.get('nvd_mode') !== 'fixture' && "
                            "pm.variables.get('allow_live_nvd') !== 'true') throw new "
                            "Error('Para NVD real se requiere allow_live_nvd=true y revisión "
                            "manual del CPE');"
                        ),
                    ],
                },
            }
        ],
        "item": [{"name": name, "item": items} for name, items in folders.items()],
    }
    dump(HERE / "VulnTrack-V2.postman_collection.json", collection)
    for mode in ["local", "test"]:
        env = {
            "id": str(uuid5(NAMESPACE_URL, "vulntrack-v2-" + mode)),
            "name": "VulnTrack V2 · " + mode + " (sin secretos)",
            "_postman_variable_scope": "environment",
            "values": [
                {
                    "key": key,
                    "value": value,
                    "enabled": True,
                    "type": "secret" if key in {"password", "expired_token"} else "default",
                }
                for key, value in {
                    "base_url": "http://127.0.0.1:8000",
                    "password": "",
                    "nvd_mode": "fixture" if mode == "test" else "live",
                    "disposable_confirmed": "false",
                    "allow_live_nvd": "false",
                    "cpe_confirmed_manually": "false",
                    "expired_token": "",
                    "disabled_base_url": "",
                }.items()
            ],
        }
        dump(HERE / f"{mode}.postman_environment.json", env)
    dump(HERE / "openapi.json", spec)
    # Persist request examples in Python for live Swagger as well as snapshot.
    body_examples = {}
    for (method, path), op in operations.items():
        content = op.get("requestBody", {}).get("content", {}).get("application/json", {})
        if "examples" in content:
            body_examples[f"{method} {path}"] = content["examples"]
    response_examples = {}
    for req in REQUESTS:
        if req["name"] in synthetic and (
            req["status"] < 300 or req["name"] == ("Workspace adicional: bloqueo RLS conocido")
        ):
            canonical = re.sub(
                r"\{\{([^}]+)\}\}",
                lambda m: (
                    "{"
                    + (
                        "run_id"
                        if m[1] in {"analysis_id", "asset_analysis_id"}
                        else "finding_id"
                        if m[1] == "asset_finding_id"
                        else m[1]
                    )
                    + "}"
                ),
                req["path"].split("?")[0],
            )
            if (req["method"], canonical) in operations:
                response_examples[f"{req['method']} {canonical}"] = [
                    req["status"],
                    synthetic[req["name"]]["body"],
                ]
    (ROOT / "app/api_examples.py").write_text(
        (
            '"""Synthetic examples only; generated by api-tests/v2/build.py. '
            'Never credentials."""\n\nRESPONSE_EXAMPLES = '
        )
        + pprint.pformat(response_examples, sort_dicts=True, width=100)
        + "\n\nREQUEST_EXAMPLES = "
        + pprint.pformat(body_examples, sort_dicts=True, width=100)
        + "\n"
    )
    from format_literals import wrap_long_literals

    generated = ROOT / "app/api_examples.py"
    for _ in range(2):
        wrap_long_literals(generated)
        subprocess.run(
            [sys.executable, "-m", "ruff", "format", str(generated)],
            check=True,
            capture_output=True,
        )
    from app import api_documentation as documentation_module
    from app import api_examples as example_module

    importlib.reload(example_module)
    importlib.reload(documentation_module)
    # Single-pass output matches the runtime generator, including explicit null examples.
    dump(HERE / "openapi.json", create_app(app.state.settings).openapi())
    print(
        "".join(
            (
                f"{len(operations)}",
                " operations; ",
                f"{len(REQUESTS)}",
                " collection requests; ",
                f"{len(response_examples)}",
                " response examples",
            )
        )
    )


if __name__ == "__main__":
    main()

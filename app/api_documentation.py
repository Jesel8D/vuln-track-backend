"""OpenAPI metadata only: no response filtering, validation or authorization changes."""

from copy import deepcopy
from itertools import chain

from fastapi import APIRouter, FastAPI
from fastapi.routing import APIRoute

from app.api_examples import REQUEST_EXAMPLES, RESPONSE_EXAMPLES

ERROR_SCHEMA = {
    "type": "object",
    "required": ["error"],
    "properties": {
        "error": {
            "type": "object",
            "required": ["code", "message", "request_id"],
            "properties": {
                name: {"type": "string"} for name in ("code", "message", ("request_id"))
            },
        }
    },
}


def configure_api_documentation(app: FastAPI, routers: tuple[APIRouter, ...]) -> None:
    app.description = (
        "API real de la línea V2 de registro. Auth conserva /api/v1. Los "
        "activos V1 usan propiedad individual; aplicaciones V2 usan "
        "workspace y RLS. No son contratos intercambiables. Registro "
        "opt-in; JWT Bearer, sin cookies. No hay endpoints de ZAP, "
        "gestión de membresías ni lectura de auditoría. Los ejemplos son "
        "sintéticos; contraseñas/tokens vacíos requieren secretos "
        "locales."
    )
    for route in chain(app.routes, *(router.routes for router in routers)):
        if not isinstance(route, APIRoute):
            continue
        path = route.path
        if path in {"/health", "/ready"}:
            tag = "Estado"
            detail = (
                "Liveness sin consultar PostgreSQL."
                if path == "/health"
                else ("Readiness: comprueba PostgreSQL, rol sin privilegios y esquema requerido.")
            )
        elif "/auth/" in path:
            tag = "Autenticación"
            detail = {
                "register_account": (
                    "Alta opt-in (REGISTRATION_ENABLED). Crea usuario, workspace "
                    "personal y membresía owner en una transacción. No permite campos"
                    " internos ni privilegios globales. Username ASCII normalizado "
                    "3–80; contraseña privada 15–128. No inicia sesión. Duplicado: "
                    "409; registro deshabilitado: 503; cuota: 429."
                ),
                "login": (
                    "JSON username/password (no formulario OAuth). Devuelve JWT "
                    "Bearer y expires_in; Cache-Control: no-store. Cuenta "
                    "inexistente, inactiva o contraseña incorrecta: 401 "
                    "indistinguible. Cuota: 429. No hay refresh/revocación "
                    "individual."
                ),
                "me": (
                    "Identidad de una cuenta activa según JWT vigente y versión de "
                    "usuario. Sin token, inválido o expirado: 401."
                ),
            }[route.endpoint.__name__]
        else:
            tag = "V1 · Activos heredados" if path.startswith("/api/v1") else ("V2 · Aplicaciones")
            if path.startswith("/api/v2"):
                if "recommendations" in path:
                    tag = "V2 · Recomendaciones"
                elif "findings" in path:
                    tag = "V2 · Hallazgos"
                elif "analyses" in path:
                    tag = "V2 · Análisis e historial"
                elif "cpe" in path or "technologies" in path:
                    tag = "V2 · Tecnologías y CPE"
                elif "targets" in path:
                    tag = "V2 · Destinos autorizados"
                elif "applications" not in path:
                    tag = "V2 · Workspaces y dashboard"
            detail = (route.endpoint.__doc__ or "").strip()
            detail += (
                " Autorización por propietario del activo; independiente de workspaces."
                if path.startswith("/api/v1")
                else (
                    " Requiere membresía del workspace y contexto HMAC transaccional "
                    "con RLS. Lectura: owner/editor/viewer; escritura: owner/editor. "
                    "Recursos ajenos suelen ocultarse como 404; algunas listas "
                    "devuelven items vacío. No usar una respuesta vacía para inferir "
                    "existencia."
                )
            )
        if route.endpoint.__name__ == "create_workspace":
            detail += (
                " INCIDENCIA VERIFICADA: el POST adicional devuelve 404 "
                "RESOURCE_NOT_FOUND (SQLSTATE 42501 al INSERT RETURNING bajo "
                "RLS), aunque su status declarado es 201. El workspace personal "
                "del registro funciona. No se modifica RLS aquí."
            )
        if route.endpoint.__module__ == "app.api.v2_nvd" and route.endpoint.__name__ in {
            "analyze_technology",
            "review_finding",
        }:
            detail += (
                " INCIDENCIAS VERIFICADAS: Pydantic/evaluador permiten "
                "undetermined pero el CHECK SQL V2 lo rechaza; análisis AND puede"
                " terminar 503 NVD_PROCESSING_FAILED y revisión undetermined en "
                "409 INTEGRITY_CONFLICT. Un título truncado a 500 que termina en "
                "espacio también provoca 503. Los ejemplos positivos usan OR y "
                "título corto SIMULADOS; no certifican esos casos reales."
            )
        if "cpe" in path:
            detail += (
                " NVD puede responder 429/502/503/504. La búsqueda NO confirma: "
                "seleccionar manualmente un candidato no deprecado y versión "
                "exacta. Pruebas offline usan UUID documentado de fixture, nunca "
                "el primer candidato por posición."
            )
        if "analyses" in path:
            detail += (
                (
                    " V2 procesa la página NVD dentro de POST y responde 201 al "
                    "terminar; no es un job 202. Conserva estados "
                    "queued/running/completed/failed e historial; complete/partial "
                    "describe cobertura. Máximo una página de 100 CVE, partial no "
                    "demuestra ausencia de más resultados."
                )
                if path.startswith("/api/v2")
                else (
                    " V1 POST acepta con 202 y Location; el worker procesa la cola. "
                    "Estados queued/running/completed/failed; consultar progreso con "
                    "GET, nunca repetir POST para hacer polling."
                )
            )
            detail += (
                " Reutilizar Idempotency-Key UUID solo para la misma intención; "
                "otra consulta activa o cambios incompatibles pueden producir "
                "409. GET de progreso/resultados no crea ejecuciones."
            )
        if "targets" in path:
            detail += (
                " Inventario HTTP(S), sin escaneo. Autorizar requiere referencia "
                "y expected_updated_at; aprobación vence en el próximo año, "
                "rechazo sin vencimiento. Conflicto de versión: 409. No demuestra"
                " propiedad del destino. ZAP permanece deshabilitado."
            )
        if "recommendations" in path or ("findings" in path and "PATCH" in route.methods):
            detail += (
                " Modificaciones requieren expected_updated_at con zona horaria; "
                "versión obsoleta/transición inválida: 409. Revisión no prueba "
                "explotación."
            )
        if path == "/api/v2/workspaces" and "POST" in route.methods:
            detail += (
                " Idempotency-Key es también UUID del workspace adicional; no "
                "reemplaza el workspace personal del registro."
            )
        query = [param.name for param in route.dependant.query_params]
        if "offset" in query:
            detail += (
                " Paginación limit/offset según límites del esquema; consultar "
                "page.total cuando exista."
            )
        elif route.endpoint.__name__ in {
            "list_applications",
            "list_technologies",
            "list_targets",
            "list_recommendations",
        }:
            detail += " Lista acotada sin parámetros de paginación: hasta 100 elementos."
        route.tags = [tag]
        route.description = detail.strip()
        route.summary = route.endpoint.__name__.replace("_", " ").capitalize()
        responses = {}
        codes = (
            {} if path == "/health" else {503: ("Dependencia, esquema o servicio no disponible")}
        )
        if path not in {"/health", "/ready"}:
            codes.update(
                {
                    401: "JWT ausente, inválido, expirado o cuenta no autorizada",
                    422: "Solicitud inválida; no se refleja información sensible",
                    413: "Cuerpo supera el límite configurado",
                }
            )
            if "/auth/" not in path:
                codes[404] = "Recurso no visible o inexistente"
            if route.methods & {"POST", "PUT", "PATCH"}:
                codes[409] = "Duplicado, conflicto de idempotencia o versión concurrente"
            calls_nvd = route.endpoint.__name__ in {
                "candidates",
                "identify",
                "cpe_candidates",
                "confirm_cpe",
                "analyze_technology",
            }
            if calls_nvd or route.endpoint.__name__ in {"register_account", "login", "accept"}:
                codes[429] = "Cuota agotada; respetar Retry-After"
            if calls_nvd:
                codes.update({502: "Respuesta NVD inválida", 504: "Timeout NVD"})
        if route.endpoint.__name__ == "login":
            codes.pop(409, None)
        # Public enrollment/login have no Bearer prerequisite.
        if route.endpoint.__name__ == "register_account":
            codes.pop(401, None)
        for status, description in codes.items():
            responses[str(status)] = {
                "description": description,
                "content": {
                    "application/json": {
                        "schema": ERROR_SCHEMA,
                    }
                },
            }
            if status in {429, 503}:
                responses[str(status)]["headers"] = {
                    "Retry-After": {
                        "schema": {"type": "string"},
                        "description": "Segundos sugeridos antes de reintentar",
                    }
                }
            if status == 401:
                responses[str(status)]["headers"] = {
                    "WWW-Authenticate": {"schema": {"type": "string"}, "example": "Bearer"}
                }
        for method in route.methods:
            key = f"{method} {path}"
            if key in RESPONSE_EXAMPLES:
                status, example = RESPONSE_EXAMPLES[key]
                responses[str(status)] = {
                    "description": "Ejemplo sintético de prueba desechable",
                    "content": {"application/json": {"example": example}},
                }
        route.responses.update({int(code): value for code, value in responses.items()})
        route.openapi_extra = {}
        for method in route.methods:
            examples = REQUEST_EXAMPLES.get(f"{method} {path}")
            if examples:
                route.openapi_extra["requestBody"] = {
                    "content": {"application/json": {"examples": examples}}
                }
    app.openapi_schema = None
    original_openapi = app.openapi

    def documented_openapi():
        schema = original_openapi()
        # FastAPI's model serialization drops None from free-form example payloads.
        # Restore explicit JSON nulls required by the actual API (e.g. expected_current_id).
        for path, methods in schema["paths"].items():
            for method, operation in methods.items():
                key = f"{method.upper()} {path}"
                if key in REQUEST_EXAMPLES:
                    operation["requestBody"]["content"]["application/json"]["examples"] = deepcopy(
                        REQUEST_EXAMPLES[key]
                    )
                if key in RESPONSE_EXAMPLES:
                    status, example = RESPONSE_EXAMPLES[key]
                    operation["responses"][str(status)]["content"]["application/json"][
                        "example"
                    ] = deepcopy(example)
        return schema

    app.openapi = documented_openapi

"""Offline schema, examples, coverage and unchanged-contract checks."""

import hashlib
import importlib.util
import json
import re
import secrets
import sys
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft4Validator, Draft202012Validator, FormatChecker
from openapi_spec_validator import validate as validate_openapi
from pydantic import TypeAdapter

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from app.core.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402

HERE = Path(__file__).resolve().parent


def load(name):
    return json.loads((HERE / name).read_text())


def contract(spec):
    """Request/response/security shape only. Additional documented errors are metadata."""
    operations = {}
    for path, methods in spec["paths"].items():
        for method, op in methods.items():
            operations[f"{method.upper()} {path}"] = {
                "parameters": op.get("parameters", []),
                "security": op.get("security", []),
                "request": op.get("requestBody", {})
                .get("content", {})
                .get("application/json", {})
                .get("schema"),
                "required": op.get("requestBody", {}).get("required", False),
                "success": {
                    code: r.get("content", {}).get("application/json", {}).get("schema")
                    for code, r in op["responses"].items()
                    if code.startswith("2")
                },
            }
    schemas = {
        name: value
        for name, value in spec["components"]["schemas"].items()
        if name not in {"HTTPValidationError", "ValidationError"}
    }
    return {
        "operations": operations,
        "schemas": schemas,
        "securitySchemes": spec["components"]["securitySchemes"],
    }


def main():
    spec = load("openapi.json")
    validate_openapi(spec)
    settings = Settings(
        _env_file=None,
        database_url="postgresql+psycopg://docs@127.0.0.1/docs",
        token_secret=secrets.token_urlsafe(48),
        cve_worker_enabled=False,
    )
    app = create_app(settings)
    assert app.openapi() == spec, "Snapshot differs from live generator"
    baseline = load("baseline-contract.json")
    assert contract(spec) == baseline, "Runtime request/success/security contract changed"
    collection = load("VulnTrack-V2.postman_collection.json")
    Draft4Validator(load("vendor/postman-collection-v2.1.schema.json")).validate(collection)
    builder_spec = importlib.util.spec_from_file_location(
        "v2_collection_build", HERE / ("build.py")
    )
    builder = importlib.util.module_from_spec(builder_spec)
    builder_spec.loader.exec_module(builder)
    ops = {
        (method.upper(), path): op
        for path, methods in spec["paths"].items()
        for method, op in methods.items()
    }
    covered = set()
    samples = load("examples/responses.json")
    checked_bodies = checked_responses = 0
    # Pydantic validation against the actual endpoint body fields, not only JSON Schema.
    from app.api.analyses import router as analyses
    from app.api.cpe import router as cpe
    from app.api.router import router as v1
    from app.api.v2_nvd import router as nvd
    from app.api.v2_resources import router as resources
    from app.api.v2_targets import router as targets

    routes = [r for router in (v1, analyses, cpe, nvd, resources, targets) for r in router.routes]
    for request in builder.REQUESTS:
        raw = request["path"].split("?")[0]
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
            raw,
        )
        key = request["method"], canonical
        if key not in ops:
            concrete = re.sub(r"\{\{[^}]+\}\}", "00000000-0000-4000-8000-000000000001", raw)
            assert any(
                method == request["method"]
                and re.fullmatch(re.sub(r"\{[^}]+\}", r"[^/]+", path), concrete)
                for method, path in ops
            ), request["name"]
            continue
        op = ops[key]
        covered.add(key)
        if request["status"] < 300:
            if request["body"] is not None:
                # Secrets and runtime UUID/timestamps are substituted locally, never committed.
                example = deepcopy(
                    op["requestBody"]["content"]["application/json"]["examples"]["local"][("value")]
                )
                if "password" in example:
                    example["password"] = secrets.token_urlsafe(28)
                Draft202012Validator(
                    {
                        "$ref": "#/request",
                        "request": op["requestBody"]["content"]["application/json"]["schema"],
                        "components": spec["components"],
                    },
                    format_checker=FormatChecker(),
                ).validate(example)
                route = next(
                    r for r in routes if r.path == canonical and request["method"] in r.methods
                )
                field = route.body_field
                TypeAdapter(field.field_info.annotation).validate_python(example)
                checked_bodies += 1
            sample = samples[request["name"]]
            assert sample["status"] == request["status"]
            response = op["responses"][str(request["status"])]["content"]["application/json"]
            Draft202012Validator(
                {
                    "$ref": "#/response",
                    "response": response.get("schema", {}),
                    "components": spec["components"],
                },
                format_checker=FormatChecker(),
            ).validate(response["example"])
            Draft202012Validator(
                {
                    "$ref": "#/response",
                    "response": response.get("schema", {}),
                    "components": spec["components"],
                },
                format_checker=FormatChecker(),
            ).validate(sample["body"])
            checked_responses += 1
        elif request["name"] in samples:
            if request["name"] == "Workspace adicional: bloqueo RLS conocido":
                example = op["requestBody"]["content"]["application/json"]["examples"]["local"][
                    "value"
                ]
                route = next(
                    r for r in routes if r.path == canonical and request["method"] in r.methods
                )
                TypeAdapter(route.body_field.field_info.annotation).validate_python(example)
                checked_bodies += 1
            sample = samples[request["name"]]
            assert sample["status"] == request["status"]
            assert set(sample["body"]) == {"error"}
            if request["error"]:
                assert sample["body"]["error"]["code"] == request["error"]
    assert covered == set(ops), set(ops) - covered
    assert len(ops) == 39 and len(builder.REQUESTS) == 61
    for env in ["local.postman_environment.json", "test.postman_environment.json"]:
        values = {v["key"]: v["value"] for v in load(env)["values"]}
        assert values["password"] == values["expired_token"] == ""
        assert values["disposable_confirmed"] == "false"
    # No committed live JWT, database credentials or substituted password.
    for path in [
        HERE / "openapi.json",
        HERE / "VulnTrack-V2.postman_collection.json",
        HERE / "examples/responses.json",
    ]:
        body = path.read_text()
        assert not re.search(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", body)
        assert "postgresql+psycopg://" not in body
    print(
        "".join(
            (
                "VALIDATED: OpenAPI 3.1; Postman 2.1; ",
                f"{len(ops)}",
                " unchanged operations; ",
                f"{len(builder.REQUESTS)}",
                " requests; ",
                f"{checked_bodies}",
                " Pydantic bodies; ",
                f"{checked_responses}",
                " positive response examples; all published examples contain no ",
                "runtime secrets.",
            )
        )
    )
    print(
        "Untyped V2 responses retain their original permissive schemas; "
        "examples are evidence, not new response validation."
    )
    print("OpenAPI SHA256:", hashlib.sha256((HERE / "openapi.json").read_bytes()).hexdigest())


if __name__ == "__main__":
    main()

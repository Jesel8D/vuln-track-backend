import json
import re
from pathlib import Path

from app.api.router import Login, Token, UserRead
from app.schemas.assets import AssetCreate, AssetList, AssetRead


def test_documented_json_examples_validate_against_real_models():
    document = Path("docs/FRONTEND_MOBILE_INTEGRATION.md").read_text()
    examples = [
        json.loads(block) for block in re.findall(r"```json\s*\n(.*?)\n```", document, re.S)
    ]
    models = [Login, Token, UserRead, AssetCreate, AssetRead, AssetList]
    assert len(examples) == len(models) + 1
    for model, body in zip(models, examples, strict=False):
        model.model_validate(body)
    assert set(examples[-1]["error"]) == {"code", "message", "request_id"}


def test_documented_operations_exist_in_openapi_and_owner_is_not_input(client):
    schema = client.get("/openapi.json").json()
    expected = {
        "/health": "get",
        "/ready": "get",
        "/api/v1/auth/login": "post",
        "/api/v1/auth/me": "get",
        "/api/v1/assets/{asset_id}": "get",
    }
    for path, method in expected.items():
        assert method in schema["paths"][path]
    assert {"post", "get"} <= schema["paths"]["/api/v1/assets"].keys()
    create = schema["components"]["schemas"]["AssetCreate"]
    assert create["additionalProperties"] is False
    assert "created_by" not in create["properties"]
    key = next(
        parameter
        for parameter in schema["paths"]["/api/v1/assets"]["post"]["parameters"]
        if parameter["name"] == "Idempotency-Key"
    )
    assert key["required"] and key["schema"]["maxLength"] == 36

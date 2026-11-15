from app.main import create_app


def test_first_and_idempotent_issuance_both_have_a_pydantic_response_contract(settings):
    spec = create_app(settings).openapi()
    path = next(
        path for path in spec["paths"] if path.endswith("/targets/{target_id}/verifications")
    )
    responses = spec["paths"][path]["post"]["responses"]
    for code in ["200", "201"]:
        assert responses[code]["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/IssueResult"
        }
    assert (
        spec["components"]["schemas"]["ChallengeRead"]["properties"]["control_verified"]["const"]
        is False
    )
    assert (
        spec["components"]["schemas"]["ChallengeRead"]["properties"]["execution_enabled"]["const"]
        is False
    )

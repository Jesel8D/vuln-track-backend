"""Create NEW persistent validation profiles; retain their volumes and private backup."""

import hashlib
import importlib.util
import json
import secrets

import httpx

from scripts.v2_development import ROOT, PersistentV2


class HTTP:
    def __init__(self, base):
        self.base = base
        self.client = httpx.Client(base_url=base, trust_env=False, timeout=30)

    def request(self, method, path, *, expected=200, token=None, body=None, key=None):
        headers = {}
        if token:
            headers["Authorization"] = "Bearer " + token
        if key:
            headers["Idempotency-Key"] = key
        response = self.client.request(method, path, json=body, headers=headers)
        assert response.status_code == expected, (
            f"{method} {path}: HTTP {response.status_code}, expected {expected}"
        )
        return response.json()

    def login(self, credentials):
        return self.request("POST", "/api/v1/auth/login", body=credentials)["access_token"]


def fixture_module():
    spec = importlib.util.spec_from_file_location(
        "persistence_http_fixture", ROOT / "api-tests/v2/run.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_data(api, credentials, other, ids):
    token = api.login(credentials)
    me = api.request("GET", "/api/v1/auth/me", token=token)
    assert me["id"] == ids["user"]
    directory = api.request("GET", "/api/v2/workspaces", token=token)["items"]
    assert (
        len(directory) == 1
        and directory[0]["workspace_id"] == ids["workspace"]
        and directory[0]["role"] == "owner"
    )
    root = f"/api/v2/workspaces/{ids['workspace']}/applications"
    assert api.request("GET", root, token=token)["items"][0]["id"] == ids["application"]
    base = root + "/" + ids["application"]
    technologies = api.request("GET", base + "/technologies", token=token)["items"]
    assert (
        technologies[0]["id"] == ids["technology"]
        and technologies[0]["confidence"] == "user_confirmed"
    )
    runs = api.request("GET", base + "/analyses", token=token)
    assert runs["page"]["total"] == 1 and runs["items"][0]["id"] == ids["analysis"]
    run = api.request("GET", base + "/analyses/" + ids["analysis"], token=token)
    assert run["status"] == "completed" and run["stored_count"] == 1
    findings = api.request("GET", base + "/analyses/" + ids["analysis"] + "/findings", token=token)[
        "items"
    ]
    finding = findings[0]
    assert (
        finding["id"] == ids["finding"]
        and finding["status"] == "reviewed"
        and finding["applicability"] == "undetermined"
    )
    assert (
        hashlib.sha256(json.dumps(finding["evidence"], sort_keys=True).encode()).hexdigest()
        == ids["evidence_hash"]
    )
    measures = api.request(
        "GET", base + "/findings/" + ids["finding"] + "/recommendations", token=token
    )["items"]
    assert (
        len(measures) == 1
        and measures[0]["id"] == ids["recommendation"]
        and measures[0]["status"] == "in_progress"
    )
    other_token = api.login(other)
    api.request("GET", base + "/analyses/" + ids["analysis"], token=other_token, expected=404)
    foreign = api.request("GET", "/api/v2/workspaces", token=other_token)["items"]
    assert ids["workspace"] not in {w["workspace_id"] for w in foreign}
    return token


def main():
    nonce = secrets.token_hex(4)
    profile = "validation-" + nonce
    stack = PersistentV2(profile, pg_port=0, api_port=0, web_port=0)
    restored = PersistentV2("restore-" + nonce, pg_port=0, api_port=0, web_port=0)
    fixture = fixture_module()
    credentials = {
        "username": "persist_" + secrets.token_hex(8),
        "password": secrets.token_urlsafe(28),
    }
    other = {"username": "other_" + secrets.token_hex(8), "password": secrets.token_urlsafe(28)}
    ids = {}
    try:
        stack.start_database()
        stack.bootstrap()
        from sqlalchemy import create_engine

        engine = create_engine(stack.url("postgres"), hide_parameters=True)
        try:
            fixture.seed_fixture_catalog(engine)
        finally:
            engine.dispose()
        with fixture.server(fixture.fixture_app(stack.settings(), original_and=True), 0) as base:
            api = HTTP(base)
            user = api.request("POST", "/api/v1/auth/register", expected=201, body=credentials)
            ids["user"] = user["id"]
            token = api.login(credentials)
            workspace = api.request("GET", "/api/v2/workspaces", token=token)["items"][0]
            ids["workspace"] = workspace["workspace_id"]
            root = f"/api/v2/workspaces/{ids['workspace']}/applications"
            app = api.request(
                "POST",
                root,
                expected=201,
                token=token,
                body={"name": "Persistencia de laboratorio"},
            )
            ids["application"] = app["id"]
            app_base = root + "/" + app["id"]
            technology = api.request(
                "POST",
                app_base + "/technologies",
                expected=201,
                token=token,
                body={
                    "product": "small_business_rv340_firmware",
                    "vendor": "cisco",
                    "version": "1.0.0.33",
                },
            )
            ids["technology"] = technology["id"]
            tech = app_base + "/technologies/" + technology["id"]
            candidate_id = "c817e5ba-62c1-41e7-a15c-fb851fea761e"
            candidates = api.request(
                "GET",
                app_base
                + "/cpe-candidates?query=cisco&mode=fixture&part=o"
                + f"&technology_id={technology['id']}",
                token=token,
            )["items"]
            assert any(c["cpe_name_id"] == candidate_id for c in candidates)
            api.request(
                "PUT",
                tech + "/cpe",
                token=token,
                body={
                    "cpe_name_id": candidate_id,
                    "expected_selected_cpe": None,
                    "part": "o",
                    "mode": "fixture",
                },
            )
            run = api.request(
                "POST",
                tech + "/analyses",
                expected=201,
                token=token,
                key=__import__("uuid").uuid4().__str__(),
            )
            assert run["status"] == "completed" and "TITLE_TRUNCATED" in run["warning_codes"]
            ids["analysis"] = run["id"]
            finding = api.request(
                "GET", app_base + "/analyses/" + run["id"] + "/findings", token=token
            )["items"][0]
            assert (
                finding["applicability"] == "undetermined"
                and len(finding["evidence"]["descriptions"][0]["value"]) > 500
            )
            ids["finding"] = finding["id"]
            api.request(
                "PATCH",
                app_base + "/findings/" + finding["id"],
                token=token,
                body={
                    "applicability": "undetermined",
                    "expected_updated_at": finding["updated_at"],
                },
            )
            ids["evidence_hash"] = hashlib.sha256(
                json.dumps(finding["evidence"], sort_keys=True).encode()
            ).hexdigest()
            recommendation = api.request(
                "POST",
                app_base + "/findings/" + finding["id"] + "/recommendations",
                expected=201,
                token=token,
                body={
                    "recommendation": (
                        "Revisar aviso y condiciones de hardware; prueba controlada, sin escaneo"
                    )
                },
            )
            ids["recommendation"] = recommendation["id"]
            api.request(
                "PATCH",
                app_base + "/recommendations/" + recommendation["id"],
                token=token,
                body={
                    "status": "in_progress",
                    "expected_updated_at": recommendation[("updated_at")],
                },
            )
            api.request("POST", "/api/v1/auth/register", expected=201, body=other)
            verify_data(api, credentials, other, ids)
            api.client.close()
        archive = stack.backup()
        stack.stop_database()
        assert not stack.inspect("container", stack.name)["State"]["Running"]
        assert stack.inspect("volume", stack.volume)
        stack.start_database()
        stack.bootstrap()
        with fixture.server(fixture.fixture_app(stack.settings(), original_and=True), 0) as base:
            api = HTTP(base)
            api.request(
                "GET", "/api/v1/auth/me", token=token
            )  # JWT key survives controlled restart.
            verify_data(api, credentials, other, ids)
            api.client.close()
        restored.restore(archive)
        with fixture.server(fixture.fixture_app(restored.settings(), original_and=True), 0) as base:
            api = HTTP(base)
            api.request(
                "GET", "/api/v1/auth/me", token=token, expected=401
            )  # restore rotates JWT key.
            verify_data(api, credentials, other, ids)
            api.client.close()
        stack.verify()
        restored.verify()
        summary = {
            "result": "passed",
            "checks": [
                "register/login",
                "owner workspace",
                "application/technology",
                "verified fixture CPE",
                "original AND CVE",
                "review undetermined",
                "recommendation state",
                "complete service stop/restart",
                "stable original evidence",
                "A/B isolation after restart",
                "custom pg_dump backup",
                "restore into NEW volume",
                "A/B isolation after restore",
                "JWT stable on restart and rotated on restore",
                "exact schema and least privileges",
            ],
            "source_profile": profile,
            "source_volume": stack.volume,
            "restored_profile": restored.profile,
            "restored_volume": restored.volume,
            "backup": str(archive),
            "volumes_retained": True,
            "production_database_used": False,
            "zap_executed": False,
        }
        out = ROOT / "api-tests/v2/.artifacts/persistence-results.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    finally:
        for owned in [restored, stack]:
            if owned.check_owner("container", owned.name):
                owned.stop_database()
        print(
            "Only owned validation services stopped; both named volumes and private backup retained"
        )


if __name__ == "__main__":
    main()

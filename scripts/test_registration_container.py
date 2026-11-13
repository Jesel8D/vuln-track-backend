"""Exercise the built non-root API image against a NEW disposable V2 database."""

import os
import subprocess
import time

from sqlalchemy.engine import make_url

from scripts.disposable_v2 import DisposableV2, run

SMOKE = """
import json, os, secrets, urllib.request, urllib.error
assert os.getuid() == 10001
base = "http://127.0.0.1:8000"
def request(path, payload=None, token=None):
    headers = {"Content-Type":"application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(base+path, headers=headers,
        data=None if payload is None else json.dumps(payload).encode())
    try:
        with urllib.request.urlopen(req, timeout=10) as result:
            return result.status, json.load(result)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)
assert request("/ready")[0] == 200
username, password = "image_" + secrets.token_hex(8), secrets.token_urlsafe(24)
code, created = request("/api/v1/auth/register", {"username":username,"password":password})
assert code == 201 and set(created) == {"id","username"}
code, session = request("/api/v1/auth/login", {"username":username,"password":password})
assert code == 200 and session["token_type"] == "bearer"
token = session["access_token"]
assert request("/api/v1/auth/me", token=token) == (200,created)
code, directory = request("/api/v2/workspaces", token=token)
assert code == 200 and len(directory["items"]) == 1
workspace = directory["items"][0]
assert workspace["role"] == "owner"
assert request("/api/v2/workspaces/"+workspace["workspace_id"]+"/applications",
    token=token) == (200,{"items":[]})
assert request("/api/v2/workspaces")[0] == 401
assert request("/api/v1/auth/register", {"username":username,"password":password})[0] == 409
print("Docker API: UID10001, ready, register, login, identity, personal workspace, "
      "empty list, auth and duplicate passed")
"""


if __name__ == "__main__":
    with DisposableV2(sql_checks=False) as stack:
        name = stack.name + "-api"
        environment = {
            **os.environ,
            **{
                key: value
                for key, value in stack.environment.items()
                if not key.startswith("TEST_")
            },
            "DATABASE_URL": make_url(stack.environment["DATABASE_URL"])
            .set(port=5432)
            .render_as_string(hide_password=False),
        }
        keys = [
            "DATABASE_URL",
            "WORKSPACE_HMAC_KEY",
            "TOKEN_SECRET",
            "REGISTRATION_ENABLED",
            "CVE_WORKER_ENABLED",
            "ENVIRONMENT",
        ]
        try:
            run(
                "docker",
                "run",
                "--rm",
                "-d",
                "--name",
                name,
                "--network",
                "container:" + stack.name,
                *[value for key in keys for value in ("-e", key)],
                "vulntrack-backend:v2-registration",
                env=environment,
            )
            for _ in range(90):
                healthy = subprocess.run(
                    [
                        "docker",
                        "exec",
                        name,
                        "python",
                        "-c",
                        "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=1)",
                    ],
                    capture_output=True,
                )
                if healthy.returncode == 0:
                    break
                time.sleep(0.25)
            result = run("docker", "exec", "-i", name, "python", "-", input=SMOKE)
            print(result.stdout.strip())
        finally:
            subprocess.run(["docker", "stop", "--time", "5", name], capture_output=True)

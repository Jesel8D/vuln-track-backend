"""Explicit, signed, one-use laboratory scope. No trusted issuer in this release."""

import base64
import hashlib
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.core.errors import APIError
from app.integrations.cve_transport import CVE_URL

HOST = "services.nvd.nist.gov"
CPE = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
CPE_ID = "10e70f95-eb64-4262-a822-9055aab8fe76"
PARAMS = {"cpeName": CPE, "startIndex": 0, "resultsPerPage": 20}
# Provisioning a review-pinned PUBLIC verification key is a later explicit action,
# not an environment switch. No signing key/real grant is issued by this release.
TRUSTED_AUTHORITY_SHA256 = None
AUTHORITY = Path(__file__).parents[2] / "dev/nvd-trial/authority.pem"
DOCUMENTS = {"contract", "anonymous_access", "quotas", "pagination", "attribution"}
_SEAL = object()


def denied():
    return APIError(503, "TRIAL_NOT_AUTHORIZED", "Ensayo NVD sin autorización válida")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def bounded_file(path, maximum=16384):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise denied()
    return path.read_bytes()


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise denied()
        obj[key] = value
    return obj


def read_json(path):
    return json.loads(bounded_file(path), object_pairs_hook=unique_object)


def validate_plan(plan):
    keys = {
        "version",
        "laboratory",
        "commit",
        "image",
        "endpoint",
        "method",
        "params",
        "requests",
        "seconds",
        "max_bytes",
        "purpose",
        "nonce",
    }
    if set(plan) != keys or plan["version"] != "5c2-egress-1":
        raise denied()
    if not re.fullmatch(r"vulntrack-5c2-[0-9a-f]{12}", plan["laboratory"]):
        raise denied()
    if not re.fullmatch(r"[0-9a-f]{40}", plan["commit"]):
        raise denied()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", plan["image"]):
        raise denied()
    if not re.fullmatch(r"[0-9a-f]{32}", plan["nonce"]):
        raise denied()
    if (
        plan["endpoint"],
        plan["method"],
        plan["params"],
        plan["requests"],
        plan["seconds"],
        plan["max_bytes"],
        plan["purpose"],
    ) != (CVE_URL, "GET", PARAMS, 1, 20, 2097152, "first-isolated-nvd-cve-trial"):
        raise denied()
    # bool == 1 must not satisfy a request quota or an index.
    for value in (
        plan["requests"],
        plan["seconds"],
        plan["max_bytes"],
        plan["params"]["startIndex"],
        plan["params"]["resultsPerPage"],
    ):
        if type(value) is not int:
            raise denied()


@dataclass(frozen=True)
class Permit:
    plan: dict
    grant_sha256: str
    plan_sha256: str
    not_after: datetime
    seal: object

    def check(self):
        if self.seal is not _SEAL or datetime.now(UTC) >= self.not_after:
            raise denied()
        validate_plan(self.plan)
        if hashlib.sha256(canonical(self.plan)).hexdigest() != self.plan_sha256:
            raise denied()


def authorize(plan_path, grant_path, *, commit, image):
    """Verify before Docker, DB, DNS or quota. A JSON assertion alone grants nothing."""
    if TRUSTED_AUTHORITY_SHA256 is None:
        raise denied()  # Before even reading an untrusted grant or plan.
    try:
        key = bounded_file(AUTHORITY, 4096)
        if hashlib.sha256(key).hexdigest() != TRUSTED_AUTHORITY_SHA256:
            raise denied()
        plan, envelope = read_json(plan_path), read_json(grant_path)
        validate_plan(plan)
        if plan["commit"] != commit or plan["image"] != image:
            raise denied()
        if set(envelope) != {"grant", "signature"}:
            raise denied()
        grant = envelope["grant"]
        if set(grant) != {
            "plan_sha256",
            "not_before",
            "not_after",
            "official_evidence",
            "approved_by",
        }:
            raise denied()
        if grant["plan_sha256"] != hashlib.sha256(canonical(plan)).hexdigest():
            raise denied()
        docs = grant["official_evidence"]
        if set(docs) != DOCUMENTS or any(
            not re.fullmatch(r"[0-9a-f]{64}", v) for v in docs.values()
        ):
            raise denied()
        if not isinstance(grant["approved_by"], str) or not 1 <= len(grant["approved_by"]) <= 128:
            raise denied()
        start, end = (datetime.fromisoformat(grant[k]) for k in ("not_before", "not_after"))
        if start.tzinfo is None or end.tzinfo is None or not start <= datetime.now(UTC) < end:
            raise denied()
        if not 20 <= (end - start).total_seconds() <= 300:
            raise denied()
        signature = base64.b64decode(envelope["signature"], validate=True)
        if len(signature) != 64 or b"BEGIN PUBLIC KEY" not in key:
            raise denied()
        with tempfile.TemporaryDirectory(prefix="nvd-signature-") as directory:
            root = Path(directory)
            (root / "key.pem").write_bytes(key)
            (root / "grant").write_bytes(canonical(grant))
            (root / "signature").write_bytes(signature)
            result = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(root / "key.pem"),
                    "-rawin",
                    "-in",
                    str(root / "grant"),
                    "-sigfile",
                    str(root / "signature"),
                ],
                capture_output=True,
                timeout=2,
            )
            if result.returncode:
                raise denied()
        permit = Permit(
            plan, hashlib.sha256(canonical(grant)).hexdigest(), grant["plan_sha256"], end, _SEAL
        )
        permit.check()
        return permit
    except APIError:
        raise
    except Exception:
        raise denied() from None

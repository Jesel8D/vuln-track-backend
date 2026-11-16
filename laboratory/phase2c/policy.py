"""Laboratory permits only. Never imported by FastAPI or an operational worker."""

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from uuid import UUID

from app.services.web_target_policy import DestinationDenied, DestinationPolicy, public_ip

LAB_HOSTS = {"control.example.net", "v6.example.net", "rebind.example.net", "fail.example.net"}


def identity(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("Invalid identity")
    return value


def number(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("Invalid time")
    return value


@dataclass(frozen=True, slots=True)
class LabPermit:
    operation_id: str
    workspace_id: str
    application_id: str
    target_id: str
    challenge_id: str
    actor_id: str
    gateway_epoch: str
    authority_epoch: str
    url: str
    hostname: str
    scheme: str
    port: int
    addresses: tuple[str, ...]
    target_version: str
    challenge_version: int
    issued_at: float
    expires_at: float
    declaration_expires_at: float
    challenge_expires_at: float
    maximum_seconds: int = 5
    maximum_connections: int = 1
    provenance: str = "laboratory"

    def __post_init__(self):
        for field in (
            "operation_id",
            "workspace_id",
            "application_id",
            "target_id",
            "challenge_id",
            "actor_id",
            "gateway_epoch",
            "authority_epoch",
        ):
            identity(getattr(self, field))
        destination = DestinationPolicy().parse(self.url)
        if (
            self.provenance != "laboratory"
            or destination.url != self.url
            or destination.hostname != self.hostname
            or self.hostname not in LAB_HOSTS
            or self.scheme != "https"
            or type(self.port) is not int
            or self.port != 443
            or not isinstance(self.addresses, tuple)
            or not 1 <= len(self.addresses) <= 16
            or self.addresses != tuple(sorted({public_ip(v) for v in self.addresses}))
            or not isinstance(self.target_version, str)
            or len(self.target_version) > 40
            or type(self.challenge_version) is not int
            or self.challenge_version < 1
            or type(self.maximum_seconds) is not int
            or self.maximum_seconds != 5
            or type(self.maximum_connections) is not int
            or self.maximum_connections != 1
        ):
            raise ValueError("Laboratory scope rejected")
        for value in (
            self.issued_at,
            self.expires_at,
            self.declaration_expires_at,
            self.challenge_expires_at,
        ):
            number(value)
        if not (
            self.issued_at < self.expires_at <= self.issued_at + 10
            and self.expires_at <= min(self.declaration_expires_at, self.challenge_expires_at)
        ):
            raise ValueError("Laboratory lease rejected")

    def to_dict(self):
        value = asdict(self)
        value["addresses"] = list(self.addresses)
        return value

    @classmethod
    def read(cls, value):
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("Invalid permit shape")
        if not isinstance(value["addresses"], list):
            raise ValueError("Invalid addresses")
        return cls(**{**value, "addresses": tuple(value["addresses"])})

    @property
    def digest(self):
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True).encode()).hexdigest()

    def require_current(self, now, epoch):
        if epoch != self.gateway_epoch or not self.issued_at <= now < self.expires_at:
            raise DestinationDenied("POLICY_EXPIRED_OR_STALE")


def require_lab_snapshot(target, challenge, *, workspace, application, actor):
    """Fresh, RLS-filtered API responses from an OWNED disposable DB, not React.

    This authorizes only a fixture experiment. A pending challenge cannot produce
    an operational permit; the operational service remains unchanged and blocked.
    """
    if (
        target["workspace_id"] != workspace
        or target["application_id"] != application
        or challenge["workspace_id"] != workspace
        or challenge["application_id"] != application
        or challenge["target_id"] != target["id"]
        or not actor
        or target["authorization_status"] != "approved"
        or challenge["state"] != "pending"
        or challenge["effective_state"] != "pending"
        or challenge["scope_invalidated"]
        or challenge["attempts"] != 0
        or challenge["control_verified"] is not False
        or challenge["remote_verification_available"] is not False
        or challenge["execution_enabled"] is not False
        or DestinationPolicy().parse(target["url"]).hostname not in LAB_HOSTS
    ):
        raise ValueError("No current laboratory scope")


def operation_request(value):
    if not isinstance(value, dict) or set(value) != {"operation_id"}:
        raise ValueError("Only an operation identity is accepted")
    return identity(value["operation_id"])

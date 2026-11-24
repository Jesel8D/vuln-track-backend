"""Scoped lab capability, not enabled by Settings or a public API parameter."""

import hashlib
from dataclasses import dataclass

from sqlalchemy.engine import make_url

from app.integrations.cve_transport import HTTPPolicy, RequestBudget
from app.integrations.nvd_cve import CVEClient
from app.integrations.nvd_lab_authorization import CPE, denied
from app.integrations.nvd_lab_transport import NVDLabTransport


class LabCVEClient(CVEClient):
    page_limit = 20

    def __init__(self, adapter, cancelled):
        if type(adapter) is not NVDLabTransport:
            raise denied()
        adapter.permit.check()
        super().__init__(transport=adapter, live=False, http_policy=HTTPPolicy(timeout=20))
        self.permit = adapter.permit
        self.cache_namespace = "lab:5c2:" + self.permit.plan["nonce"]
        self.budget = RequestBudget(
            requests=1, seconds=adapter.pin.remaining(), cancelled=cancelled
        )
        self._prepared = None
        self._delivered = False

    def prepare(self):
        if self._prepared is not None:
            raise denied()
        page = self._fetch()
        self.transport.attest(self.last_response_bytes)
        self._prepared = page
        return page

    def _fetch(self):
        return super().page(CPE, 0, 20, budget=self.budget)

    def page(self, cpe, start=0, limit=20, **kwargs):
        # The one response is validated BEFORE a run_context is captured. SQL
        # provenance is immutable, so do not create a live-labelled queued intent.
        if cpe != CPE or start != 0 or limit != 20 or kwargs or self._delivered or not proven(self):
            raise denied()
        self._delivered = True
        return self._prepared


def lab_client(value):
    return type(value) is LabCVEClient and type(value.transport) is NVDLabTransport


def proven(client):
    return (
        lab_client(client)
        and client._prepared is not None
        and client.last_response_bytes is not None
        and client.transport.raw_digest == hashlib.sha256(client.last_response_bytes).hexdigest()
        and client.transport.peer_verified
        and client.transport.attempts == 1
    )


@dataclass(frozen=True)
class LabScope:
    client: LabCVEClient
    database_url_digest: str


def bind_lab(app, client, database_url):
    # A factory-only in-process capability; normal create_app() never installs it.
    # Worker has numeric PG on its exclusive internal bridge, not a normal profile.
    url = make_url(database_url)
    if (
        url.username != "vulntrack_v2_api"
        or url.database != "vulntrack_v2_development"
        or url.port != 5432
    ):
        raise denied()
    if url.query or not lab_client(client):
        raise denied()
    app.state.nvd_lab_scope = LabScope(client, hashlib.sha256(database_url.encode()).hexdigest())
    app.state.cve = client


def scoped_lab(request):
    scope = getattr(request.app.state, "nvd_lab_scope", None)
    client = request.app.state.cve
    return (
        type(scope) is LabScope
        and scope.client is client
        and proven(client)
        and scope.database_url_digest
        == hashlib.sha256(
            request.app.state.settings.database_url.get_secret_value().encode()
        ).hexdigest()
    )

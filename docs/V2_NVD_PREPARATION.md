# CVE transport preparation 5C.1 (offline only)

This release has **no real CVE network capability**, including the legacy V1
worker. CVEClient accepts only an explicitly injected httpx.MockTransport;
no adapter, a different adapter, `live=True`, NVD_MODE=live or an API key cannot
open CVE egress. CVE_LIVE_ENABLED defaults false and true is rejected by Settings.
V2 keeps its additional live gate. Normal CPE/catalog operations are retained; the base CPE helper now rejects
the CVE URL as well, preventing it from becoming a second CVE path.

The CVE boundary retains the canonical HTTPS endpoint and three public params,
sets verify=True, trust_env=False, follow_redirects=False, requests identity
encoding and rejects any compression before reading. It checks declared/raw byte
limits and rejects ambiguous JSON. An asynchronous exchange has an overall
monotonic deadline and worker cancellation observer; a bounded phase timeout is
also configured. This is tested on simulated async streams, not NVD TLS/DNS.
The body is public provider data, without inventory/review/credential context.

The transport owns no retries. The existing worker retains at most two retries,
its backoff/cooldown and durable per-page transactions. New per-execution budgets
are shared across pages/attempts: CVE_MAX_REQUESTS=15, CVE_MAX_PAGES=5,
CVE_MAX_RECORDS=500, CVE_MAX_BYTES=10485760, CVE_MAX_SECONDS=300. HTTP defaults:
CVE_HTTP_MAX_BYTES=2097152, CVE_HTTP_TOTAL_SECONDS=10. V2 stays one page/100;
there is no new collection endpoint. A budget/error after a valid page produces
partial coverage, before one failed coverage, preserving history. Retry-After
supports seconds/date without shortening large delays to force retries.

Clients sharing the application's quota share a CVE concurrency mutex and a
workspace-independent spacing budget. Cache hits remain before provider I/O.
This is not a distributed egress limiter. Multiple processes or other consumers
still need exclusive/shared coordination before any future live experiment.

The public cache field allowlist was aligned with fields found in the official
CVE JSON schema2.2.4 (recorded in a test fixture); parser identity becomes
public-cve-5c1-1, so older evidence is never rewritten. The parser is a restricted
subset, not a full schema/$ref validator; for example vulnStatus remains required
by the local model although optional in that schema. Such differences and current
service semantics must be reviewed before live. Fixture/simulated data never
become live merely because this schema was read.

`scripts.nvd_controlled_probe --plan` only reads the existing local readonly CPE
catalogue and prepares a public-identity plan with no inventory or API key.
`--execute-live` always returns2 before any DB or network operation in5C.1.
No frontend toggle, hidden environment bypass or auto-enable by key exists.

Official six NVD documentation pages returned403 during this increment; the
schema at csrc.nist.gov was accessible. Endpoint/request semantics, current
quotas and attribution are not certified from the schema. Real DNS/public-IP
pinning/egress and TLS behavior have not been tested against NVD. A future
reviewed5C.2 release plus later explicit authorization is required; technical
readiness to request that experiment remains NO-GO until the documented controls
are closed. The normal installation stays fixture, schema v10 unchanged.

Official schema receipt: https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
(2026-11-24, SHA256 2b9c4e8ab7e6e42aa17ea787f58167beff47c119c6f291405f86ac19c6149e01).
The unchanged official bytes are in tests/fixtures/nvd_cve_api_2_2_4.schema.json.
This is a schema document, never a live CVE response.

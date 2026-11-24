# V2 persistent CVE cache (5B, offline only)

Migration `v2_0010_cve_cache` adds a private RLS coordination schema and immutable
public provider responses. Application/device runs retain private context and
reference the response version; human review is never part of a cached body.
The catalogue database is unchanged. Upgrade the verification Alembic chain as a
coordinated release, with a new verified backup first. Destructive downgrade is
intentionally refused; restore into another owned volume with matching code.

The optional `storage` object in run DTOs has exactly `resolution`
(provider/reused/failed), `refresh_attempted` (boolean), `used_at`, `obtained_at`,
and `expires_at` (timestamps or all null for failed). A hit preserves original
`provenance.response_received_at`, while its private execution/request and finding
IDs are new. Existing history with no metadata remains readable. Dashboard recent
runs and priority items use the same decorator; monthly counts are executions,
including reuse, rather than provider calls. Existing endpoints and pagination
are retained. Internal IDs, keys, namespaces and leases are not public DTO fields.

Default settings (environment, uppercase):

- CVE_CACHE_ENABLED=true
- CVE_CACHE_TTL_SECONDS=86400, CVE_CACHE_EMPTY_TTL_SECONDS=3600
- CVE_CACHE_LEASE_SECONDS=120, also bounded by CVE_EXECUTION_SECONDS
- CVE_CACHE_MAX_ENTRIES=500 (both slots and immutable response versions/workspace)
- CVE_CACHE_MAX_BYTES=104857600 (logical body bytes/workspace)

Hard SQL ceilings are 500 slots, 500 versions and 100 MiB per workspace, 2 MiB per
body, lease at most 5 minutes, response TTL at most 7 days. Lower settings can
refuse admission earlier. There is no eviction or automatic deletion. At capacity,
a valid hit still works; growth fails explicitly. These ceilings do not cap WAL,
indexes, backups, all workspaces combined or total physical disk usage.

Only complete unexpired validated pages hit. Partial pages are immutable evidence
but never replace the complete pointer; empty valid pages have shorter TTL and
are not claims of absence of vulnerabilities. Expired refresh failure preserves
history, returns failure and never returns stale data as freshly obtained or zero.

Deterministic keys preserve exact validated CPE bindings and include provider,
source mode, stable dataset/scenario namespace, parser/contract version, pagination
and supported filters. A named controlled provider opts in via `cache_namespace`;
unregistered injected clients keep their uncached test behavior. Default fixture
factory namespaces are hashed from the actual capture/variant, with derivatives
classified simulated. The V2 resolver refuses live before I/O, irrespective of
cache setting. Fixture cannot satisfy live. V1 worker behavior is unchanged.

Short signed transactions use nonblocking per-workspace coordination and token
fencing, never hold SQL across provider I/O, and return 409 CVE_CACHE_BUSY to a
follower. A crashed lease expires; a late leader cannot publish. Reconcile a
failed intent using the same Idempotency-Key; a genuinely new attempt uses a new
key. No automatic retries. A lease is not a transport cancellation/deadline.

Errors: CVE_CACHE_BUSY, CVE_CACHE_LEASE_EXPIRED, CVE_CACHE_CAPACITY_REACHED,
CVE_CACHE_INVALID_RESPONSE, CVE_CACHE_INTEGRITY, CVE_CACHE_UNAVAILABLE,
CVE_LIVE_DISABLED. Preserve their distinction from a successful empty page.

Focused offline tests: `tests/unit/test_cve_cache.py` and
`tests/integration/test_cve_cache.py`, the latter through an owned DisposableV2
runner. The existing autouse HTTPTransport guard forbids real HTTP during pytest;
CVE upstream is MockTransport/countable or explicitly forbidden on a persisted
hit. Real PG restart and dump restore evidence is kept in the installation's
private incremento-5b-evidencia directory. No real NVD success is claimed.

-- Additive RC2.2 catalog. Only the database operator can import official records.
CREATE SCHEMA vulntrack_catalog;
REVOKE ALL ON SCHEMA vulntrack_catalog FROM PUBLIC;
GRANT USAGE ON SCHEMA vulntrack_catalog TO vulntrack_app;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE vulntrack_catalog.products (
    mode text NOT NULL CHECK (mode IN ('fixture','live')),
    cpe_name_id uuid NOT NULL,
    cpe_name text NOT NULL CHECK (vulntrack.valid_text(cpe_name, 1024) AND left(cpe_name, 8)='cpe:2.3:'),
    part text NOT NULL CHECK (part IN ('a','h','o')),
    vendor text NOT NULL,
    product text NOT NULL,
    version text NOT NULL,
    title text NOT NULL,
    search_text text NOT NULL,
    titles jsonb NOT NULL CHECK (jsonb_typeof(titles)='array'),
    deprecated boolean NOT NULL,
    deprecated_by jsonb NOT NULL CHECK (jsonb_typeof(deprecated_by)='array'),
    nvd_created timestamptz NOT NULL,
    nvd_modified timestamptz NOT NULL CHECK (nvd_modified >= nvd_created),
    synchronized_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    source text NOT NULL CHECK (source IN ('nvd-api','nvd-captured-fixture')),
    original jsonb NOT NULL CHECK (jsonb_typeof(original)='object' AND octet_length(original::text)<=65536),
    PRIMARY KEY (mode, cpe_name_id),
    CHECK ((mode='live') = (source='nvd-api'))
);
CREATE INDEX catalog_vendor_idx ON vulntrack_catalog.products(mode, vendor, part);
CREATE INDEX catalog_product_version_idx ON vulntrack_catalog.products(mode, part, vendor, product, version);
CREATE INDEX catalog_search_idx ON vulntrack_catalog.products USING gin(search_text gin_trgm_ops);

CREATE TABLE vulntrack_catalog.sync_runs (
    id uuid PRIMARY KEY,
    mode text NOT NULL CHECK (mode IN ('fixture','live')),
    scope jsonb NOT NULL CHECK (jsonb_typeof(scope)='object'),
    status text NOT NULL DEFAULT 'partial' CHECK (status IN ('partial','complete','failed')),
    next_offset integer NOT NULL DEFAULT 0 CHECK (next_offset >= 0),
    total_reported integer CHECK (total_reported >= 0),
    error_code text,
    retry_after timestamptz,
    started_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
CREATE INDEX catalog_last_sync_idx ON vulntrack_catalog.sync_runs(mode, updated_at DESC, id);
CREATE TABLE vulntrack_catalog.sync_pages (
    run_id uuid NOT NULL REFERENCES vulntrack_catalog.sync_runs(id),
    page_offset integer NOT NULL CHECK (page_offset >= 0),
    nvd_timestamp timestamptz NOT NULL,
    received_count integer NOT NULL CHECK (received_count BETWEEN 0 AND 20),
    stored_count integer NOT NULL CHECK (stored_count BETWEEN 0 AND received_count),
    discarded jsonb NOT NULL CHECK (jsonb_typeof(discarded)='object'),
    fetched_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY(run_id, page_offset)
);
GRANT SELECT ON vulntrack_catalog.products, vulntrack_catalog.sync_runs TO vulntrack_app;

ALTER TABLE vulntrack_devices.devices
    ALTER COLUMN product_vendor DROP NOT NULL,
    ALTER COLUMN product DROP NOT NULL;
ALTER TABLE vulntrack_devices.identifications ADD COLUMN catalog_evidence jsonb
    CHECK (catalog_evidence IS NULL OR jsonb_typeof(catalog_evidence)='object');

CREATE SCHEMA vulntrack_catalog_private;
REVOKE ALL ON SCHEMA vulntrack_catalog_private FROM PUBLIC;
GRANT USAGE ON SCHEMA vulntrack_catalog_private TO vulntrack_app;
CREATE TABLE vulntrack_catalog_private.device_registrations (
    workspace_id uuid NOT NULL,
    actor_id uuid NOT NULL REFERENCES vulntrack.users(id),
    request_key uuid NOT NULL,
    fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    device_id uuid NOT NULL,
    identification_id uuid,
    PRIMARY KEY (workspace_id, actor_id, request_key),
    FOREIGN KEY (workspace_id, device_id) REFERENCES vulntrack_devices.devices(workspace_id, id),
    FOREIGN KEY (workspace_id, device_id, identification_id)
        REFERENCES vulntrack_devices.identifications(workspace_id, device_id, id)
);
ALTER TABLE vulntrack_catalog_private.device_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulntrack_catalog_private.device_registrations FORCE ROW LEVEL SECURITY;
CREATE POLICY scoped_records ON vulntrack_catalog_private.device_registrations
    USING (workspace_id=vulntrack.current_workspace_id()
       AND actor_id=vulntrack.current_user_id()
       AND vulntrack.has_workspace_role(workspace_id, ARRAY['owner','editor']))
    WITH CHECK (workspace_id=vulntrack.current_workspace_id()
       AND actor_id=vulntrack.current_user_id()
       AND vulntrack.has_workspace_role(workspace_id, ARRAY['owner','editor']));
GRANT SELECT, INSERT ON vulntrack_catalog_private.device_registrations TO vulntrack_app;

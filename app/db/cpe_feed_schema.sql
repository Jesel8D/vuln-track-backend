-- RC2.3 reuses the existing CPE table. A digest identifies one verified official feed.
DO $$
DECLARE item record;
BEGIN
    FOR item IN SELECT conname FROM pg_constraint
        WHERE conrelid='vulntrack_catalog.products'::regclass AND contype='c'
          AND pg_get_constraintdef(oid) LIKE '%nvd-api%'
    LOOP
        EXECUTE format('ALTER TABLE vulntrack_catalog.products DROP CONSTRAINT %I', item.conname);
    END LOOP;
END $$;
ALTER TABLE vulntrack_catalog.products ADD CONSTRAINT products_official_source_check
    CHECK ((mode='fixture' AND source='nvd-captured-fixture')
        OR (mode='live' AND source IN ('nvd-api','nvd-feed')));
CREATE INDEX catalog_cpe_exact_idx ON vulntrack_catalog.products (mode,cpe_name);
CREATE INDEX catalog_vendor_prefix_idx ON vulntrack_catalog.products (mode,vendor text_pattern_ops);
CREATE INDEX catalog_family_browse_idx ON vulntrack_catalog.products
    (mode,vendor,product,part,version,deprecated,cpe_name_id);

CREATE TABLE vulntrack_catalog.feed_imports (
    digest text PRIMARY KEY CHECK (digest ~ '^[0-9a-f]{64}$'),
    source_modified timestamptz NOT NULL,
    gz_bytes bigint NOT NULL CHECK (gz_bytes > 0),
    json_bytes bigint NOT NULL CHECK (json_bytes > 0),
    total_items bigint NOT NULL CHECK (total_items >= 0),
    next_item bigint NOT NULL DEFAULT 0 CHECK (next_item BETWEEN 0 AND total_items),
    stored bigint NOT NULL DEFAULT 0 CHECK (stored >= 0),
    discarded bigint NOT NULL DEFAULT 0 CHECK (discarded >= 0),
    skipped bigint NOT NULL DEFAULT 0 CHECK (skipped >= 0),
    status text NOT NULL DEFAULT 'partial' CHECK (status IN ('partial','complete','failed')),
    error_code text,
    started_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK (stored+discarded+skipped=next_item),
    CHECK (status<>'complete' OR next_item=total_items)
);
GRANT SELECT ON vulntrack_catalog.feed_imports TO vulntrack_app;

ALTER TABLE vulntrack_catalog.sync_pages
    ADD COLUMN new_count integer CHECK (new_count BETWEEN 0 AND stored_count),
    ADD COLUMN changed_count integer CHECK (changed_count BETWEEN 0 AND stored_count),
    ADD COLUMN deprecated_count integer CHECK (deprecated_count BETWEEN 0 AND stored_count);

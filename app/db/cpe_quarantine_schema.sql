-- Quarantine records remain evidence of a rejected dictionary entry.
CREATE TABLE vulntrack_catalog.feed_quarantine (
    digest text NOT NULL REFERENCES vulntrack_catalog.feed_imports(digest),
    cpe_name_id uuid NOT NULL,
    ordinal bigint NOT NULL CHECK (ordinal > 0),
    reason text NOT NULL CHECK (reason = 'INVALID_CPE_LANGUAGE'),
    original jsonb NOT NULL CHECK (
        jsonb_typeof(original) = 'object'
        AND (original #>> '{cpe,cpeNameId}') IS NOT NULL
        AND lower(original #>> '{cpe,cpeNameId}') = cpe_name_id::text
    ),
    recorded_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (digest,cpe_name_id),
    UNIQUE (digest,ordinal)
);
REVOKE ALL ON vulntrack_catalog.feed_quarantine FROM PUBLIC,vulntrack_app;

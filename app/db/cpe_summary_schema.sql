-- One cached aggregate per acquisition mode, ordered independently of feed progress.
CREATE TABLE vulntrack_catalog.summary (
    mode text PRIMARY KEY CHECK (mode IN ('live','fixture')),
    records bigint NOT NULL CHECK (records >= 0),
    vendors bigint NOT NULL CHECK (vendors BETWEEN 0 AND records),
    products bigint NOT NULL CHECK (products BETWEEN 0 AND records),
    last_synchronized_at timestamptz,
    refreshed_at timestamptz NOT NULL DEFAULT statement_timestamp()
);
GRANT SELECT ON vulntrack_catalog.summary TO vulntrack_app;

INSERT INTO vulntrack_catalog.summary
    (mode,records,vendors,products,last_synchronized_at)
SELECT modes.mode,counts.records,counts.vendors,counts.products,counts.latest
FROM (VALUES ('live'),('fixture')) modes(mode)
CROSS JOIN LATERAL (
    SELECT COALESCE(sum(family.records),0)::bigint records,
           count(DISTINCT family.vendor) vendors,count(*) products,max(family.latest) latest
    FROM (
        SELECT vendor,product,part,count(*) records,max(synchronized_at) latest
        FROM vulntrack_catalog.products WHERE mode=modes.mode GROUP BY vendor,product,part
    ) family
) counts;

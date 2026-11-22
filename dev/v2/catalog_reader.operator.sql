-- Operator-only. Execute on the verified source after explicit authorization.
\set ON_ERROR_STOP on
BEGIN;
CREATE ROLE vulntrack_catalog_reader NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB
    NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT CONNECT ON DATABASE vulntrack_v2_development TO vulntrack_catalog_reader;
GRANT USAGE ON SCHEMA vulntrack_catalog TO vulntrack_catalog_reader;
GRANT SELECT ON vulntrack_catalog.products, vulntrack_catalog.summary,
    vulntrack_catalog.sync_runs, vulntrack_catalog.feed_imports TO vulntrack_catalog_reader;
ALTER ROLE vulntrack_catalog_reader IN DATABASE vulntrack_v2_development
    SET default_transaction_read_only = on;
ALTER ROLE vulntrack_catalog_reader IN DATABASE vulntrack_v2_development
    SET statement_timeout = '2s';
COMMIT;
-- Set a unique password interactively with \password before enabling LOGIN.

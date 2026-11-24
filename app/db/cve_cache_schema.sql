-- 5B: private coordination separate from immutable public provider bodies.
CREATE SCHEMA vulntrack_cve_cache;
REVOKE ALL ON SCHEMA vulntrack_cve_cache FROM PUBLIC;
GRANT USAGE ON SCHEMA vulntrack_cve_cache TO vulntrack_app;

CREATE TABLE vulntrack_cve_cache.slots (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES vulntrack.workspaces(id) ON DELETE RESTRICT,
    key text NOT NULL CHECK (key ~ '^[0-9a-f]{64}$'),
    query text NOT NULL CHECK (octet_length(query)<=4096 AND jsonb_typeof(query::jsonb)='object'),
    source text NOT NULL CHECK (source IN ('fixture','simulated','live','unknown')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    current_response_id uuid,
    lease_token uuid,
    lease_expires_at timestamptz,
    UNIQUE (workspace_id,key),
    CHECK (key=encode(sha256(convert_to(query,'UTF8')),'hex')),
    CHECK ((query::jsonb)->>'mode'=source),
    CHECK ((lease_token IS NULL)=(lease_expires_at IS NULL))
);
CREATE TABLE vulntrack_cve_cache.responses (
    id uuid PRIMARY KEY,
    slot_id uuid NOT NULL REFERENCES vulntrack_cve_cache.slots(id) ON DELETE RESTRICT,
    body text NOT NULL CHECK (octet_length(body)<=2097152 AND jsonb_typeof(body::jsonb)='object'),
    digest text NOT NULL CHECK (digest=encode(sha256(convert_to(body,'UTF8')),'hex')),
    coverage text NOT NULL CHECK (coverage IN ('complete','partial')),
    warning_codes jsonb NOT NULL CHECK (jsonb_typeof(warning_codes)='array'
        AND jsonb_array_length(warning_codes)<=20),
    fetched_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (slot_id,id),
    CHECK (expires_at>fetched_at AND expires_at<=fetched_at+interval '7 days')
);
ALTER TABLE vulntrack_cve_cache.slots ADD CONSTRAINT cache_current_response_fk
    FOREIGN KEY (id,current_response_id) REFERENCES vulntrack_cve_cache.responses(slot_id,id)
    ON DELETE RESTRICT;
CREATE INDEX cache_response_slot_created_idx ON vulntrack_cve_cache.responses(slot_id,created_at,id);

ALTER TABLE vulntrack_cve_cache.slots ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulntrack_cve_cache.slots FORCE ROW LEVEL SECURITY;
ALTER TABLE vulntrack_cve_cache.responses ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulntrack_cve_cache.responses FORCE ROW LEVEL SECURITY;
CREATE POLICY cache_slots_read ON vulntrack_cve_cache.slots FOR SELECT
    USING (workspace_id=vulntrack.current_workspace_id()
        AND vulntrack.has_workspace_role(workspace_id,ARRAY['owner','editor','viewer']));
CREATE POLICY cache_slots_create ON vulntrack_cve_cache.slots FOR INSERT
    WITH CHECK (workspace_id=vulntrack.current_workspace_id()
        AND vulntrack.has_workspace_role(workspace_id,ARRAY['owner','editor']));
CREATE POLICY cache_slots_update ON vulntrack_cve_cache.slots FOR UPDATE
    USING (workspace_id=vulntrack.current_workspace_id()
        AND vulntrack.has_workspace_role(workspace_id,ARRAY['owner','editor']))
    WITH CHECK (workspace_id=vulntrack.current_workspace_id()
        AND vulntrack.has_workspace_role(workspace_id,ARRAY['owner','editor']));
CREATE POLICY cache_responses_read ON vulntrack_cve_cache.responses FOR SELECT
    USING (EXISTS (SELECT 1 FROM vulntrack_cve_cache.slots s WHERE s.id=slot_id));
CREATE POLICY cache_responses_create ON vulntrack_cve_cache.responses FOR INSERT
    WITH CHECK (EXISTS (SELECT 1 FROM vulntrack_cve_cache.slots s WHERE s.id=slot_id
        AND vulntrack.has_workspace_role(s.workspace_id,ARRAY['owner','editor'])));
GRANT SELECT,INSERT ON vulntrack_cve_cache.slots,vulntrack_cve_cache.responses TO vulntrack_app;
GRANT UPDATE(current_response_id,lease_token,lease_expires_at)
    ON vulntrack_cve_cache.slots TO vulntrack_app;

CREATE FUNCTION vulntrack_cve_cache.guard_slot() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND
        ROW(NEW.id,NEW.workspace_id,NEW.key,NEW.query,NEW.source,NEW.created_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.workspace_id,OLD.key,OLD.query,OLD.source,OLD.created_at)) THEN
        RAISE EXCEPTION 'Immutable cache identity' USING ERRCODE='23514';
    END IF;
    IF NOT pg_try_advisory_xact_lock(hashtextextended(NEW.workspace_id::text,55)) THEN
        RAISE EXCEPTION 'Cache coordinator busy' USING ERRCODE='55P03';
    END IF;
    IF TG_OP='INSERT' THEN
        IF NEW.current_response_id IS NOT NULL OR NEW.lease_token IS NOT NULL OR
            (SELECT count(*) FROM vulntrack_cve_cache.slots WHERE workspace_id=NEW.workspace_id)>=500
        THEN RAISE EXCEPTION 'Cache admission limit' USING ERRCODE='23514'; END IF;
    ELSE
        IF (OLD.lease_token IS NOT NULL AND OLD.lease_expires_at>clock_timestamp()
            AND NEW.lease_token IS DISTINCT FROM OLD.lease_token AND NEW.lease_token IS NOT NULL)
            OR (OLD.lease_token IS NOT NULL AND NEW.lease_token IS NULL AND
                OLD.lease_token::text IS DISTINCT FROM current_setting('vulntrack.cache_lease',true))
            OR (NEW.lease_token IS NOT NULL AND
                (NEW.lease_token::text IS DISTINCT FROM current_setting('vulntrack.cache_lease',true)
                 OR NEW.lease_expires_at<=clock_timestamp()
                 OR NEW.lease_expires_at>clock_timestamp()+interval '5 minutes')) THEN
            RAISE EXCEPTION 'Invalid cache lease transition' USING ERRCODE='23514';
        END IF;
        IF NEW.current_response_id IS DISTINCT FROM OLD.current_response_id AND
            (OLD.lease_token IS NULL OR OLD.lease_expires_at IS NULL
             OR OLD.lease_token::text IS DISTINCT FROM current_setting('vulntrack.cache_lease',true)
             OR OLD.lease_expires_at<=clock_timestamp()
             OR NOT EXISTS (SELECT 1 FROM vulntrack_cve_cache.responses r
                WHERE r.id=NEW.current_response_id AND r.slot_id=NEW.id AND r.coverage='complete'))
        THEN RAISE EXCEPTION 'Invalid cache publication' USING ERRCODE='23514'; END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER cache_slot_guard BEFORE INSERT OR UPDATE OR DELETE ON vulntrack_cve_cache.slots
    FOR EACH ROW EXECUTE FUNCTION vulntrack_cve_cache.guard_slot();

CREATE FUNCTION vulntrack_cve_cache.guard_response() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE s vulntrack_cve_cache.slots%ROWTYPE;
BEGIN
    IF TG_OP<>'INSERT' THEN
        RAISE EXCEPTION 'Cache evidence is immutable' USING ERRCODE='23514';
    END IF;
    SELECT * INTO s FROM vulntrack_cve_cache.slots WHERE id=NEW.slot_id FOR UPDATE NOWAIT;
    IF s.id IS NULL OR s.workspace_id IS DISTINCT FROM vulntrack.current_workspace_id()
        OR NOT vulntrack.has_workspace_role(s.workspace_id,ARRAY['owner','editor'])
        OR s.lease_token IS NULL OR s.lease_expires_at<=clock_timestamp()
        OR s.lease_token::text IS DISTINCT FROM current_setting('vulntrack.cache_lease',true)
        OR NEW.fetched_at>clock_timestamp() THEN
        RAISE EXCEPTION 'Cache publication requires active scoped lease' USING ERRCODE='23514';
    END IF;
    IF NOT pg_try_advisory_xact_lock(hashtextextended(s.workspace_id::text,55)) THEN
        RAISE EXCEPTION 'Cache coordinator busy' USING ERRCODE='55P03';
    END IF;
    IF (SELECT count(*) FROM vulntrack_cve_cache.responses r JOIN vulntrack_cve_cache.slots p
            ON p.id=r.slot_id WHERE p.workspace_id=s.workspace_id)>=500 OR
       (SELECT coalesce(sum(octet_length(r.body)),0) FROM vulntrack_cve_cache.responses r
            JOIN vulntrack_cve_cache.slots p ON p.id=r.slot_id WHERE p.workspace_id=s.workspace_id)
            +octet_length(NEW.body)>104857600 THEN
        RAISE EXCEPTION 'Cache evidence capacity limit' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER cache_response_guard BEFORE INSERT OR UPDATE OR DELETE ON vulntrack_cve_cache.responses
    FOR EACH ROW EXECUTE FUNCTION vulntrack_cve_cache.guard_response();

ALTER TABLE vulntrack.application_analysis_runs
    ADD COLUMN cache_response_id uuid REFERENCES vulntrack_cve_cache.responses(id) ON DELETE RESTRICT,
    ADD COLUMN cache_usage jsonb CHECK (cache_usage IS NULL OR
        (jsonb_typeof(cache_usage)='object' AND octet_length(cache_usage::text)<=1024));
ALTER TABLE vulntrack_devices.runs
    ADD COLUMN cache_response_id uuid REFERENCES vulntrack_cve_cache.responses(id) ON DELETE RESTRICT,
    ADD COLUMN cache_usage jsonb CHECK (cache_usage IS NULL OR
        (jsonb_typeof(cache_usage)='object' AND octet_length(cache_usage::text)<=1024));
GRANT UPDATE(cache_response_id,cache_usage) ON vulntrack.application_analysis_runs,
    vulntrack_devices.runs TO vulntrack_app;
CREATE INDEX app_run_cache_response_idx ON vulntrack.application_analysis_runs(cache_response_id)
    WHERE cache_response_id IS NOT NULL;
CREATE INDEX device_run_cache_response_idx ON vulntrack_devices.runs(cache_response_id)
    WHERE cache_response_id IS NOT NULL;

CREATE FUNCTION vulntrack_cve_cache.guard_run() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE evidence record; used timestamptz; resolution text;
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.cache_response_id IS NOT NULL OR NEW.cache_usage IS NOT NULL THEN
            RAISE EXCEPTION 'Cache association is a finalization fact' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    IF (OLD.cache_response_id IS NOT NULL OR OLD.cache_usage IS NOT NULL) AND
        ROW(NEW.cache_response_id,NEW.cache_usage) IS DISTINCT FROM
        ROW(OLD.cache_response_id,OLD.cache_usage) THEN
        RAISE EXCEPTION 'Immutable cache association' USING ERRCODE='23514';
    END IF;
    IF NEW.cache_usage IS NULL THEN
        IF NEW.cache_response_id IS NOT NULL THEN
            RAISE EXCEPTION 'Cache association requires usage' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    resolution:=NEW.cache_usage->>'resolution';
    IF NOT (NEW.cache_usage ?& ARRAY['resolution','refresh_attempted','used_at'])
       OR (NEW.cache_usage-ARRAY['resolution','refresh_attempted','used_at'])<>'{}'::jsonb
       OR coalesce(resolution,'') NOT IN ('provider','reused','failed')
       OR jsonb_typeof(NEW.cache_usage->'refresh_attempted') IS DISTINCT FROM 'boolean' THEN
        RAISE EXCEPTION 'Invalid cache usage' USING ERRCODE='23514';
    END IF;
    IF resolution='failed' THEN
        IF NEW.status<>'failed' OR NEW.cache_response_id IS NOT NULL OR
            NEW.cache_usage->'used_at'<>'null'::jsonb THEN
            RAISE EXCEPTION 'Invalid failed cache usage' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
    END IF;
    used:=(NEW.cache_usage->>'used_at')::timestamptz;
    SELECT p.workspace_id,p.source,p.query,r.fetched_at,r.expires_at,r.coverage INTO evidence
      FROM vulntrack_cve_cache.responses r JOIN vulntrack_cve_cache.slots p ON p.id=r.slot_id
      WHERE r.id=NEW.cache_response_id;
    IF NEW.status<>'completed' OR evidence.workspace_id IS DISTINCT FROM NEW.workspace_id
       OR evidence.source IS DISTINCT FROM NEW.run_context->>'cve_source'
       OR (evidence.query::jsonb)->'params'->>'cpeName' IS DISTINCT FROM NEW.selected_cpe
       OR NEW.response_received_at IS DISTINCT FROM evidence.fetched_at
       OR used IS NULL OR used<evidence.fetched_at OR used>clock_timestamp()
       OR (resolution='reused' AND (evidence.coverage<>'complete' OR used>=evidence.expires_at)) THEN
        RAISE EXCEPTION 'Cache evidence must match private query snapshot' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER cache_run_guard BEFORE INSERT OR UPDATE ON vulntrack.application_analysis_runs
    FOR EACH ROW EXECUTE FUNCTION vulntrack_cve_cache.guard_run();
CREATE TRIGGER cache_run_guard BEFORE INSERT OR UPDATE ON vulntrack_devices.runs
    FOR EACH ROW EXECUTE FUNCTION vulntrack_cve_cache.guard_run();
REVOKE ALL ON FUNCTION vulntrack_cve_cache.guard_slot(),vulntrack_cve_cache.guard_response(),
    vulntrack_cve_cache.guard_run() FROM PUBLIC,vulntrack_app;

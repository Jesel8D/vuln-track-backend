-- 5A: bounded recovery and immutable provenance on existing V2 runs. No cache tables.
ALTER TABLE vulntrack.application_analysis_runs
    ADD COLUMN run_context jsonb,
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN response_received_at timestamptz,
    ADD CONSTRAINT app_run_context_valid CHECK (run_context IS NULL OR
        (jsonb_typeof(run_context)='object' AND octet_length(run_context::text)<=8192));
ALTER TABLE vulntrack_devices.runs
    ADD COLUMN run_context jsonb,
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN response_received_at timestamptz,
    ADD CONSTRAINT device_run_context_valid CHECK (run_context IS NULL OR
        (jsonb_typeof(run_context)='object' AND octet_length(run_context::text)<=8192));
GRANT UPDATE(response_received_at) ON vulntrack.application_analysis_runs,
    vulntrack_devices.runs TO vulntrack_app;

CREATE FUNCTION vulntrack.guard_cve_reliability() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF (NEW.run_context IS NULL) <> (NEW.lease_expires_at IS NULL)
           OR NEW.response_received_at IS NOT NULL
           OR (NEW.run_context IS NOT NULL AND
               (NEW.run_context->>'contract' IS DISTINCT FROM 'v2-cve-5a-1'
                OR NOT (NEW.run_context ?& ARRAY['cve_source','identification_id','cpe_mode',
                    'cpe_source','observed_vendor','observed_product','observed_version'])
                OR coalesce(NEW.run_context->>'cve_source','')
                    NOT IN ('fixture','simulated','live','unknown')
                OR coalesce(jsonb_typeof(NEW.run_context->'observed_vendor'),'')
                    NOT IN ('string','null')
                OR coalesce(jsonb_typeof(NEW.run_context->'observed_product'),'')<>'string'
                OR coalesce(jsonb_typeof(NEW.run_context->'observed_version'),'')<>'string'
                OR NEW.lease_expires_at < clock_timestamp()+interval '10 seconds'
                OR NEW.lease_expires_at > clock_timestamp()+interval '5 minutes')) THEN
            RAISE EXCEPTION 'Invalid CVE execution context' USING ERRCODE='23514';
        END IF;
    ELSE
        IF NEW.run_context IS DISTINCT FROM OLD.run_context
           OR NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at
           OR (OLD.response_received_at IS NOT NULL AND
               NEW.response_received_at IS DISTINCT FROM OLD.response_received_at)
           OR (OLD.status IN ('completed','failed') AND NEW IS DISTINCT FROM OLD)
           OR (NEW.response_received_at IS DISTINCT FROM OLD.response_received_at AND
               (NEW.status<>'completed' OR NEW.response_received_at>clock_timestamp())) THEN
            RAISE EXCEPTION 'Immutable CVE execution context' USING ERRCODE='23514';
        END IF;
        IF NEW.status='completed' AND OLD.lease_expires_at<=clock_timestamp()
           AND NOT (NEW.coverage='partial' AND
               (NEW.warning_codes ? 'INTERRUPTED' OR
                   coalesce(NEW.failure_code='INTERRUPTED',false))) THEN
            RAISE EXCEPTION 'Expired CVE execution cannot finalize' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER cve_reliability_guard BEFORE INSERT OR UPDATE ON vulntrack.application_analysis_runs
    FOR EACH ROW EXECUTE FUNCTION vulntrack.guard_cve_reliability();
CREATE TRIGGER cve_reliability_guard BEFORE INSERT OR UPDATE ON vulntrack_devices.runs
    FOR EACH ROW EXECUTE FUNCTION vulntrack.guard_cve_reliability();
CREATE INDEX app_cve_expiry_idx ON vulntrack.application_analysis_runs(workspace_id,lease_expires_at,id)
    WHERE status IN ('queued','running');
CREATE INDEX device_cve_expiry_idx ON vulntrack_devices.runs(workspace_id,lease_expires_at,id)
    WHERE status='running';

-- Recovery is a technical transition, not viewer-controlled UPDATE. Context is verified
-- by existing signed-context functions; there are no caller-supplied IDs or SQL fragments.
CREATE FUNCTION vulntrack.recover_cve_runs() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE scope uuid := vulntrack.current_workspace_id();
BEGIN
    IF scope IS NULL OR NOT vulntrack.has_workspace_role(scope,ARRAY['owner','editor','viewer']) THEN
        RAISE EXCEPTION 'Workspace context required' USING ERRCODE='42501';
    END IF;
    WITH expired AS (
        SELECT id FROM vulntrack.application_analysis_runs
        WHERE workspace_id=scope AND kind='nvd_cve' AND status IN ('queued','running')
          AND coalesce(lease_expires_at,created_at+interval '2 minutes')<=clock_timestamp()
        ORDER BY coalesce(lease_expires_at,created_at+interval '2 minutes'),id
        LIMIT 100 FOR UPDATE SKIP LOCKED
    ) UPDATE vulntrack.application_analysis_runs r
      SET status=CASE WHEN r.page_count>0 THEN 'completed' ELSE 'failed' END,
          coverage=CASE WHEN r.page_count>0 THEN 'partial' ELSE NULL END,
          failure_code=CASE WHEN r.page_count>0 AND
              (jsonb_array_length(r.warning_codes)<20 OR r.warning_codes ? 'INTERRUPTED')
              THEN NULL ELSE 'INTERRUPTED' END,
          warning_codes=CASE WHEN r.page_count>0 AND NOT r.warning_codes ? 'INTERRUPTED'
              AND jsonb_array_length(r.warning_codes)<20
              THEN r.warning_codes||'["INTERRUPTED"]'::jsonb ELSE r.warning_codes END,
          completed_at=clock_timestamp()
      FROM expired e WHERE r.id=e.id AND r.workspace_id=scope;
    WITH expired AS (
        SELECT id FROM vulntrack_devices.runs WHERE workspace_id=scope AND status='running'
          AND coalesce(lease_expires_at,created_at+interval '2 minutes')<=clock_timestamp()
        ORDER BY coalesce(lease_expires_at,created_at+interval '2 minutes'),id
        LIMIT 100 FOR UPDATE SKIP LOCKED
    ) UPDATE vulntrack_devices.runs r
      SET status=CASE WHEN r.retrieved_count>0 THEN 'completed' ELSE 'failed' END,
          coverage=CASE WHEN r.retrieved_count>0 THEN 'partial' ELSE NULL END,
          failure_code=CASE WHEN r.retrieved_count>0 THEN NULL ELSE 'INTERRUPTED' END,
          warning_codes=CASE WHEN r.retrieved_count>0 AND NOT r.warning_codes ? 'INTERRUPTED'
              THEN r.warning_codes||'["INTERRUPTED"]'::jsonb ELSE r.warning_codes END,
          completed_at=clock_timestamp()
      FROM expired e WHERE r.id=e.id AND r.workspace_id=scope;
END $$;
REVOKE ALL ON FUNCTION vulntrack.guard_cve_reliability() FROM PUBLIC;
REVOKE ALL ON FUNCTION vulntrack.recover_cve_runs() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION vulntrack.recover_cve_runs() TO vulntrack_app;

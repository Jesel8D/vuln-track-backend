-- MVP-B additive schema. Apply only after verified MVP-A, in one maintenance transaction.
-- No legacy data is rewritten. Duplicate CVE/active-run conflicts abort the transaction.
ALTER TABLE vulntrack.analysis_runs
 ADD COLUMN identification_id uuid,
 ADD COLUMN observed_version text,
 ADD COLUMN idempotency_key uuid,
 ADD COLUMN request_hash text,
 ADD COLUMN total_results integer,
 ADD COLUMN retrieved_count integer NOT NULL DEFAULT 0,
 ADD COLUMN stored_count integer NOT NULL DEFAULT 0,
 ADD COLUMN page_count integer NOT NULL DEFAULT 0,
 ADD COLUMN next_index integer NOT NULL DEFAULT 0,
 ADD COLUMN retry_count integer NOT NULL DEFAULT 0,
 ADD COLUMN query_parameters jsonb NOT NULL DEFAULT '{}'::jsonb,
 ADD COLUMN warning_codes jsonb NOT NULL DEFAULT '[]'::jsonb,
 ADD COLUMN source_timestamps jsonb NOT NULL DEFAULT '[]'::jsonb,
 ADD COLUMN page_manifest jsonb NOT NULL DEFAULT '[]'::jsonb,
 ADD COLUMN failure_code text,
 ADD COLUMN nvd_cooldown_until timestamptz,
 ADD CONSTRAINT analysis_identification_fk FOREIGN KEY(asset_id, identification_id)
   REFERENCES vulntrack.asset_cpe_identifications(asset_id,id) ON DELETE RESTRICT,
 ADD CONSTRAINT analysis_idempotency_unique UNIQUE(asset_id,initiated_by,idempotency_key),
 ADD CONSTRAINT analysis_identity_valid CHECK (
  (identification_id IS NULL AND observed_version IS NULL AND idempotency_key IS NULL AND request_hash IS NULL)
  OR (identification_id IS NOT NULL AND observed_version IS NOT NULL
      AND vulntrack.valid_text(observed_version,120) AND idempotency_key IS NOT NULL
      AND request_hash IS NOT NULL AND request_hash ~ '^[0-9a-f]{64}$')),
 ADD CONSTRAINT analysis_counts_valid CHECK (
   total_results >= 0 AND retrieved_count >= 0 AND stored_count >= 0
   AND stored_count <= retrieved_count AND page_count BETWEEN 0 AND 5
   AND next_index >= 0 AND retry_count BETWEEN 0 AND 10),
 ADD CONSTRAINT analysis_metadata_valid CHECK (
   jsonb_typeof(query_parameters)='object' AND octet_length(query_parameters::text)<=4096
   AND jsonb_typeof(warning_codes)='array' AND jsonb_array_length(warning_codes)<=20
   AND jsonb_typeof(source_timestamps)='array' AND jsonb_array_length(source_timestamps)<=5
   AND jsonb_typeof(page_manifest)='array' AND jsonb_array_length(page_manifest)<=5
   AND octet_length(page_manifest::text)<=8192),
 ADD CONSTRAINT analysis_failure_valid CHECK (
   failure_code IS NULL OR failure_code ~ '^[A-Z][A-Z0-9_]{0,79}$'),
 ADD CONSTRAINT analysis_outcome_valid CHECK (identification_id IS NULL OR (
   (status IN ('queued','running') AND coverage IS NULL AND failure_code IS NULL)
   OR (status='completed' AND page_count>0 AND coverage IS NOT NULL
       AND (coverage='partial' OR (failure_code IS NULL AND jsonb_array_length(warning_codes)=0
            AND next_index=total_results AND stored_count=total_results)))
   OR (status='failed' AND coverage IS NULL AND page_count=0 AND failure_code IS NOT NULL)));
CREATE UNIQUE INDEX analysis_active_unique ON vulntrack.analysis_runs(asset_id)
 WHERE status IN ('queued','running');
CREATE INDEX analysis_created_idx ON vulntrack.analysis_runs(asset_id,created_at,id);
CREATE INDEX analysis_queue_idx ON vulntrack.analysis_runs(created_at,id) WHERE status='queued';
ALTER TABLE vulntrack.findings
 DROP CONSTRAINT findings_applicability_v1,
 ADD COLUMN evidence jsonb,
 ADD COLUMN reviewed_by uuid REFERENCES vulntrack.users(id) ON DELETE RESTRICT,
 ADD COLUMN reviewed_at timestamptz,
 ADD COLUMN review_reason text,
 ADD COLUMN review_evidence text,
 ADD CONSTRAINT findings_applicability_valid CHECK (
   applicability IN ('potential','undetermined','not_applicable')),
 ADD CONSTRAINT findings_evidence_valid CHECK (evidence IS NULL OR (
   jsonb_typeof(evidence)='object' AND octet_length(evidence::text)<=65536
   AND evidence->>'initial_applicability' IS NOT NULL
   AND evidence->>'initial_applicability' IN ('potential','undetermined'))),
 ADD CONSTRAINT findings_review_valid CHECK (
   (reviewed_by IS NULL AND reviewed_at IS NULL AND review_reason IS NULL AND review_evidence IS NULL
       AND (evidence IS NULL OR status='open')) OR
   (evidence IS NOT NULL AND status='reviewed' AND reviewed_by IS NOT NULL
      AND reviewed_at IS NOT NULL AND reviewed_at>=observed_at
      AND review_reason IS NOT NULL AND vulntrack.valid_text(review_reason,500)
      AND review_evidence IS NOT NULL AND vulntrack.valid_text(review_evidence,2000))),
 ADD CONSTRAINT findings_cve_unique UNIQUE(analysis_id,source,external_id);

CREATE FUNCTION vulntrack.guard_analysis_run() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ident vulntrack.asset_cpe_identifications; owner_id uuid;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Analysis history is immutable' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  -- Historical rows are only installed before this guard, never inferred from a CPE string.
  IF NEW.identification_id IS NULL OR NEW.status<>'queued' OR NEW.page_count<>0
     OR NEW.retrieved_count<>0 OR NEW.stored_count<>0 OR NEW.next_index<>0 THEN
   RAISE EXCEPTION 'New analysis requires a queued identification snapshot' USING ERRCODE='23514';
  END IF;
  SELECT created_by INTO owner_id FROM vulntrack.assets WHERE id=NEW.asset_id FOR UPDATE;
  SELECT * INTO ident FROM vulntrack.asset_cpe_identifications WHERE id=NEW.identification_id;
  IF owner_id IS DISTINCT FROM NEW.initiated_by OR ident.asset_id IS DISTINCT FROM NEW.asset_id
    OR ident.state IS DISTINCT FROM 'confirmed' OR ident.valid_to IS NOT NULL
    OR ident.cpe_name IS DISTINCT FROM NEW.selected_cpe
    OR ident.observed_version IS DISTINCT FROM NEW.observed_version THEN
   RAISE EXCEPTION 'Invalid analysis identity or owner' USING ERRCODE='23514';
  END IF;
 ELSE
  IF OLD.identification_id IS NULL THEN
   RAISE EXCEPTION 'Legacy analysis cannot be reinterpreted' USING ERRCODE='23514';
  END IF;
  IF ROW(NEW.id,NEW.kind,NEW.asset_id,NEW.initiated_by,NEW.selected_cpe,NEW.identification_id,
      NEW.observed_version,NEW.idempotency_key,NEW.request_hash,NEW.created_at,NEW.query_parameters)
    IS DISTINCT FROM ROW(OLD.id,OLD.kind,OLD.asset_id,OLD.initiated_by,OLD.selected_cpe,
      OLD.identification_id,OLD.observed_version,OLD.idempotency_key,OLD.request_hash,
      OLD.created_at,OLD.query_parameters) OR OLD.status IN ('completed','failed') THEN
   RAISE EXCEPTION 'Analysis snapshot is immutable' USING ERRCODE='23514';
  END IF;
  IF NOT ((OLD.status='queued' AND NEW.status='running') OR
       (OLD.status='running' AND NEW.status IN ('running','completed','failed')))
    OR NEW.retrieved_count<OLD.retrieved_count OR NEW.stored_count<OLD.stored_count
    OR NEW.page_count<OLD.page_count OR NEW.next_index<OLD.next_index
    OR NEW.retry_count<OLD.retry_count
    OR (OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at) THEN
   RAISE EXCEPTION 'Invalid analysis transition' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER analysis_guard BEFORE INSERT OR UPDATE OR DELETE ON vulntrack.analysis_runs
 FOR EACH ROW EXECUTE FUNCTION vulntrack.guard_analysis_run();

CREATE FUNCTION vulntrack.guard_finding() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE run vulntrack.analysis_runs; owner_id uuid;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Finding history is immutable' USING ERRCODE='23514'; END IF;
 SELECT * INTO run FROM vulntrack.analysis_runs WHERE id=NEW.analysis_id FOR UPDATE;
 IF TG_OP='INSERT' THEN
  IF run.identification_id IS NULL OR run.status<>'running' OR NEW.evidence IS NULL
    OR NEW.status<>'open' OR NEW.applicability IS DISTINCT FROM NEW.evidence->>'initial_applicability'
    OR NEW.applicability NOT IN ('potential','undetermined') THEN
   RAISE EXCEPTION 'Invalid finding ingestion' USING ERRCODE='23514';
  END IF;
 ELSE
  IF OLD.evidence IS NULL OR OLD.status<>'open' OR NEW.status<>'reviewed'
   OR run.status NOT IN ('completed','failed') OR
   (to_jsonb(NEW)-ARRAY['status','applicability','reviewed_by','reviewed_at','review_reason',
      'review_evidence','updated_at']) IS DISTINCT FROM
   (to_jsonb(OLD)-ARRAY['status','applicability','reviewed_by','reviewed_at','review_reason',
      'review_evidence','updated_at']) THEN
   RAISE EXCEPTION 'Only one evidence-preserving review is allowed' USING ERRCODE='23514';
  END IF;
  SELECT created_by INTO owner_id FROM vulntrack.assets WHERE id=run.asset_id;
  IF NEW.reviewed_by IS NULL OR owner_id IS DISTINCT FROM NEW.reviewed_by THEN
   RAISE EXCEPTION 'Reviewer must own asset' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER finding_guard BEFORE INSERT OR UPDATE OR DELETE ON vulntrack.findings
 FOR EACH ROW EXECUTE FUNCTION vulntrack.guard_finding();
REVOKE ALL ON FUNCTION vulntrack.guard_analysis_run(), vulntrack.guard_finding() FROM PUBLIC;
GRANT UPDATE (total_results,retrieved_count,stored_count,page_count,next_index,retry_count,
 warning_codes,source_timestamps,page_manifest,failure_code,nvd_cooldown_until) ON vulntrack.analysis_runs TO vulntrack_app;
GRANT UPDATE (applicability,reviewed_by,reviewed_at,review_reason,review_evidence)
 ON vulntrack.findings TO vulntrack_app;

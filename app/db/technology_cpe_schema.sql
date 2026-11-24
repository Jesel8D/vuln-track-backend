-- New confirmations only. Never infer provenance for pre-existing selections.
CREATE SCHEMA vulntrack_technology_cpe;
REVOKE ALL ON SCHEMA vulntrack_technology_cpe FROM PUBLIC;
GRANT USAGE ON SCHEMA vulntrack_technology_cpe TO vulntrack_app;

CREATE TABLE vulntrack_technology_cpe.confirmations (
    id uuid PRIMARY KEY,
    event_number bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    workspace_id uuid NOT NULL,
    application_id uuid NOT NULL,
    technology_id uuid NOT NULL,
    recorded_by uuid NOT NULL,
    confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    cpe_name_id uuid NOT NULL,
    cpe_name text NOT NULL CHECK (vulntrack.valid_text(cpe_name,1024)),
    mode text NOT NULL CHECK (mode IN ('live','fixture')),
    source text NOT NULL CHECK (source IN ('nvd-api','nvd-feed','nvd-captured-fixture')),
    observed_vendor text,
    observed_product text NOT NULL,
    observed_version text NOT NULL,
    reason text CHECK (reason IS NULL OR vulntrack.valid_text(reason,500)),
    evidence text CHECK (evidence IS NULL OR vulntrack.valid_text(evidence,2000)),
    catalog_evidence jsonb NOT NULL CHECK (jsonb_typeof(catalog_evidence)='object'),
    FOREIGN KEY (workspace_id,application_id,technology_id)
        REFERENCES vulntrack.technologies(workspace_id,application_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,recorded_by)
        REFERENCES vulntrack.workspace_members(workspace_id,user_id) ON DELETE RESTRICT,
    CHECK ((mode='fixture') = (source='nvd-captured-fixture'))
);
CREATE INDEX technology_cpe_history_idx ON vulntrack_technology_cpe.confirmations
    (workspace_id,application_id,technology_id,event_number DESC);
ALTER TABLE vulntrack_technology_cpe.confirmations ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulntrack_technology_cpe.confirmations FORCE ROW LEVEL SECURITY;
CREATE POLICY confirmations_read ON vulntrack_technology_cpe.confirmations FOR SELECT
    USING (workspace_id=vulntrack.current_workspace_id()
        AND vulntrack.has_workspace_role(workspace_id,ARRAY['owner','editor','viewer']));
CREATE POLICY confirmations_insert ON vulntrack_technology_cpe.confirmations FOR INSERT
    WITH CHECK (workspace_id=vulntrack.current_workspace_id()
        AND recorded_by=vulntrack.current_user_id()
        AND vulntrack.has_workspace_role(workspace_id,ARRAY['owner','editor']));

CREATE FUNCTION vulntrack_technology_cpe.guard_confirmation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'CPE confirmation history is immutable' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM vulntrack.technologies t
        WHERE t.workspace_id=NEW.workspace_id AND t.application_id=NEW.application_id
          AND t.id=NEW.technology_id AND t.selected_cpe=NEW.cpe_name
          AND t.confidence='user_confirmed'
          AND t.vendor IS NOT DISTINCT FROM NEW.observed_vendor
          AND t.product=NEW.observed_product AND t.version=NEW.observed_version) THEN
        RAISE EXCEPTION 'Confirmation must match current technology' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION vulntrack_technology_cpe.guard_confirmation() FROM PUBLIC;
CREATE TRIGGER confirmation_guard BEFORE INSERT OR UPDATE OR DELETE
    ON vulntrack_technology_cpe.confirmations FOR EACH ROW
    EXECUTE FUNCTION vulntrack_technology_cpe.guard_confirmation();
GRANT SELECT,INSERT ON vulntrack_technology_cpe.confirmations TO vulntrack_app;
GRANT USAGE,SELECT ON SEQUENCE vulntrack_technology_cpe.confirmations_event_number_seq
    TO vulntrack_app;

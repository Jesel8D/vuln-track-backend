CREATE FUNCTION vulntrack.guard_cpe_event()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prior vulntrack.asset_cpe_identifications; owner_id uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'CPE history is immutable' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF (to_jsonb(NEW) - 'valid_to') IS DISTINCT FROM (to_jsonb(OLD) - 'valid_to')
           OR OLD.valid_to IS NOT NULL OR NEW.valid_to IS NULL THEN
            RAISE EXCEPTION 'Only current event closure is allowed' USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    SELECT created_by INTO owner_id FROM vulntrack.assets WHERE id = NEW.asset_id FOR UPDATE;
    IF owner_id IS NULL OR owner_id IS DISTINCT FROM NEW.recorded_by THEN
        RAISE EXCEPTION 'Event actor must own asset' USING ERRCODE = '23514';
    END IF;
    IF NEW.valid_to IS NOT NULL THEN
        RAISE EXCEPTION 'New event must be current' USING ERRCODE = '23514';
    END IF;
    IF NEW.replaces_id IS NULL THEN
        IF NEW.state <> 'confirmed' OR EXISTS (
            SELECT 1 FROM vulntrack.asset_cpe_identifications WHERE asset_id = NEW.asset_id
        ) THEN
            RAISE EXCEPTION 'Invalid first event' USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT * INTO prior FROM vulntrack.asset_cpe_identifications
        WHERE asset_id = NEW.asset_id AND id = NEW.replaces_id;
        IF prior.id IS NULL OR prior.valid_to IS DISTINCT FROM NEW.recorded_at THEN
            RAISE EXCEPTION 'Predecessor must close at new event time' USING ERRCODE = '23514';
        END IF;
        IF NEW.state = 'needs_review' AND (
            prior.state <> 'confirmed' OR
            ROW(NEW.cpe_name, NEW.cpe_name_id, NEW.component_kind, NEW.observed_version,
                NEW.source, NEW.validated_at) IS DISTINCT FROM
            ROW(prior.cpe_name, prior.cpe_name_id, prior.component_kind, prior.observed_version,
                prior.source, prior.validated_at)
        ) THEN
            RAISE EXCEPTION 'Invalid review snapshot' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER cpe_event_guard BEFORE INSERT OR UPDATE OR DELETE
ON vulntrack.asset_cpe_identifications FOR EACH ROW EXECUTE FUNCTION vulntrack.guard_cpe_event();

CREATE FUNCTION vulntrack.check_cpe_chain()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT count(*) FROM vulntrack.asset_cpe_identifications
        WHERE asset_id = NEW.asset_id AND valid_to IS NULL) <> 1
       OR EXISTS (
        SELECT 1 FROM vulntrack.asset_cpe_identifications e
        WHERE e.asset_id = NEW.asset_id AND e.valid_to IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM vulntrack.asset_cpe_identifications n
            WHERE n.asset_id = e.asset_id AND n.replaces_id = e.id AND n.recorded_at = e.valid_to
        )
    ) THEN
        RAISE EXCEPTION 'Incomplete CPE history chain' USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER cpe_chain_complete AFTER INSERT OR UPDATE
ON vulntrack.asset_cpe_identifications DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION vulntrack.check_cpe_chain();
REVOKE ALL ON FUNCTION vulntrack.guard_cpe_event() FROM PUBLIC;
REVOKE ALL ON FUNCTION vulntrack.check_cpe_chain() FROM PUBLIC;
GRANT SELECT, INSERT ON vulntrack.asset_cpe_identifications TO vulntrack_app;
GRANT UPDATE(valid_to) ON vulntrack.asset_cpe_identifications TO vulntrack_app;
-- SELECT FOR UPDATE requires UPDATE on at least one column; assets_touch forbids changing id.
GRANT UPDATE(id) ON vulntrack.assets TO vulntrack_app;

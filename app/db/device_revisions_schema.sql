-- RC3, additive record revisions. Legacy devices and their evidence start at generation 1.
ALTER TABLE vulntrack_devices.devices
    ADD COLUMN record_version bigint NOT NULL DEFAULT 1 CHECK (record_version > 0),
    ADD COLUMN identity_generation bigint NOT NULL DEFAULT 1
        CHECK (identity_generation BETWEEN 1 AND record_version);
ALTER TABLE vulntrack_devices.identifications
    ADD COLUMN identity_generation bigint NOT NULL DEFAULT 1 CHECK (identity_generation > 0);
ALTER TABLE vulntrack_devices.runs
    ADD COLUMN evaluated_technology jsonb
        CHECK (evaluated_technology IS NULL OR jsonb_typeof(evaluated_technology) = 'object');

CREATE INDEX device_generation_cpe_idx ON vulntrack_devices.identifications
    (workspace_id, device_id, identity_generation, created_at DESC, id DESC);

CREATE TABLE vulntrack_devices.revisions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid NOT NULL,
    device_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    previous_version bigint NOT NULL CHECK (previous_version > 0),
    new_version bigint NOT NULL CHECK (new_version = previous_version + 1),
    changed_fields text[] NOT NULL CHECK (cardinality(changed_fields) > 0),
    change_kind text NOT NULL CHECK (change_kind IN ('administrative', 'physical', 'technological')),
    reason text NOT NULL CHECK (vulntrack.valid_text(reason, 500)),
    previous_values jsonb NOT NULL CHECK (jsonb_typeof(previous_values) = 'object'),
    new_values jsonb NOT NULL CHECK (jsonb_typeof(new_values) = 'object'),
    related_identification_id uuid,
    cpe_review_state text NOT NULL CHECK (cpe_review_state IN ('pending','confirmed','needs_review')),
    FOREIGN KEY (workspace_id, device_id) REFERENCES vulntrack_devices.devices(workspace_id, id),
    FOREIGN KEY (workspace_id, actor_id)
        REFERENCES vulntrack.workspace_members(workspace_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id, device_id, related_identification_id)
        REFERENCES vulntrack_devices.identifications(workspace_id, device_id, id),
    UNIQUE (workspace_id, device_id, new_version)
);

ALTER TABLE vulntrack_devices.revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulntrack_devices.revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY scoped_read ON vulntrack_devices.revisions FOR SELECT
    USING (workspace_id = vulntrack.current_workspace_id() AND
           vulntrack.has_workspace_role(workspace_id, ARRAY['owner','editor','viewer']));
GRANT SELECT ON vulntrack_devices.revisions TO vulntrack_app;
GRANT UPDATE (device_type, manufacturer, model, site_label, inventory_label, notes,
              component_kind, product_vendor, product, version)
    ON vulntrack_devices.devices TO vulntrack_app;

CREATE FUNCTION vulntrack_devices.revision_values(d vulntrack_devices.devices)
RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
    SELECT jsonb_build_object(
        'device_type', d.device_type, 'manufacturer', d.manufacturer, 'model', d.model,
        'site_label', d.site_label, 'inventory_label', d.inventory_label, 'status', d.status,
        'component_kind', d.component_kind, 'product_vendor', d.product_vendor,
        'product', d.product, 'version', d.version)
$$;

CREATE FUNCTION vulntrack_devices.capture_revision() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    actor uuid := vulntrack.current_user_id();
    prior jsonb := vulntrack_devices.revision_values(OLD);
    next_values jsonb := vulntrack_devices.revision_values(NEW);
    fields text[];
    kind text := 'administrative';
    review text;
    rationale text := nullif(current_setting('vulntrack.device_edit_reason', true), '');
    identification uuid;
    revision uuid;
BEGIN
    SELECT coalesce(array_agg(key ORDER BY key), '{}'::text[]) INTO fields
      FROM jsonb_object_keys(prior) AS keys(key)
     WHERE prior->key IS DISTINCT FROM next_values->key;
    IF OLD.notes IS DISTINCT FROM NEW.notes THEN
        fields := array_append(fields, 'notes');
    END IF;
    IF cardinality(fields) = 0 THEN
        RETURN NEW;
    END IF;
    IF actor IS NULL OR vulntrack.current_workspace_id() IS DISTINCT FROM OLD.workspace_id OR
       NOT coalesce(vulntrack.has_workspace_role(OLD.workspace_id, ARRAY['owner','editor']), false) THEN
        RAISE EXCEPTION 'Device revision requires a scoped writer' USING ERRCODE = '42501';
    END IF;
    IF rationale IS NULL OR NOT vulntrack.valid_text(rationale, 500) THEN
        RAISE EXCEPTION 'Device revision requires a reason' USING ERRCODE = '23514';
    END IF;
    NEW.record_version := OLD.record_version + 1;
    NEW.identity_generation := OLD.identity_generation;
    NEW.updated_at := clock_timestamp();
    SELECT id INTO identification FROM vulntrack_devices.identifications
      WHERE workspace_id = OLD.workspace_id AND device_id = OLD.id
        AND identity_generation = OLD.identity_generation
      ORDER BY created_at DESC, id DESC LIMIT 1;

    IF fields && ARRAY['component_kind','product_vendor','product','version'] THEN
        kind := 'technological';
        NEW.identity_generation := OLD.identity_generation + 1;
    ELSIF fields && ARRAY['device_type','manufacturer','model'] THEN
        kind := 'physical';
    END IF;
    review := CASE WHEN kind <> 'technological' AND identification IS NOT NULL THEN 'confirmed'
                   WHEN NEW.identity_generation > 1 THEN 'needs_review' ELSE 'pending' END;
    INSERT INTO vulntrack_devices.revisions
        (workspace_id, device_id, actor_id, previous_version, new_version, changed_fields,
         change_kind, reason, previous_values, new_values, related_identification_id, cpe_review_state)
    VALUES (OLD.workspace_id, OLD.id, actor, OLD.record_version, NEW.record_version, fields,
            kind, rationale, prior, next_values, identification, review)
    RETURNING id INTO revision;
    INSERT INTO vulntrack.audit_events(workspace_id, actor_id, action, object_type, object_id)
    VALUES (OLD.workspace_id, actor, 'device.revised', 'device_revision', revision);
    RETURN NEW;
END $$;

CREATE FUNCTION vulntrack_devices.bind_identity_generation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    SELECT d.identity_generation INTO NEW.identity_generation FROM vulntrack_devices.devices d
      WHERE d.workspace_id = NEW.workspace_id AND d.id = NEW.device_id FOR SHARE;
    RETURN NEW;
END $$;

CREATE FUNCTION vulntrack_devices.capture_run_technology() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    d vulntrack_devices.devices%ROWTYPE;
    i vulntrack_devices.identifications%ROWTYPE;
BEGIN
    SELECT * INTO d FROM vulntrack_devices.devices
      WHERE workspace_id = NEW.workspace_id AND id = NEW.device_id FOR SHARE;
    SELECT * INTO i FROM vulntrack_devices.identifications
      WHERE workspace_id = NEW.workspace_id AND device_id = NEW.device_id
        AND identity_generation = d.identity_generation
      ORDER BY created_at DESC, id DESC LIMIT 1;
    IF d.status IS DISTINCT FROM 'active' OR d.version IS NULL OR i.id IS NULL OR
       ROW(NEW.identification_id, NEW.selected_cpe, NEW.mode, NEW.observed_version)
       IS DISTINCT FROM ROW(i.id, i.cpe_name, i.mode, d.version) THEN
        RAISE EXCEPTION 'Device analysis requires current identification' USING ERRCODE = '23514';
    END IF;
    NEW.evaluated_technology := jsonb_build_object(
        'component_kind', d.component_kind, 'product_vendor', d.product_vendor,
        'product', d.product, 'observed_version', d.version, 'record_version', d.record_version,
        'identity_generation', d.identity_generation, 'basis', 'observed');
    RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION vulntrack_devices.revision_values(vulntrack_devices.devices),
    vulntrack_devices.capture_revision(), vulntrack_devices.bind_identity_generation(),
    vulntrack_devices.capture_run_technology() FROM PUBLIC, vulntrack_app;

CREATE TRIGGER device_revision_before_update
BEFORE UPDATE OF device_type,manufacturer,model,site_label,inventory_label,notes,status,
    component_kind,product_vendor,product,version ON vulntrack_devices.devices
FOR EACH ROW EXECUTE FUNCTION vulntrack_devices.capture_revision();
CREATE TRIGGER device_identification_generation_before_insert
BEFORE INSERT ON vulntrack_devices.identifications
FOR EACH ROW EXECUTE FUNCTION vulntrack_devices.bind_identity_generation();
CREATE TRIGGER device_run_technology_before_insert
BEFORE INSERT ON vulntrack_devices.runs
FOR EACH ROW EXECUTE FUNCTION vulntrack_devices.capture_run_technology();

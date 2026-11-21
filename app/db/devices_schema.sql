-- Additive RC2 extension. Execute after SQL008 inside a maintenance transaction.
CREATE SCHEMA vulntrack_devices;
REVOKE ALL ON SCHEMA vulntrack_devices FROM PUBLIC;
GRANT USAGE ON SCHEMA vulntrack_devices TO vulntrack_app;

CREATE TABLE vulntrack_devices.devices (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL REFERENCES vulntrack.workspaces(id),
    created_by uuid NOT NULL REFERENCES vulntrack.users(id),
    device_type text NOT NULL CHECK (device_type IN ('router', 'switch', 'server')),
    manufacturer text NOT NULL CHECK (vulntrack.valid_text(manufacturer, 120)),
    model text NOT NULL CHECK (vulntrack.valid_text(model, 120)),
    product_vendor text NOT NULL CHECK (vulntrack.valid_text(product_vendor, 120)),
    product text NOT NULL CHECK (vulntrack.valid_text(product, 160)),
    component_kind text NOT NULL CHECK (component_kind IN ('firmware','os','software','hardware')),
    version text CHECK (version IS NULL OR (
        vulntrack.valid_text(version, 120) AND lower(version) NOT IN ('unknown','*','-')
    )),
    site_label text NOT NULL CHECK (vulntrack.valid_text(site_label, 120)),
    inventory_label text CHECK (inventory_label IS NULL OR vulntrack.valid_text(inventory_label, 120)),
    notes text CHECK (notes IS NULL OR vulntrack.valid_text(notes, 1000)),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired')),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (workspace_id, id)
);
CREATE INDEX device_inventory_idx
    ON vulntrack_devices.devices (workspace_id, device_type, created_at DESC, id);

CREATE TABLE vulntrack_devices.identifications (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    device_id uuid NOT NULL,
    recorded_by uuid NOT NULL REFERENCES vulntrack.users(id),
    cpe_name text NOT NULL CHECK (vulntrack.valid_text(cpe_name, 1024) AND left(cpe_name, 8)='cpe:2.3:'),
    cpe_name_id uuid NOT NULL,
    mode text NOT NULL CHECK (mode IN ('fixture','live','unknown')),
    reason text NOT NULL CHECK (vulntrack.valid_text(reason, 500)),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    FOREIGN KEY (workspace_id, device_id) REFERENCES vulntrack_devices.devices(workspace_id, id),
    UNIQUE (workspace_id, device_id, id)
);
CREATE INDEX device_cpe_history_idx
    ON vulntrack_devices.identifications (workspace_id, device_id, created_at DESC, id DESC);

CREATE TABLE vulntrack_devices.runs (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    device_id uuid NOT NULL,
    identification_id uuid NOT NULL,
    initiated_by uuid NOT NULL REFERENCES vulntrack.users(id),
    request_key uuid NOT NULL,
    selected_cpe text NOT NULL,
    observed_version text NOT NULL,
    mode text NOT NULL CHECK (mode IN ('fixture','live','unknown')),
    source text NOT NULL DEFAULT 'nvd' CHECK (source='nvd'),
    status text NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','failed')),
    coverage text CHECK (coverage IN ('complete','partial')),
    total_results integer CHECK (total_results >= 0),
    retrieved_count integer NOT NULL DEFAULT 0 CHECK (retrieved_count >= 0),
    stored_count integer NOT NULL DEFAULT 0 CHECK (stored_count BETWEEN 0 AND retrieved_count),
    warning_codes jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(warning_codes)='array'),
    failure_code text,
    source_timestamp timestamptz,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    completed_at timestamptz,
    FOREIGN KEY (workspace_id, device_id, identification_id)
        REFERENCES vulntrack_devices.identifications(workspace_id, device_id, id),
    UNIQUE (workspace_id, device_id, id),
    UNIQUE (workspace_id, device_id, initiated_by, request_key),
    CHECK (
        (status='running' AND completed_at IS NULL AND coverage IS NULL AND failure_code IS NULL) OR
        (status='completed' AND completed_at IS NOT NULL AND coverage IS NOT NULL AND failure_code IS NULL) OR
        (status='failed' AND completed_at IS NOT NULL AND coverage IS NULL AND failure_code IS NOT NULL)
    )
);
CREATE UNIQUE INDEX device_one_running_idx
    ON vulntrack_devices.runs (workspace_id, device_id) WHERE status='running';
CREATE INDEX device_run_history_idx
    ON vulntrack_devices.runs (workspace_id, device_id, created_at DESC, id DESC);

CREATE TABLE vulntrack_devices.findings (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    device_id uuid NOT NULL,
    analysis_id uuid NOT NULL,
    external_id text NOT NULL CHECK (external_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    title text,
    severity text NOT NULL CHECK (severity IN ('critical','high','medium','low','none','unknown')),
    cvss jsonb CHECK (cvss IS NULL OR jsonb_typeof(cvss)='object'),
    evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence)='object' AND octet_length(evidence::text)<=65536),
    applicability text NOT NULL CHECK (applicability IN ('potential','undetermined','not_applicable')),
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','reviewed')),
    published_at timestamptz NOT NULL,
    last_modified_at timestamptz NOT NULL,
    reviewed_by uuid REFERENCES vulntrack.users(id),
    review_reason text CHECK (review_reason IS NULL OR vulntrack.valid_text(review_reason, 500)),
    review_evidence text CHECK (review_evidence IS NULL OR vulntrack.valid_text(review_evidence, 2000)),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    FOREIGN KEY (workspace_id, device_id, analysis_id)
        REFERENCES vulntrack_devices.runs(workspace_id, device_id, id),
    UNIQUE (workspace_id, device_id, id),
    UNIQUE (analysis_id, external_id),
    CHECK ((status='reviewed') = (reviewed_by IS NOT NULL AND review_reason IS NOT NULL AND review_evidence IS NOT NULL))
);
CREATE INDEX device_findings_run_idx
    ON vulntrack_devices.findings (workspace_id, device_id, analysis_id, id);

CREATE TABLE vulntrack_devices.recommendations (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    device_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    created_by uuid NOT NULL REFERENCES vulntrack.users(id),
    request_key uuid NOT NULL,
    recommendation text NOT NULL CHECK (vulntrack.valid_text(recommendation, 4000)),
    status text NOT NULL DEFAULT 'pending' CHECK (status='pending'),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    FOREIGN KEY (workspace_id, device_id, finding_id)
        REFERENCES vulntrack_devices.findings(workspace_id, device_id, id),
    UNIQUE (workspace_id, finding_id, id),
    UNIQUE (workspace_id, finding_id, created_by, request_key)
);
CREATE INDEX device_recommendation_idx
    ON vulntrack_devices.recommendations (workspace_id, device_id, finding_id, created_at DESC, id DESC);

DO $$
DECLARE item record;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('devices', 'created_by = vulntrack.current_user_id()'),
        ('identifications', 'recorded_by = vulntrack.current_user_id()'),
        ('runs', 'initiated_by = vulntrack.current_user_id()'),
        ('findings', 'status = ''open'' AND applicability IN (''potential'',''undetermined'')'),
        ('recommendations', 'created_by = vulntrack.current_user_id()')
    ) AS definitions(table_name, check_actor)
    LOOP
        EXECUTE format('ALTER TABLE vulntrack_devices.%I ENABLE ROW LEVEL SECURITY', item.table_name);
        EXECUTE format('ALTER TABLE vulntrack_devices.%I FORCE ROW LEVEL SECURITY', item.table_name);
        EXECUTE format('CREATE POLICY scoped_read ON vulntrack_devices.%I FOR SELECT USING (
             workspace_id = vulntrack.current_workspace_id() AND
             vulntrack.has_workspace_role(workspace_id, ARRAY[''owner'',''editor'',''viewer'']))', item.table_name);
        EXECUTE format('CREATE POLICY scoped_insert ON vulntrack_devices.%I FOR INSERT WITH CHECK (
             workspace_id = vulntrack.current_workspace_id() AND %s AND
             vulntrack.has_workspace_role(workspace_id, ARRAY[''owner'',''editor'']))', item.table_name, item.check_actor);
        EXECUTE format('GRANT SELECT, INSERT ON vulntrack_devices.%I TO vulntrack_app', item.table_name);
    END LOOP;
END $$;

CREATE POLICY scoped_update ON vulntrack_devices.devices FOR UPDATE
    USING (workspace_id = vulntrack.current_workspace_id() AND vulntrack.has_workspace_role(workspace_id, ARRAY['owner','editor']))
    WITH CHECK (workspace_id = vulntrack.current_workspace_id() AND vulntrack.has_workspace_role(workspace_id, ARRAY['owner','editor']));
CREATE POLICY scoped_update ON vulntrack_devices.runs FOR UPDATE
    USING (status='running' AND workspace_id = vulntrack.current_workspace_id() AND vulntrack.has_workspace_role(workspace_id, ARRAY['owner','editor']))
    WITH CHECK (workspace_id = vulntrack.current_workspace_id() AND vulntrack.has_workspace_role(workspace_id, ARRAY['owner','editor']));
CREATE POLICY scoped_update ON vulntrack_devices.findings FOR UPDATE
    USING (status='open' AND workspace_id = vulntrack.current_workspace_id() AND vulntrack.has_workspace_role(workspace_id, ARRAY['owner','editor']))
    WITH CHECK (workspace_id = vulntrack.current_workspace_id() AND status='reviewed' AND reviewed_by=vulntrack.current_user_id()
        AND vulntrack.has_workspace_role(workspace_id, ARRAY['owner','editor']));

GRANT UPDATE (status, updated_at) ON vulntrack_devices.devices TO vulntrack_app;
GRANT UPDATE (status, coverage, total_results, retrieved_count, stored_count, warning_codes, failure_code, source_timestamp, completed_at)
    ON vulntrack_devices.runs TO vulntrack_app;
GRANT UPDATE (applicability, status, reviewed_by, review_reason, review_evidence, updated_at)
    ON vulntrack_devices.findings TO vulntrack_app;

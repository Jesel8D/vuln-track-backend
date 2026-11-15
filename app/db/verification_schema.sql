-- Phase 2B, additive and explicit: apply only on a compatible SQL007 database.
-- No network operation or ZAP permission is enabled by this schema.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';
DO $$ BEGIN
    IF to_regclass('vulntrack.application_targets') IS NULL
       OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='vulntrack_registration')
       OR NOT EXISTS (SELECT 1 FROM pg_constraint
           WHERE conrelid='vulntrack.application_findings'::regclass
             AND conname='app_findings_applicability_valid'
             AND pg_get_constraintdef(oid) LIKE '%undetermined%') THEN
        RAISE EXCEPTION 'SQL007 required before target verification';
    END IF;
END $$;

CREATE ROLE vulntrack_verification_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS;
CREATE ROLE vulntrack_verification_lab NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS;
CREATE SCHEMA vulntrack_verification AUTHORIZATION vulntrack_verification_owner;
REVOKE ALL ON SCHEMA vulntrack_verification FROM PUBLIC;
GRANT USAGE ON SCHEMA vulntrack TO vulntrack_verification_owner, vulntrack_verification_lab;
GRANT EXECUTE ON FUNCTION vulntrack.current_user_id(), vulntrack.current_workspace_id(),
    vulntrack.context_is_valid(), vulntrack.has_workspace_role(uuid,text[])
    TO vulntrack_verification_owner, vulntrack_verification_lab;
GRANT EXECUTE ON FUNCTION vulntrack.valid_text(text,integer) TO vulntrack_verification_owner;
GRANT EXECUTE ON FUNCTION vulntrack.establish_context(uuid,uuid,bigint,uuid,text)
    TO vulntrack_verification_lab;
GRANT SELECT ON vulntrack.applications, vulntrack.application_targets TO vulntrack_verification_owner;
GRANT REFERENCES(workspace_id,application_id,id) ON vulntrack.application_targets TO vulntrack_verification_owner;
GRANT REFERENCES(workspace_id,user_id) ON vulntrack.workspace_members TO vulntrack_verification_owner;
-- PostgreSQL row-lock clauses need UPDATE on at least one column. These grants
-- belong only to a non-login, non-member definer; its fixed functions never write them.
GRANT UPDATE(name) ON vulntrack.applications TO vulntrack_verification_owner;
GRANT UPDATE(label) ON vulntrack.application_targets TO vulntrack_verification_owner;
GRANT INSERT ON vulntrack.audit_events TO vulntrack_verification_owner;
GRANT USAGE, SELECT ON SEQUENCE vulntrack.audit_events_id_seq TO vulntrack_verification_owner;

SET LOCAL ROLE vulntrack_verification_owner;
ALTER DEFAULT PRIVILEGES IN SCHEMA vulntrack_verification REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA vulntrack_verification REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE vulntrack_verification.challenges (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    application_id uuid NOT NULL,
    target_id uuid NOT NULL,
    issued_by uuid NOT NULL,
    request_key uuid NOT NULL,
    method text NOT NULL DEFAULT 'https_file' CHECK (method='https_file'),
    purpose text NOT NULL DEFAULT 'vulntrack-domain-control-https-v1'
        CHECK (purpose='vulntrack-domain-control-https-v1'),
    origin text NOT NULL CHECK (origin ~ '^https://[^/?#@[:space:]]+$' AND length(origin)<=300),
    url_sha256 text NOT NULL CHECK (url_sha256 ~ '^[0-9a-f]{64}$'),
    declaration_version timestamptz NOT NULL,
    declaration_expires_at timestamptz NOT NULL,
    proof_sha256 text NOT NULL CHECK (proof_sha256 ~ '^[0-9a-f]{64}$'),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','verified','failed','expired','revoked')),
    attempts smallint NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 1),
    version integer NOT NULL DEFAULT 1 CHECK (version>0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    verified_at timestamptz,
    evidence_expires_at timestamptz,
    revoked_at timestamptz,
    result_code text NOT NULL DEFAULT 'NOT_CHECKED'
        CHECK (result_code IN ('NOT_CHECKED','LABORATORY_IN_PROGRESS','LABORATORY_MATCH_ONLY',
            'PROOF_MISMATCH','TRANSPORT_FAILED','ATTEMPT_EXPIRED','CHALLENGE_EXPIRED',
            'SCOPE_CHANGED','REVOKED','REMOTE_VERIFIED')),
    CONSTRAINT challenge_target_fk FOREIGN KEY (workspace_id,application_id,target_id)
        REFERENCES vulntrack.application_targets(workspace_id,application_id,id) ON DELETE RESTRICT,
    CONSTRAINT challenge_member_fk FOREIGN KEY (workspace_id,issued_by)
        REFERENCES vulntrack.workspace_members(workspace_id,user_id) ON DELETE RESTRICT,
    CONSTRAINT challenge_expiry CHECK (created_at<expires_at AND expires_at<=created_at+interval '10 minutes'
        AND expires_at<=declaration_expires_at AND declaration_version<=created_at),
    CONSTRAINT challenge_consumption CHECK ((attempts=0 AND consumed_at IS NULL)
        OR (attempts=1 AND consumed_at IS NOT NULL)),
    CONSTRAINT challenge_no_automatic_verification CHECK (
        (state='verified' AND verified_at IS NOT NULL AND evidence_expires_at IS NOT NULL
         AND result_code='REMOTE_VERIFIED' AND attempts=1
         AND verified_at<evidence_expires_at AND evidence_expires_at<=declaration_expires_at)
        OR (state<>'verified' AND verified_at IS NULL AND evidence_expires_at IS NULL)),
    CONSTRAINT challenge_revocation CHECK ((state='revoked')=(revoked_at IS NOT NULL)),
    UNIQUE(workspace_id,application_id,target_id,id),
    UNIQUE(workspace_id,issued_by,request_key)
);
CREATE UNIQUE INDEX challenge_one_pending_target ON vulntrack_verification.challenges(workspace_id,target_id)
    WHERE state='pending';
CREATE INDEX challenge_workspace_history ON vulntrack_verification.challenges(workspace_id,target_id,created_at DESC,id);

CREATE TABLE vulntrack_verification.attempts (
    id uuid PRIMARY KEY,
    workspace_id uuid NOT NULL,
    application_id uuid NOT NULL,
    target_id uuid NOT NULL,
    challenge_id uuid NOT NULL UNIQUE,
    actor_id uuid NOT NULL,
    provenance text NOT NULL CHECK (provenance='laboratory'),
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deadline_at timestamptz NOT NULL,
    completed_at timestamptz,
    outcome text NOT NULL DEFAULT 'in_progress'
        CHECK (outcome IN ('in_progress','laboratory_match','proof_mismatch','transport_failed','expired','revoked')),
    received_sha256 text CHECK (received_sha256 ~ '^[0-9a-f]{64}$'),
    peer_ip inet,
    certificate_sha256 text CHECK (certificate_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT attempt_challenge_fk FOREIGN KEY (workspace_id,application_id,target_id,challenge_id)
        REFERENCES vulntrack_verification.challenges(workspace_id,application_id,target_id,id) ON DELETE RESTRICT,
    CONSTRAINT attempt_actor_fk FOREIGN KEY (workspace_id,actor_id)
        REFERENCES vulntrack.workspace_members(workspace_id,user_id) ON DELETE RESTRICT,
    CONSTRAINT attempt_deadline CHECK (started_at<deadline_at AND deadline_at<=started_at+interval '15 seconds'),
    CONSTRAINT attempt_completion CHECK ((outcome='in_progress')=(completed_at IS NULL))
);

ALTER TABLE vulntrack_verification.challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulntrack_verification.challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE vulntrack_verification.attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulntrack_verification.attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY challenge_read ON vulntrack_verification.challenges FOR SELECT USING (
    workspace_id=vulntrack.current_workspace_id()
    AND vulntrack.has_workspace_role(workspace_id,ARRAY['owner','editor','viewer']));
CREATE POLICY challenge_insert ON vulntrack_verification.challenges FOR INSERT WITH CHECK (
    workspace_id=vulntrack.current_workspace_id() AND issued_by=vulntrack.current_user_id()
    AND vulntrack.has_workspace_role(workspace_id,ARRAY['owner','editor']));
CREATE POLICY challenge_update ON vulntrack_verification.challenges FOR UPDATE USING (
    workspace_id=vulntrack.current_workspace_id()
    AND vulntrack.has_workspace_role(workspace_id,ARRAY['owner','editor'])) WITH CHECK (
    workspace_id=vulntrack.current_workspace_id()
    AND vulntrack.has_workspace_role(workspace_id,ARRAY['owner','editor']));
CREATE POLICY attempt_read ON vulntrack_verification.attempts FOR SELECT USING (
    workspace_id=vulntrack.current_workspace_id()
    AND vulntrack.has_workspace_role(workspace_id,ARRAY['owner','editor','viewer']));
CREATE POLICY attempt_insert ON vulntrack_verification.attempts FOR INSERT WITH CHECK (
    workspace_id=vulntrack.current_workspace_id() AND actor_id=vulntrack.current_user_id()
    AND vulntrack.has_workspace_role(workspace_id,ARRAY['owner','editor']));
CREATE POLICY attempt_update ON vulntrack_verification.attempts FOR UPDATE USING (
    workspace_id=vulntrack.current_workspace_id()
    AND vulntrack.has_workspace_role(workspace_id,ARRAY['owner','editor'])) WITH CHECK (
    workspace_id=vulntrack.current_workspace_id()
    AND vulntrack.has_workspace_role(workspace_id,ARRAY['owner','editor']));

CREATE FUNCTION vulntrack_verification.guard_challenge() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.workspace_id,NEW.application_id,NEW.target_id,NEW.issued_by,
        NEW.request_key,NEW.method,NEW.purpose,NEW.origin,NEW.url_sha256,NEW.declaration_version,
        NEW.declaration_expires_at,NEW.proof_sha256,NEW.created_at,NEW.expires_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.workspace_id,OLD.application_id,OLD.target_id,OLD.issued_by,
        OLD.request_key,OLD.method,OLD.purpose,OLD.origin,OLD.url_sha256,OLD.declaration_version,
        OLD.declaration_expires_at,OLD.proof_sha256,OLD.created_at,OLD.expires_at)
        OR NEW.version<>OLD.version+1 OR NEW.attempts<OLD.attempts
        OR NEW.state='verified' OR (OLD.state<>'pending' AND NEW.state<>'revoked') THEN
        RAISE EXCEPTION 'verification transition denied' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER challenge_guard BEFORE UPDATE OR DELETE ON vulntrack_verification.challenges
    FOR EACH ROW EXECUTE FUNCTION vulntrack_verification.guard_challenge();
CREATE FUNCTION vulntrack_verification.guard_attempt() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
    IF TG_OP='DELETE' OR OLD.outcome<>'in_progress'
        OR ROW(NEW.id,NEW.workspace_id,NEW.application_id,NEW.target_id,NEW.challenge_id,
               NEW.actor_id,NEW.provenance,NEW.started_at,NEW.deadline_at)
        IS DISTINCT FROM ROW(OLD.id,OLD.workspace_id,OLD.application_id,OLD.target_id,OLD.challenge_id,
               OLD.actor_id,OLD.provenance,OLD.started_at,OLD.deadline_at) THEN
        RAISE EXCEPTION 'immutable verification evidence' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER attempt_guard BEFORE UPDATE OR DELETE ON vulntrack_verification.attempts
    FOR EACH ROW EXECUTE FUNCTION vulntrack_verification.guard_attempt();

CREATE FUNCTION vulntrack_verification.lock_target(w uuid,a uuid,t uuid,require_active boolean DEFAULT true)
RETURNS vulntrack.application_targets LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE target vulntrack.application_targets; BEGIN
    IF w IS DISTINCT FROM vulntrack.current_workspace_id()
       OR NOT vulntrack.has_workspace_role(w,ARRAY['owner','editor']) THEN
        RAISE EXCEPTION 'verification resource unavailable' USING ERRCODE='42501';
    END IF;
    PERFORM 1 FROM vulntrack.applications WHERE workspace_id=w AND id=a
        AND (NOT require_active OR status='active') FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'verification resource unavailable' USING ERRCODE='42501'; END IF;
    SELECT * INTO target FROM vulntrack.application_targets
        WHERE workspace_id=w AND application_id=a AND id=t FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'verification resource unavailable' USING ERRCODE='42501'; END IF;
    RETURN target;
END $$;

CREATE FUNCTION vulntrack_verification.issue(w uuid,a uuid,t uuid,identity uuid,key uuid,
    expected timestamptz,canonical_origin text,digest text)
RETURNS TABLE(challenge_id uuid,created boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE target vulntrack.application_targets; prior vulntrack_verification.challenges;
    moment timestamptz:=clock_timestamp(); old_id uuid; BEGIN
    target:=vulntrack_verification.lock_target(w,a,t);
    -- Serialize the workspace quota as well as the per-target unique constraint.
    PERFORM pg_advisory_xact_lock(hashtextextended('verification-quota:'||w::text,0));
    moment:=clock_timestamp();
    SELECT * INTO prior FROM vulntrack_verification.challenges
        WHERE workspace_id=w AND issued_by=vulntrack.current_user_id() AND request_key=key;
    IF FOUND THEN
        IF prior.target_id<>t OR prior.application_id<>a OR prior.declaration_version<>expected
           OR prior.origin<>canonical_origin THEN
            RAISE EXCEPTION 'idempotency conflict' USING ERRCODE='23505';
        END IF;
        RETURN QUERY SELECT prior.id,false; RETURN;
    END IF;
    IF target.updated_at IS DISTINCT FROM expected OR target.authorization_status<>'approved'
       OR target.authorization_reference IS NULL OR target.authorization_expires_at<=moment
       OR canonical_origin IS DISTINCT FROM substring(target.url from '^(https://[^/?#]+)') THEN
        RAISE EXCEPTION 'verification scope changed' USING ERRCODE='23514';
    END IF;
    FOR old_id IN SELECT id FROM vulntrack_verification.challenges
        WHERE workspace_id=w AND target_id=t AND state='pending' AND expires_at<=moment FOR UPDATE LOOP
        UPDATE vulntrack_verification.challenges SET state='expired',result_code='CHALLENGE_EXPIRED',
            version=version+1 WHERE id=old_id;
        UPDATE vulntrack_verification.attempts SET outcome='expired',completed_at=moment
            WHERE challenge_id=old_id AND outcome='in_progress';
        INSERT INTO vulntrack.audit_events(workspace_id,actor_id,action,object_type,object_id)
            VALUES(w,vulntrack.current_user_id(),'verification.expired','target_verification',old_id);
    END LOOP;
    IF (SELECT count(*) FROM vulntrack_verification.challenges
        WHERE workspace_id=w AND created_at>moment-interval '24 hours')>=20 THEN
        RAISE EXCEPTION 'verification quota reached' USING ERRCODE='54000';
    END IF;
    INSERT INTO vulntrack_verification.challenges(id,workspace_id,application_id,target_id,issued_by,
        request_key,origin,url_sha256,declaration_version,declaration_expires_at,proof_sha256,created_at,expires_at)
        VALUES(identity,w,a,t,vulntrack.current_user_id(),key,canonical_origin,
            encode(public.digest(target.url,'sha256'),'hex'),target.updated_at,
            target.authorization_expires_at,digest,moment,least(moment+interval '10 minutes',target.authorization_expires_at));
    INSERT INTO vulntrack.audit_events(workspace_id,actor_id,action,object_type,object_id)
        VALUES(w,vulntrack.current_user_id(),'verification.issued','target_verification',identity);
    RETURN QUERY SELECT identity,true;
END $$;

CREATE FUNCTION vulntrack_verification.revoke(w uuid,a uuid,t uuid,identity uuid,expected integer)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prior vulntrack_verification.challenges; moment timestamptz:=clock_timestamp(); BEGIN
    PERFORM vulntrack_verification.lock_target(w,a,t,false);
    SELECT * INTO prior FROM vulntrack_verification.challenges WHERE workspace_id=w
        AND application_id=a AND target_id=t AND id=identity FOR UPDATE;
    moment:=clock_timestamp();
    IF NOT FOUND THEN RAISE EXCEPTION 'verification resource unavailable' USING ERRCODE='42501'; END IF;
    IF prior.state='revoked' THEN RETURN; END IF;
    IF prior.version IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'verification version conflict' USING ERRCODE='23505';
    END IF;
    UPDATE vulntrack_verification.challenges SET state='revoked',revoked_at=moment,
        result_code='REVOKED',version=version+1 WHERE id=identity;
    UPDATE vulntrack_verification.attempts SET outcome='revoked',completed_at=moment
        WHERE challenge_id=identity AND outcome='in_progress';
    INSERT INTO vulntrack.audit_events(workspace_id,actor_id,action,object_type,object_id)
        VALUES(w,vulntrack.current_user_id(),'verification.revoked','target_verification',identity);
END $$;

CREATE FUNCTION vulntrack_verification.claim_laboratory(w uuid,a uuid,t uuid,identity uuid,attempt uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE target vulntrack.application_targets; prior vulntrack_verification.challenges;
    moment timestamptz:=clock_timestamp(); BEGIN
    target:=vulntrack_verification.lock_target(w,a,t);
    SELECT * INTO prior FROM vulntrack_verification.challenges WHERE workspace_id=w
        AND application_id=a AND target_id=t AND id=identity FOR UPDATE;
    moment:=clock_timestamp();
    IF NOT FOUND THEN RAISE EXCEPTION 'verification resource unavailable' USING ERRCODE='42501'; END IF;
    IF prior.state<>'pending' OR prior.attempts<>0 OR prior.expires_at<=moment
       OR target.updated_at<>prior.declaration_version
       OR encode(public.digest(target.url,'sha256'),'hex')<>prior.url_sha256
       OR target.authorization_status<>'approved' OR target.authorization_expires_at<=moment THEN
        RAISE EXCEPTION 'verification consumed, expired or changed' USING ERRCODE='23514';
    END IF;
    UPDATE vulntrack_verification.challenges SET attempts=1,consumed_at=moment,
        result_code='LABORATORY_IN_PROGRESS',version=version+1 WHERE id=identity;
    INSERT INTO vulntrack_verification.attempts(id,workspace_id,application_id,target_id,challenge_id,
        actor_id,provenance,started_at,deadline_at)
        VALUES(attempt,w,a,t,identity,vulntrack.current_user_id(),'laboratory',moment,
            least(moment+interval '15 seconds',prior.expires_at));
    INSERT INTO vulntrack.audit_events(workspace_id,actor_id,action,object_type,object_id)
        VALUES(w,vulntrack.current_user_id(),'verification.laboratory_claimed','target_verification',identity);
END $$;

CREATE FUNCTION vulntrack_verification.finish_laboratory(w uuid,a uuid,t uuid,identity uuid,
    attempt uuid,received_digest text,peer inet,certificate_digest text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE target vulntrack.application_targets; prior vulntrack_verification.challenges;
    evidence vulntrack_verification.attempts; moment timestamptz:=clock_timestamp(); code text; result text; BEGIN
    target:=vulntrack_verification.lock_target(w,a,t);
    SELECT * INTO prior FROM vulntrack_verification.challenges WHERE workspace_id=w
        AND application_id=a AND target_id=t AND id=identity FOR UPDATE;
    SELECT * INTO evidence FROM vulntrack_verification.attempts
        WHERE workspace_id=w AND challenge_id=identity AND id=attempt FOR UPDATE;
    moment:=clock_timestamp();
    IF prior.id IS NULL OR evidence.id IS NULL OR prior.state<>'pending'
       OR prior.attempts<>1 OR evidence.outcome<>'in_progress'
       OR evidence.actor_id<>vulntrack.current_user_id() THEN
        RAISE EXCEPTION 'verification attempt unavailable' USING ERRCODE='23514';
    END IF;
    IF target.updated_at<>prior.declaration_version
       OR encode(public.digest(target.url,'sha256'),'hex')<>prior.url_sha256
       OR target.authorization_status<>'approved' OR target.authorization_expires_at<=moment THEN
        code:='SCOPE_CHANGED'; result:='revoked';
    ELSIF prior.expires_at<=moment OR evidence.deadline_at<=moment THEN
        code:='ATTEMPT_EXPIRED'; result:='expired';
    ELSIF received_digest IS NULL THEN code:='TRANSPORT_FAILED'; result:='transport_failed';
    ELSIF received_digest=prior.proof_sha256 THEN code:='LABORATORY_MATCH_ONLY'; result:='laboratory_match';
    ELSE code:='PROOF_MISMATCH'; result:='proof_mismatch'; END IF;
    UPDATE vulntrack_verification.attempts SET completed_at=moment,outcome=result,
        received_sha256=received_digest,peer_ip=peer,certificate_sha256=certificate_digest WHERE id=attempt;
    -- A fixture match is persisted as a laboratory result, NEVER as verified control.
    UPDATE vulntrack_verification.challenges SET state='failed',result_code=code,version=version+1 WHERE id=identity;
    INSERT INTO vulntrack.audit_events(workspace_id,actor_id,action,object_type,object_id)
        VALUES(w,vulntrack.current_user_id(),'verification.laboratory_completed','target_verification',identity);
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA vulntrack_verification FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA vulntrack_verification FROM PUBLIC;
GRANT USAGE ON SCHEMA vulntrack_verification TO vulntrack_app, vulntrack_verification_lab;
GRANT SELECT(id,workspace_id,application_id,target_id,issued_by,request_key,method,purpose,origin,
    url_sha256,declaration_version,declaration_expires_at,state,attempts,version,created_at,expires_at,
    consumed_at,verified_at,evidence_expires_at,revoked_at,result_code)
    ON vulntrack_verification.challenges TO vulntrack_app;
GRANT SELECT(id,workspace_id,application_id,target_id,challenge_id,actor_id,provenance,started_at,
    deadline_at,completed_at,outcome) ON vulntrack_verification.attempts TO vulntrack_app;
GRANT SELECT ON vulntrack_verification.challenges,vulntrack_verification.attempts TO vulntrack_verification_lab;
GRANT EXECUTE ON FUNCTION vulntrack_verification.issue(uuid,uuid,uuid,uuid,uuid,timestamptz,text,text),
    vulntrack_verification.revoke(uuid,uuid,uuid,uuid,integer) TO vulntrack_app;
GRANT EXECUTE ON FUNCTION vulntrack_verification.claim_laboratory(uuid,uuid,uuid,uuid,uuid),
    vulntrack_verification.finish_laboratory(uuid,uuid,uuid,uuid,uuid,text,inet,text) TO vulntrack_verification_lab;
COMMENT ON SCHEMA vulntrack_verification IS 'Phase 2B: durable scoped challenges; operational remote verification and ZAP disabled';
COMMENT ON TABLE vulntrack_verification.attempts IS 'Laboratory provenance only; never evidence of real domain control';
RESET ROLE;

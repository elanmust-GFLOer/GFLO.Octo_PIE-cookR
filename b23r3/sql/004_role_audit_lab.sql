-- B2.3-R3 disposable role/audit prototype. NOT PRODUCTION AUTH.
DO $g$ BEGIN
 IF current_database() NOT LIKE 'b2test\_%' ESCAPE '\'
 OR current_setting('gflo.b2_disposable_ok',true) IS DISTINCT FROM 'YES'
 THEN RAISE EXCEPTION 'disposable DB guard'; END IF;
END $g$;
BEGIN;
CREATE ROLE b23r3_data_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
CREATE ROLE b23r3_mutator NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
CREATE ROLE b23r3_lab_caller NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
ALTER TABLE private.wallet_binding_state OWNER TO b23r3_data_owner;
ALTER TABLE private.wallet_binding_challenges OWNER TO b23r3_data_owner;
ALTER TABLE private.wallet_bindings OWNER TO b23r3_data_owner;
ALTER TABLE private.wallet_recovery_cases OWNER TO b23r3_data_owner;
ALTER TABLE private.wallet_binding_audit OWNER TO b23r3_data_owner;
-- FK checks on referenced rows execute with table-owner rights; ownership does not imply schema USAGE.
GRANT USAGE ON SCHEMA private TO b23r3_data_owner;
GRANT USAGE ON SCHEMA private,b23_auth_sim TO b23r3_mutator;
GRANT USAGE ON SCHEMA private TO b23r3_lab_caller;
GRANT SELECT,UPDATE ON private.wallet_binding_state,private.wallet_binding_challenges,private.wallet_bindings TO b23r3_mutator;
GRANT INSERT ON private.wallet_binding_audit TO b23r3_mutator;
GRANT SELECT ON private.wallet_binding_audit TO b23r3_mutator;
-- FOR UPDATE row locking requires UPDATE privilege on the lab session table.
GRANT SELECT,UPDATE ON b23_auth_sim.sessions TO b23r3_mutator;
CREATE POLICY r3_mutator_state ON private.wallet_binding_state TO b23r3_mutator USING(true) WITH CHECK(true);
CREATE POLICY r3_mutator_challenge ON private.wallet_binding_challenges TO b23r3_mutator USING(true) WITH CHECK(true);
CREATE POLICY r3_mutator_binding ON private.wallet_bindings TO b23r3_mutator USING(true) WITH CHECK(true);
CREATE POLICY r3_mutator_audit ON private.wallet_binding_audit FOR INSERT TO b23r3_mutator WITH CHECK(true);
CREATE POLICY r3_mutator_audit_read ON private.wallet_binding_audit FOR SELECT TO b23r3_mutator USING(true);
CREATE TABLE private.b23r3_requests(
 request_id uuid PRIMARY KEY,
 user_id uuid NOT NULL,
 session_id uuid NOT NULL,
 chain_id bigint NOT NULL,
 target_binding uuid NOT NULL,
 expected_epoch bigint NOT NULL,
 payload_hash bytea NOT NULL CHECK(octet_length(payload_hash)=32),
 outcome text NOT NULL CHECK(outcome='suspended'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE private.b23r3_requests OWNER TO b23r3_data_owner;
ALTER TABLE private.b23r3_requests ENABLE ROW LEVEL SECURITY;
GRANT SELECT,INSERT ON private.b23r3_requests TO b23r3_mutator;
CREATE POLICY r3_mutator_requests ON private.b23r3_requests TO b23r3_mutator USING(true) WITH CHECK(true);
CREATE FUNCTION private.b23r3_suspend_lab(
 p_user uuid,p_session uuid,p_chain bigint,p_binding uuid,p_epoch bigint,p_request uuid,p_payload_hash bytea
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $f$
DECLARE v_user uuid;v_revoked timestamptz;v_binding private.wallet_binding_status;
 v_controller private.wallet_controller_status;v_epoch bigint;v_request private.b23r3_requests%ROWTYPE;
BEGIN
 IF p_user IS NULL OR p_session IS NULL OR p_chain IS NULL OR p_chain<=0 OR p_binding IS NULL
 OR p_epoch IS NULL OR p_request IS NULL OR p_payload_hash IS NULL OR octet_length(p_payload_hash)<>32
 THEN RAISE EXCEPTION 'invalid input' USING ERRCODE='22023'; END IF;
 SELECT user_id,revoked_at INTO v_user,v_revoked FROM b23_auth_sim.sessions
 WHERE session_id=p_session FOR UPDATE;
 IF NOT FOUND OR v_revoked IS NOT NULL OR v_user IS DISTINCT FROM p_user
 THEN RAISE EXCEPTION 'lab session not authorized' USING ERRCODE='42501'; END IF;
 SELECT * INTO v_request FROM private.b23r3_requests WHERE request_id=p_request;
 IF FOUND THEN
  IF v_request.user_id<>p_user OR v_request.session_id<>p_session OR v_request.chain_id<>p_chain
   OR v_request.target_binding<>p_binding OR v_request.expected_epoch<>p_epoch OR v_request.payload_hash<>p_payload_hash
  THEN RAISE EXCEPTION 'request replay payload mismatch' USING ERRCODE='23505'; END IF;
  RETURN v_request.outcome;
 END IF;
 SELECT epoch,binding_status INTO v_epoch,v_controller FROM private.wallet_binding_state
 WHERE user_id=p_user AND chain_id=p_chain FOR UPDATE;
 IF NOT FOUND OR v_epoch<>p_epoch OR v_controller<>'active'
 THEN RAISE EXCEPTION 'controller state mismatch' USING ERRCODE='23514'; END IF;
 SELECT status INTO v_binding FROM private.wallet_bindings
 WHERE binding_id=p_binding AND user_id=p_user AND chain_id=p_chain FOR UPDATE;
 IF NOT FOUND OR v_binding<>'active'
 THEN RAISE EXCEPTION 'binding not active' USING ERRCODE='23514'; END IF;
 IF v_epoch>=9223372036854775806 THEN RAISE EXCEPTION 'epoch limit' USING ERRCODE='22003'; END IF;
 UPDATE private.wallet_bindings SET status='suspended',suspended_at=clock_timestamp() WHERE binding_id=p_binding;
 UPDATE private.wallet_binding_state SET binding_status='suspended',epoch=epoch+1,updated_at=clock_timestamp()
 WHERE user_id=p_user AND chain_id=p_chain;
 UPDATE private.wallet_binding_challenges SET status='invalidated'
 WHERE user_id=p_user AND chain_id=p_chain AND status='pending';
 INSERT INTO private.wallet_binding_audit(request_id,actor_ref,object_ref,event_type,result,policy_version)
 VALUES(p_request,p_user::text,p_binding::text,'BINDING_SUSPENDED','success','B23-R3-lab');
 INSERT INTO private.b23r3_requests(request_id,user_id,session_id,chain_id,target_binding,expected_epoch,payload_hash,outcome)
 VALUES(p_request,p_user,p_session,p_chain,p_binding,p_epoch,p_payload_hash,'suspended');
 RETURN 'suspended';
END $f$;
ALTER FUNCTION private.b23r3_suspend_lab(uuid,uuid,bigint,uuid,bigint,uuid,bytea) OWNER TO b23r3_mutator;
REVOKE ALL ON FUNCTION private.b23r3_suspend_lab(uuid,uuid,bigint,uuid,bigint,uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.b23r3_suspend_lab(uuid,uuid,bigint,uuid,bigint,uuid,bytea) TO b23r3_lab_caller;
REVOKE ALL ON ALL TABLES IN SCHEMA private FROM b23_runtime,b23_untrusted,b23r3_lab_caller;
COMMIT;

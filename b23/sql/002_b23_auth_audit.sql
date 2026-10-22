-- B2.3 disposable session authority simulator. Not production Supabase integration.
DO $g$ BEGIN
 IF current_database() NOT LIKE 'b2test\_%' ESCAPE '\' OR current_setting('gflo.b2_disposable_ok',true) IS DISTINCT FROM 'YES'
 THEN RAISE EXCEPTION 'B2.3 refuses non-disposable DB'; END IF;
END $g$;
BEGIN;
CREATE SCHEMA b23_auth_sim;
REVOKE ALL ON SCHEMA b23_auth_sim FROM PUBLIC;
CREATE TABLE b23_auth_sim.sessions (session_id uuid PRIMARY KEY, user_id uuid NOT NULL, revoked_at timestamptz);
CREATE ROLE b23_runtime NOLOGIN;
CREATE ROLE b23_untrusted NOLOGIN;
REVOKE ALL ON ALL TABLES IN SCHEMA b23_auth_sim FROM PUBLIC;
GRANT USAGE ON SCHEMA private, b23_auth_sim TO b23_runtime;
GRANT SELECT ON b23_auth_sim.sessions TO b23_runtime;
-- Runtime should NEVER have direct table writes in production.
CREATE FUNCTION private.b23_suspend(p_user uuid,p_session uuid,p_chain bigint,p_request uuid)
 RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $f$
DECLARE v_owner uuid; v_revoked timestamptz; v_status private.wallet_binding_status; v_epoch bigint;
BEGIN
 IF p_user IS NULL OR p_session IS NULL OR p_request IS NULL OR p_chain IS NULL OR p_chain<=0
 THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='22023'; END IF;
 -- Same-row lock only simulates transactional revocation interlock.
 SELECT user_id,revoked_at INTO v_owner,v_revoked FROM b23_auth_sim.sessions WHERE session_id=p_session FOR UPDATE;
 IF NOT FOUND OR v_owner IS DISTINCT FROM p_user OR v_revoked IS NOT NULL
 THEN RAISE EXCEPTION 'unauthorized session' USING ERRCODE='42501'; END IF;
 SELECT epoch INTO v_epoch FROM private.wallet_binding_state WHERE user_id=p_user AND chain_id=p_chain FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'controller not found' USING ERRCODE='P0002'; END IF;
 SELECT status INTO v_status FROM private.wallet_bindings WHERE user_id=p_user AND chain_id=p_chain
  AND status IN ('active','suspended') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'reserved binding not found' USING ERRCODE='P0002'; END IF;
 IF v_status='suspended' THEN RETURN 'already_suspended'; END IF;
 IF v_epoch>=9223372036854775806 THEN RAISE EXCEPTION 'epoch limit' USING ERRCODE='22003'; END IF;
 UPDATE private.wallet_bindings SET status='suspended',suspended_at=clock_timestamp()
 WHERE user_id=p_user AND chain_id=p_chain AND status='active';
 UPDATE private.wallet_binding_state SET epoch=epoch+1,binding_status='suspended',updated_at=clock_timestamp()
 WHERE user_id=p_user AND chain_id=p_chain;
 UPDATE private.wallet_binding_challenges SET status='invalidated'
 WHERE user_id=p_user AND chain_id=p_chain AND status='pending';
 INSERT INTO private.wallet_binding_audit(request_id,actor_ref,object_ref,event_type,result,policy_version)
 VALUES(p_request,p_user::text,p_user::text||':'||p_chain::text,'BINDING_SUSPENDED','success','B2.3-lab');
 RETURN 'suspended';
END $f$;
REVOKE ALL ON FUNCTION private.b23_suspend(uuid,uuid,bigint,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.b23_suspend(uuid,uuid,bigint,uuid) TO b23_runtime;
COMMIT;
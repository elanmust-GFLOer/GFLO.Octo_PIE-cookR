-- R1 isolated restrictive overlay; applies only to disposable b2test_* DB
DO $$
BEGIN
 IF current_database() NOT LIKE 'b2test\_%' ESCAPE '\'
   OR current_setting('gflo.b2_disposable_ok',true) IS DISTINCT FROM 'YES'
 THEN RAISE EXCEPTION 'R1 refuses non-disposable database'; END IF;
END $$;
BEGIN;
REVOKE SELECT ON b23_auth_sim.sessions FROM b23_runtime;
REVOKE EXECUTE ON FUNCTION private.b23_suspend(uuid,uuid,bigint,uuid) FROM b23_runtime;
REVOKE EXECUTE ON FUNCTION private.b23_suspend(uuid,uuid,bigint,uuid) FROM PUBLIC;
-- An explicit lab-owned interface demonstrates controller serialization.
-- Deliberately NOT exposed to any operational role.
CREATE FUNCTION private.b23r1_issue_challenge(
 p_user uuid,p_chain bigint,p_wallet bytea,p_nonce_hash bytea,p_session uuid,
 p_siwe_digest bytea,p_consent_digest bytea
) RETURNS uuid LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $fn$
DECLARE v_epoch bigint; v_status private.wallet_controller_status; v_challenge uuid;
BEGIN
 SELECT epoch,binding_status INTO v_epoch,v_status
 FROM private.wallet_binding_state
 WHERE user_id=p_user AND chain_id=p_chain FOR UPDATE;
 IF NOT FOUND OR v_status <> 'unbound' THEN
   RAISE EXCEPTION 'challenge issuance disallowed in current lifecycle' USING ERRCODE='42501';
 END IF;
 INSERT INTO private.wallet_binding_challenges(
  user_id,chain_id,wallet_address,nonce_hash,epoch,auth_session_id,auth_generation,
  domain,uri,siwe_message_digest,consent_digest,consent_version,scopes,expires_at
 ) VALUES(
  p_user,p_chain,p_wallet,p_nonce_hash,v_epoch,p_session,0,
  'example.test','https://example.test',p_siwe_digest,p_consent_digest,
  'R1-lab-only',ARRAY['bind:wallet'],clock_timestamp()+interval '4 minutes'
 ) RETURNING challenge_id INTO v_challenge;
 RETURN v_challenge;
END $fn$;
REVOKE ALL ON FUNCTION private.b23r1_issue_challenge(uuid,bigint,bytea,bytea,uuid,bytea,bytea) FROM PUBLIC;
-- Fail closed on inconsistent already-suspended rows; no audit-free repair.
CREATE OR REPLACE FUNCTION private.b23_suspend(p_user uuid,p_session uuid,p_chain bigint,p_request uuid)
 RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $f$
DECLARE v_owner uuid; v_revoked timestamptz; v_status private.wallet_binding_status;
 v_epoch bigint; v_controller private.wallet_controller_status; v_pending int;
BEGIN
 IF p_user IS NULL OR p_session IS NULL OR p_request IS NULL OR p_chain IS NULL OR p_chain<=0
 THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='22023'; END IF;
 SELECT user_id,revoked_at INTO v_owner,v_revoked FROM b23_auth_sim.sessions
 WHERE session_id=p_session FOR UPDATE;
 IF NOT FOUND OR v_owner IS DISTINCT FROM p_user OR v_revoked IS NOT NULL
 THEN RAISE EXCEPTION 'unauthorized session' USING ERRCODE='42501'; END IF;
 SELECT epoch,binding_status INTO v_epoch,v_controller
 FROM private.wallet_binding_state WHERE user_id=p_user AND chain_id=p_chain FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'controller not found' USING ERRCODE='P0002'; END IF;
 SELECT status INTO v_status FROM private.wallet_bindings
 WHERE user_id=p_user AND chain_id=p_chain AND status IN ('active','suspended') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'binding not found' USING ERRCODE='P0002'; END IF;
 IF v_status='suspended' THEN
   SELECT count(*) INTO v_pending FROM private.wallet_binding_challenges
    WHERE user_id=p_user AND chain_id=p_chain AND status='pending';
   IF v_controller <> 'suspended' OR v_pending <> 0 THEN
     RAISE EXCEPTION 'inconsistent suspended state requires audited recovery' USING ERRCODE='23514';
   END IF;
   RETURN 'already_suspended';
 END IF;
 IF v_epoch>=9223372036854775806 THEN RAISE EXCEPTION 'epoch limit' USING ERRCODE='22003'; END IF;
 UPDATE private.wallet_bindings SET status='suspended',suspended_at=clock_timestamp()
 WHERE user_id=p_user AND chain_id=p_chain AND status='active';
 UPDATE private.wallet_binding_state SET epoch=epoch+1,binding_status='suspended',updated_at=clock_timestamp()
 WHERE user_id=p_user AND chain_id=p_chain;
 UPDATE private.wallet_binding_challenges SET status='invalidated'
 WHERE user_id=p_user AND chain_id=p_chain AND status='pending';
 INSERT INTO private.wallet_binding_audit(request_id,actor_ref,object_ref,event_type,result,policy_version)
 VALUES(p_request,p_user::text,p_user::text||':'||p_chain::text,'BINDING_SUSPENDED','success','B2.3-R1-lab');
 RETURN 'suspended';
END $f$;
REVOKE ALL ON FUNCTION private.b23_suspend(uuid,uuid,bigint,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION private.b23_suspend(uuid,uuid,bigint,uuid) FROM b23_runtime;
COMMIT;

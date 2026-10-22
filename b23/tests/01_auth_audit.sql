\set ON_ERROR_STOP on
BEGIN;
DO $t$
DECLARE u uuid:=gen_random_uuid(); other_u uuid:=gen_random_uuid(); s uuid:=gen_random_uuid(); w bytea:=decode(repeat('12',20),'hex'); d bytea:=decode(repeat('ab',32),'hex'); n bytea:=decode(repeat('cd',32),'hex'); a int; v text;
BEGIN
 INSERT INTO private.wallet_binding_state(user_id,chain_id,binding_status) VALUES(u,1,'active');
 INSERT INTO b23_auth_sim.sessions(session_id,user_id) VALUES(s,u);
 INSERT INTO private.wallet_bindings(binding_id,user_id,chain_id,wallet_address,epoch,consent_version,consent_digest,scopes)
 VALUES(gen_random_uuid(),u,1,w,0,'B2.3',d,ARRAY['bind:wallet']);
 INSERT INTO private.wallet_binding_challenges(user_id,chain_id,wallet_address,nonce_hash,epoch,auth_session_id,auth_generation,domain,uri,siwe_message_digest,consent_digest,consent_version,scopes,expires_at)
 VALUES(u,1,w,n,0,s,0,'example.test','https://example.test',d,d,'B2.3',ARRAY['bind:wallet'],clock_timestamp()+interval '4 minutes');
 BEGIN
  PERFORM private.b23_suspend(other_u,s,1,gen_random_uuid());
  RAISE EXCEPTION 'foreign profile accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 v := private.b23_suspend(u,s,1,gen_random_uuid());
 IF v<>'suspended' THEN RAISE EXCEPTION 'unexpected status'; END IF;
 IF (SELECT status FROM private.wallet_bindings WHERE user_id=u)<>'suspended' THEN RAISE EXCEPTION 'binding not suspended'; END IF;
 IF (SELECT epoch FROM private.wallet_binding_state WHERE user_id=u)<>1 THEN RAISE EXCEPTION 'epoch not advanced'; END IF;
 IF (SELECT status FROM private.wallet_binding_challenges WHERE user_id=u)<>'invalidated' THEN RAISE EXCEPTION 'pending challenge not invalidated'; END IF;
 SELECT count(*) INTO a FROM private.wallet_binding_audit WHERE actor_ref=u::text AND event_type='BINDING_SUSPENDED';
 IF a<>1 THEN RAISE EXCEPTION 'audit not atomic'; END IF;
 IF private.b23_suspend(u,s,1,gen_random_uuid()) <> 'already_suspended' THEN RAISE EXCEPTION 'not idempotent'; END IF;
 IF (SELECT count(*) FROM private.wallet_binding_audit WHERE actor_ref=u::text)<>1 THEN RAISE EXCEPTION 'duplicate audit'; END IF;
 UPDATE b23_auth_sim.sessions SET revoked_at=clock_timestamp() WHERE session_id=s;
 BEGIN
  PERFORM private.b23_suspend(u,s,1,gen_random_uuid());
  RAISE EXCEPTION 'revoked session accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 RAISE NOTICE 'PASS B2.3 local simulated session, suspension, epoch, invalidation, audit, repeat, revoked denial';
END $t$;
ROLLBACK;

\set ON_ERROR_STOP on
BEGIN;
DO $t$
DECLARE u1 uuid:=gen_random_uuid(); u2 uuid:=gen_random_uuid(); w bytea:=decode(repeat('11',20),'hex'); d bytea:=decode(repeat('aa',32),'hex'); n bytea:=decode(repeat('bb',32),'hex'); cnt int;
BEGIN
 INSERT INTO private.wallet_binding_state(user_id,chain_id) VALUES(u1,1),(u2,1);
 INSERT INTO private.wallet_bindings(binding_id,user_id,chain_id,wallet_address,epoch,consent_version,consent_digest,scopes)
 VALUES(gen_random_uuid(),u1,1,w,0,'B2.2',d,ARRAY['bind:wallet']);
 BEGIN
  INSERT INTO private.wallet_bindings(binding_id,user_id,chain_id,wallet_address,epoch,consent_version,consent_digest,scopes)
  VALUES(gen_random_uuid(),u2,1,w,0,'B2.2',d,ARRAY['bind:wallet']);
  RAISE EXCEPTION 'duplicate wallet erroneously permitted';
 EXCEPTION WHEN unique_violation THEN NULL; END;
 UPDATE private.wallet_bindings SET status='suspended',suspended_at=clock_timestamp() WHERE user_id=u1;
 BEGIN
  INSERT INTO private.wallet_bindings(binding_id,user_id,chain_id,wallet_address,epoch,consent_version,consent_digest,scopes)
  VALUES(gen_random_uuid(),u2,1,w,0,'B2.2',d,ARRAY['bind:wallet']);
  RAISE EXCEPTION 'suspended wallet erroneously released';
 EXCEPTION WHEN unique_violation THEN NULL; END;
 INSERT INTO private.wallet_binding_challenges(user_id,chain_id,wallet_address,nonce_hash,epoch,auth_session_id,auth_generation,domain,uri,siwe_message_digest,consent_digest,consent_version,scopes,expires_at)
 VALUES(u1,1,w,n,0,gen_random_uuid(),0,'example.test','https://example.test',d,d,'B2.2',ARRAY['bind:wallet'],clock_timestamp()+interval '4 minutes');
 BEGIN
  INSERT INTO private.wallet_binding_challenges(user_id,chain_id,wallet_address,nonce_hash,epoch,auth_session_id,auth_generation,domain,uri,siwe_message_digest,consent_digest,consent_version,scopes,expires_at)
  VALUES(u2,1,w,n,0,gen_random_uuid(),0,'example.test','https://example.test',d,d,'B2.2',ARRAY['bind:wallet'],clock_timestamp()+interval '4 minutes');
  RAISE EXCEPTION 'nonce reuse erroneously permitted';
 EXCEPTION WHEN unique_violation THEN NULL; END;
 SELECT count(*) INTO cnt FROM pg_class c JOIN pg_namespace s ON s.oid=c.relnamespace WHERE s.nspname='private' AND c.relrowsecurity AND c.relname IN ('wallet_binding_state','wallet_binding_challenges','wallet_bindings','wallet_recovery_cases','wallet_binding_audit');
 IF cnt<>5 THEN RAISE EXCEPTION 'RLS not enabled on all five tables'; END IF;
 RAISE NOTICE 'PASS: base uniqueness, suspended reservation, nonce uniqueness, RLS enablement';
END $t$;
ROLLBACK;

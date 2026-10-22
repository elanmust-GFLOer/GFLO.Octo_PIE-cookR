\set ON_ERROR_STOP on
BEGIN;
-- Runtime cannot enumerate simulator and cannot call legacy suspension even if schema is usable.
GRANT USAGE ON SCHEMA private,b23_auth_sim TO b23_untrusted;
DO $t$
DECLARE u uuid:=gen_random_uuid();s uuid:=gen_random_uuid();
BEGIN
 IF has_function_privilege('b23_runtime','private.b23_suspend(uuid,uuid,bigint,uuid)','EXECUTE')
 THEN RAISE EXCEPTION 'runtime still allowed to suspend'; END IF;
 IF has_table_privilege('b23_runtime','b23_auth_sim.sessions','SELECT')
 THEN RAISE EXCEPTION 'runtime still allowed to enumerate sessions'; END IF;
 IF has_function_privilege('b23_untrusted','private.b23_suspend(uuid,uuid,bigint,uuid)','EXECUTE')
 THEN RAISE EXCEPTION 'untrusted still allowed to execute'; END IF;
 IF has_function_privilege('b23_runtime','private.b23r1_issue_challenge(uuid,bigint,bytea,bytea,uuid,bytea,bytea)','EXECUTE')
 THEN RAISE EXCEPTION 'runtime can issue via lab function'; END IF;
 IF has_table_privilege('b23_runtime','private.wallet_binding_challenges','INSERT')
 THEN RAISE EXCEPTION 'runtime can insert challenges'; END IF;
 RAISE NOTICE 'PASS: R1 runtime denies sensitive operations';
END $t$;
ROLLBACK;

BEGIN;
DO $t$
DECLARE u uuid:=gen_random_uuid();s uuid:=gen_random_uuid(); w bytea:=decode(repeat('12',20),'hex');
 d bytea:=decode(repeat('ab',32),'hex'); n bytea:=decode(repeat('cd',32),'hex'); ch uuid;
BEGIN
 INSERT INTO private.wallet_binding_state(user_id,chain_id,binding_status) VALUES(u,1,'unbound');
 ch:=private.b23r1_issue_challenge(u,1,w,n,s,d,d);
 IF ch IS NULL THEN RAISE EXCEPTION 'expected challenge'; END IF;
 UPDATE private.wallet_binding_state SET binding_status='suspended' WHERE user_id=u AND chain_id=1;
 BEGIN
  PERFORM private.b23r1_issue_challenge(u,1,w,decode(repeat('ee',32),'hex'),s,d,d);
  RAISE EXCEPTION 'suspended issuance erroneously succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 RAISE NOTICE 'PASS: lifecycle guard rejects suspended challenge issuance';
END $t$;
ROLLBACK;

BEGIN;
DO $t$
DECLARE u uuid:=gen_random_uuid();s uuid:=gen_random_uuid();w bytea:=decode(repeat('24',20),'hex');d bytea:=decode(repeat('ba',32),'hex');
BEGIN
 INSERT INTO private.wallet_binding_state(user_id,chain_id,binding_status) VALUES(u,1,'active');
 INSERT INTO b23_auth_sim.sessions(session_id,user_id) VALUES(s,u);
 INSERT INTO private.wallet_bindings(binding_id,user_id,chain_id,wallet_address,epoch,consent_version,consent_digest,scopes,status,suspended_at)
 VALUES(gen_random_uuid(),u,1,w,0,'B2.3-R1',d,ARRAY['bind:wallet'],'suspended',clock_timestamp());
 BEGIN
  PERFORM private.b23_suspend(u,s,1,gen_random_uuid());
  RAISE EXCEPTION 'inconsistent suspended binding treated as success';
 EXCEPTION WHEN check_violation THEN NULL; END;
 RAISE NOTICE 'PASS: inconsistent pre-suspended data rejected';
END $t$;
ROLLBACK;

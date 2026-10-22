\set ON_ERROR_STOP on
BEGIN;
-- Full table DML privileges for known non-authoritative roles.
DO $x$
DECLARE role_name text; table_name text; priv text;
BEGIN
 FOREACH role_name IN ARRAY ARRAY['b23_runtime','b23_untrusted','b23r3_lab_caller','b23r5_app_probe'] LOOP
  FOREACH table_name IN ARRAY ARRAY[
    'private.wallet_binding_state','private.wallet_binding_challenges',
    'private.wallet_bindings','private.wallet_recovery_cases',
    'private.wallet_binding_audit','private.b23r3_requests',
    'b23_auth_sim.sessions'
  ] LOOP
   FOREACH priv IN ARRAY ARRAY['INSERT','UPDATE','DELETE','TRUNCATE'] LOOP
    IF has_table_privilege(role_name,table_name,priv) THEN
     RAISE EXCEPTION 'R5 matrix: % still has % on %', role_name,priv,table_name;
    END IF;
   END LOOP;
  END LOOP;
  IF pg_has_role(role_name,'b23r3_data_owner','MEMBER') OR pg_has_role(role_name,'b23r3_mutator','MEMBER') OR pg_has_role(role_name,'b23r3_mutator','USAGE') THEN
   RAISE EXCEPTION 'R5 matrix: privilege assumption remains for %',role_name;
  END IF;
 END LOOP;
 RAISE NOTICE 'PASS R5 full table DML + membership matrix 4 roles x 7 tables';
END $x$;
ROLLBACK;

BEGIN;
-- A user armed with the complete victim identifiers is still refused at the RPC ACL;
-- the lab function itself remains unsafe if that grant were restored.
-- Genuine A/B fixtures; no grant is restored, even inside this transaction.
INSERT INTO private.wallet_binding_state(user_id,chain_id,binding_status) VALUES
 ('00000000-0000-4000-8000-000000000001',1,'active'),
 ('00000000-0000-4000-8000-000000000010',1,'active');
INSERT INTO b23_auth_sim.sessions(session_id,user_id) VALUES
 ('00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000001'),
 ('00000000-0000-4000-8000-000000000011','00000000-0000-4000-8000-000000000010');
INSERT INTO private.wallet_bindings(binding_id,user_id,chain_id,wallet_address,epoch,consent_version,consent_digest,scopes) VALUES
 ('00000000-0000-4000-8000-000000000003','00000000-0000-4000-8000-000000000001',1,decode(repeat('a1',20),'hex'),0,'R6A-fixture',decode(repeat('a1',32),'hex'),ARRAY['bind:wallet']),
 ('00000000-0000-4000-8000-000000000012','00000000-0000-4000-8000-000000000010',1,decode(repeat('b1',20),'hex'),0,'R6A-fixture',decode(repeat('b1',32),'hex'),ARRAY['bind:wallet']);
DO $x$ BEGIN
 IF has_function_privilege('b23r3_lab_caller',
 'private.b23r3_suspend_lab(uuid,uuid,bigint,uuid,bigint,uuid,bytea)','EXECUTE') THEN
  RAISE EXCEPTION 'R6A independent ACL oracle failed';
 END IF;
 IF (SELECT count(*) FROM b23_auth_sim.sessions WHERE session_id IN
 ('00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000011'))<>2 THEN
  RAISE EXCEPTION 'R6A A/B fixtures missing';
 END IF;
END $x$;
SET LOCAL ROLE b23r3_lab_caller;
DO $x$
BEGIN
 BEGIN
  PERFORM private.b23r3_suspend_lab(
   '00000000-0000-4000-8000-000000000010'::uuid,
   '00000000-0000-4000-8000-000000000011'::uuid,1,
   '00000000-0000-4000-8000-000000000012'::uuid,0,
   '00000000-0000-4000-8000-000000000013'::uuid,
   decode(repeat('ff',32),'hex'));
  RAISE EXCEPTION 'R5 known victim tuple reached suspended endpoint';
 EXCEPTION WHEN insufficient_privilege THEN
  IF SQLERRM <> 'permission denied for function b23r3_suspend_lab' THEN
   RAISE EXCEPTION 'wrong denial oracle: %',SQLERRM;
  END IF;
 END;
 RAISE NOTICE 'PASS R5 victim identifier RPC ACL denied for lab role';
END $x$;
ROLLBACK;

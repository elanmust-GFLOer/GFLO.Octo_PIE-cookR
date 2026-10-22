\set ON_ERROR_STOP on
BEGIN;
DO $t$
DECLARE v text; r text; f text;
BEGIN
 FOREACH r IN ARRAY ARRAY['b23_runtime','b23_untrusted','b23r3_lab_caller','b23r5_app_probe'] LOOP
  IF has_function_privilege(r,'private.b23_suspend(uuid,uuid,bigint,uuid)','EXECUTE')
   OR has_function_privilege(r,'private.b23r3_suspend_lab(uuid,uuid,bigint,uuid,bigint,uuid,bytea)','EXECUTE')
   OR has_function_privilege(r,'private.b23r1_issue_challenge(uuid,bigint,bytea,bytea,uuid,bytea,bytea)','EXECUTE')
  THEN RAISE EXCEPTION 'unsafe EXECUTE remains for %',r; END IF;
  IF has_table_privilege(r,'private.wallet_bindings','INSERT')
   OR has_table_privilege(r,'private.wallet_bindings','UPDATE')
   OR has_table_privilege(r,'private.wallet_bindings','DELETE')
   OR has_table_privilege(r,'private.wallet_binding_audit','INSERT')
   OR has_table_privilege(r,'b23_auth_sim.sessions','SELECT')
  THEN RAISE EXCEPTION 'unsafe DML/SELECT remains for %',r; END IF;
  IF pg_has_role(r,'b23r3_data_owner','MEMBER') OR pg_has_role(r,'b23r3_mutator','MEMBER')
  THEN RAISE EXCEPTION 'role escalation through membership for %',r; END IF;
 END LOOP;
 RAISE NOTICE 'PASS R5: four untrusted/lab caller roles denied RPC, binding DML, session enumeration, elevated role membership';
END $t$;
SET LOCAL ROLE b23r5_app_probe;
DO $t$
BEGIN
 BEGIN
  PERFORM private.b23r3_suspend_lab(gen_random_uuid(),gen_random_uuid(),1,gen_random_uuid(),0,gen_random_uuid(),decode(repeat('aa',32),'hex'));
  RAISE EXCEPTION 'R5 app probe unexpectedly executed definer';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 RAISE NOTICE 'PASS R5: schema usage granted but EXECUTE denied';
END $t$;
ROLLBACK;

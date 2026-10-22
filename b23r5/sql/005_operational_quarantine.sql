-- B2.3-R5 LAB-ONLY quarantine. Applies after B2.3-R3. Never run on production.
DO $g$ BEGIN
 IF current_database() NOT LIKE 'b2test\_%' ESCAPE '\' OR current_setting('gflo.b2_disposable_ok',true) IS DISTINCT FROM 'YES'
 THEN RAISE EXCEPTION 'R5 refuses non-disposable database'; END IF;
END $g$;
BEGIN;
CREATE ROLE b23r5_app_probe NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA private TO b23r5_app_probe;
-- The lab caller has a known forged-principal flaw. Remove the capability,
-- rather than pretending its caller-supplied identity is authoritative.
REVOKE EXECUTE ON FUNCTION private.b23r3_suspend_lab(uuid,uuid,bigint,uuid,bigint,uuid,bytea) FROM b23r3_lab_caller;
REVOKE ALL ON FUNCTION private.b23r3_suspend_lab(uuid,uuid,bigint,uuid,bigint,uuid,bytea) FROM PUBLIC,b23_runtime,b23_untrusted,b23r5_app_probe;
REVOKE EXECUTE ON FUNCTION private.b23_suspend(uuid,uuid,bigint,uuid) FROM PUBLIC,b23_runtime,b23_untrusted,b23r3_lab_caller,b23r5_app_probe;
REVOKE EXECUTE ON FUNCTION private.b23r1_issue_challenge(uuid,bigint,bytea,bytea,uuid,bytea,bytea) FROM PUBLIC,b23_runtime,b23_untrusted,b23r3_lab_caller,b23r5_app_probe;
REVOKE ALL ON private.wallet_binding_state,private.wallet_binding_challenges,private.wallet_bindings,private.wallet_recovery_cases,private.wallet_binding_audit,private.b23r3_requests FROM b23r5_app_probe,b23r3_lab_caller,b23_runtime,b23_untrusted;
REVOKE ALL ON b23_auth_sim.sessions FROM b23r5_app_probe,b23r3_lab_caller,b23_runtime,b23_untrusted;
COMMIT;

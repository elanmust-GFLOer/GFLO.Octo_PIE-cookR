\set ON_ERROR_STOP on
BEGIN;
SET LOCAL ROLE b23_untrusted;
DO $t$ BEGIN
 BEGIN
  PERFORM private.b23_suspend(gen_random_uuid(),gen_random_uuid(),1,gen_random_uuid());
  RAISE EXCEPTION 'untrusted RPC execute succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
  PERFORM 1 FROM private.wallet_bindings LIMIT 1;
  RAISE EXCEPTION 'untrusted table read succeeded';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 RAISE NOTICE 'PASS B2.3 direct role denial';
END $t$;
ROLLBACK;

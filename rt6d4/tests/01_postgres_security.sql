\set ON_ERROR_STOP on
\echo RT6D4-01 verifying isolated schema RLS, role ACLs and default functions
DO $$
BEGIN
 IF (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
     WHERE n.nspname='gflo_bridge' AND c.relkind='r' AND c.relrowsecurity) != 3 THEN
   RAISE EXCEPTION 'FAIL: RLS not enabled on all three tables'; END IF;
 IF has_schema_privilege('authenticated','gflo_bridge','USAGE') OR
    has_schema_privilege('anon','gflo_bridge','USAGE') OR
    has_function_privilege('anon','gflo_bridge.record_reviewed_event(uuid,uuid,uuid,uuid,text,text,uuid,text)','EXECUTE') OR
    has_function_privilege('authenticated','gflo_bridge.lease_next_event(integer)','EXECUTE') OR
    has_function_privilege('gflo_rt_worker','gflo_bridge.record_reviewed_event(uuid,uuid,uuid,uuid,text,text,uuid,text)','EXECUTE') OR
    has_table_privilege('gflo_rt_ingest','gflo_bridge.source_events','INSERT') THEN
   RAISE EXCEPTION 'FAIL: excessive privilege'; END IF;
END $$;
\echo RT6D4-02 anonymous and authenticated cannot view or forge source rows
SET ROLE authenticated;
DO $$ BEGIN
  BEGIN
    PERFORM * FROM gflo_bridge.source_events;
    RAISE EXCEPTION 'FAIL: browser role read source table';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  BEGIN
    PERFORM gflo_bridge.record_reviewed_event(
      '00000000-0000-0000-0000-000000000001'::uuid,
      '00000000-0000-0000-0000-000000000101'::uuid,
      '00000000-0000-0000-0000-000000000201'::uuid,
      '00000000-0000-0000-0000-000000000301'::uuid,
      'r1','0x'||repeat('a',64),
      '00000000-0000-0000-0000-000000000401'::uuid,'nonce-001');
    RAISE EXCEPTION 'FAIL: browser role forged reviewed event';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
SET ROLE anon;
DO $$ BEGIN
  BEGIN
    PERFORM * FROM gflo_bridge.attestation_outbox;
    RAISE EXCEPTION 'FAIL: anon viewed outbox';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
\echo RT6D4-03 ingester cannot directly mutate tables; function creates atomic triplet
SET ROLE gflo_rt_ingest;
DO $$ BEGIN
  BEGIN
    INSERT INTO gflo_bridge.source_events(event_id,subject_user_id,project_id,task_id,source_revision,evidence_digest,reviewer_user_id)
    VALUES ('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000102',
      '00000000-0000-0000-0000-000000000202','00000000-0000-0000-0000-000000000302',
      'r2','0x'||repeat('b',64),'00000000-0000-0000-0000-000000000402');
    RAISE EXCEPTION 'FAIL: ingester bypassed function';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
SELECT gflo_bridge.record_reviewed_event(
 '00000000-0000-0000-0000-000000000001',
 '00000000-0000-0000-0000-000000000101',
 '00000000-0000-0000-0000-000000000201',
 '00000000-0000-0000-0000-000000000301',
 'r1','0x'||repeat('a',64),
 '00000000-0000-0000-0000-000000000401','nonce-001');
RESET ROLE;
DO $$ BEGIN
 IF (SELECT count(*) FROM gflo_bridge.source_events)!=1 OR
    (SELECT count(*) FROM gflo_bridge.attestation_outbox)!=1 OR
    (SELECT count(*) FROM gflo_bridge.used_source_keys)!=3 THEN
  RAISE EXCEPTION 'FAIL: event+replay+outbox not atomic'; END IF;
END $$;
\echo RT6D4-04 duplicate nonce / evidence / revision aborts entire statement
SET ROLE gflo_rt_ingest;
DO $$ BEGIN
  BEGIN
    PERFORM gflo_bridge.record_reviewed_event(
      '00000000-0000-0000-0000-000000000002',
      '00000000-0000-0000-0000-000000000102',
      '00000000-0000-0000-0000-000000000202',
      '00000000-0000-0000-0000-000000000302',
      'r2','0x'||repeat('b',64),
      '00000000-0000-0000-0000-000000000402','nonce-001');
    RAISE EXCEPTION 'FAIL: reused nonce permitted';
  EXCEPTION WHEN unique_violation THEN NULL; END;
  BEGIN
    PERFORM gflo_bridge.record_reviewed_event(
      '00000000-0000-0000-0000-000000000003',
      '00000000-0000-0000-0000-000000000103',
      '00000000-0000-0000-0000-000000000203',
      '00000000-0000-0000-0000-000000000303',
      'r3','0x'||repeat('a',64),
      '00000000-0000-0000-0000-000000000403','nonce-003');
    RAISE EXCEPTION 'FAIL: reused evidence accepted';
  EXCEPTION WHEN unique_violation THEN NULL; END;
  BEGIN
    PERFORM gflo_bridge.record_reviewed_event(
      '00000000-0000-0000-0000-000000000004',
      '00000000-0000-0000-0000-000000000104',
      '00000000-0000-0000-0000-000000000204',
      '00000000-0000-0000-0000-000000000301',
      'r1','0x'||repeat('d',64),
      '00000000-0000-0000-0000-000000000404','nonce-004');
    RAISE EXCEPTION 'FAIL: duplicate task revision accepted';
  EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF (SELECT count(*) FROM gflo_bridge.source_events)!=1 OR
    (SELECT count(*) FROM gflo_bridge.attestation_outbox)!=1 OR
    (SELECT count(*) FROM gflo_bridge.used_source_keys)!=3 THEN
  RAISE EXCEPTION 'FAIL: replay error left partial state'; END IF;
END $$;
\echo RT6D4-05 self-review is refused by DB constraint
SET ROLE gflo_rt_ingest;
DO $$ BEGIN
  BEGIN
    PERFORM gflo_bridge.record_reviewed_event(
      '00000000-0000-0000-0000-000000000005',
      '00000000-0000-0000-0000-000000000105',
      '00000000-0000-0000-0000-000000000205',
      '00000000-0000-0000-0000-000000000305',
      'r5','0x'||repeat('e',64),
      '00000000-0000-0000-0000-000000000105','nonce-005');
    RAISE EXCEPTION 'FAIL: self review succeeded';
  EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
\echo RT6D4-06 worker cannot forge event and leasing yields one fencing token
SET ROLE gflo_rt_worker;
DO $$ BEGIN
  BEGIN
    PERFORM gflo_bridge.record_reviewed_event(
      '00000000-0000-0000-0000-000000000006',
      '00000000-0000-0000-0000-000000000106',
      '00000000-0000-0000-0000-000000000206',
      '00000000-0000-0000-0000-000000000306',
      'r6','0x'||repeat('f',64),
      '00000000-0000-0000-0000-000000000406','nonce-006');
    RAISE EXCEPTION 'FAIL: worker forged event';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
SELECT outbox_id AS leased_outbox,lease_token AS leased_token,attempt_count AS leased_attempt
  FROM gflo_bridge.lease_next_event(60) \gset
SELECT 1 / CASE WHEN :'leased_token'::uuid IS NOT NULL AND :'leased_attempt'::int = 1 THEN 1 ELSE 0 END;
-- Pending row must no longer be available to another worker.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM gflo_bridge.lease_next_event(60)) THEN
  RAISE EXCEPTION 'FAIL: leased a non-expired row twice'; END IF;
END $$;
RESET ROLE;
\echo RT6D4-07 stale token cannot ACK and live token succeeds only once
SET ROLE gflo_rt_worker;
SELECT 1 / CASE WHEN NOT gflo_bridge.mark_ready(:'leased_outbox'::uuid,'00000000-0000-0000-0000-000000000999'::uuid)
 THEN 1 ELSE 0 END;
SELECT 1 / CASE WHEN gflo_bridge.mark_ready(:'leased_outbox'::uuid,:'leased_token'::uuid)
 THEN 1 ELSE 0 END;
SELECT 1 / CASE WHEN NOT gflo_bridge.mark_ready(:'leased_outbox'::uuid,:'leased_token'::uuid)
 THEN 1 ELSE 0 END;
RESET ROLE;
DO $$ BEGIN
 IF (SELECT count(*) FROM gflo_bridge.attestation_outbox WHERE state='ready')!=1 OR
    (SELECT count(*) FROM gflo_bridge.attestation_outbox WHERE state='pending')!=0 THEN
   RAISE EXCEPTION 'FAIL: outbox status incorrect'; END IF;
END $$;
\echo RT6D4-08 lease expiry is reclaimable; stale token cannot ACK after reclaim
SET ROLE gflo_rt_ingest;
SELECT gflo_bridge.record_reviewed_event(
 '00000000-0000-0000-0000-000000000008',
 '00000000-0000-0000-0000-000000000108',
 '00000000-0000-0000-0000-000000000208',
 '00000000-0000-0000-0000-000000000308',
 'r8','0x'||repeat('8',64),
 '00000000-0000-0000-0000-000000000408','nonce-008');
RESET ROLE;
SET ROLE gflo_rt_worker;
SELECT outbox_id AS expiring_outbox,lease_token AS original_token
FROM gflo_bridge.lease_next_event(10) \gset
RESET ROLE;
-- Test owner simulates clock passage without a 10 second wall-clock delay.
UPDATE gflo_bridge.attestation_outbox SET leased_until=clock_timestamp()-interval '1 second'
WHERE outbox_id=:'expiring_outbox'::uuid;
SET ROLE gflo_rt_worker;
SELECT lease_token AS renewed_token,attempt_count AS renewed_attempt
FROM gflo_bridge.lease_next_event(60) \gset
SELECT 1 / CASE WHEN :'original_token'::uuid <> :'renewed_token'::uuid
 AND :'renewed_attempt'::integer=2 THEN 1 ELSE 0 END;
SELECT 1 / CASE WHEN NOT gflo_bridge.mark_ready(:'expiring_outbox'::uuid,:'original_token'::uuid)
 THEN 1 ELSE 0 END;
SELECT 1 / CASE WHEN gflo_bridge.mark_ready(:'expiring_outbox'::uuid,:'renewed_token'::uuid)
 THEN 1 ELSE 0 END;
RESET ROLE;
\echo RT6D4-09 no EIP-712 proof or XP was created by bridge DB
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='gflo_bridge' AND table_name IN ('signed_proofs','xp_grants')) THEN
   RAISE EXCEPTION 'FAIL: bridge unexpectedly has XP writer tables'; END IF;
END $$;
\echo RT6D4 9/9 logical security groups passed (SQL script assertions)

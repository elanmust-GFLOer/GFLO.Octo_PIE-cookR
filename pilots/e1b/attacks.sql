\set ON_ERROR_STOP on
-- Admin-only synthetic seed, not a production identity mapping.
INSERT INTO e1b.projects(id,owner_id) VALUES('GFLOProject0001','gflo:person:alpha');
INSERT INTO e1b.reviewers(id,active) VALUES('gflo:person:reviewer',true),('gflo:person:disabled',false);
DO $$
BEGIN
 IF has_function_privilege('e1b_browser','e1b.server_issue_review(text,text,integer,text,text)','EXECUTE')
 THEN RAISE EXCEPTION 'BROWSER_CAN_EXECUTE'; END IF;
 IF has_table_privilege('e1b_browser','e1b.review_events','INSERT') OR
    has_table_privilege('e1b_browser','e1b.review_events','UPDATE') OR
    has_table_privilege('e1b_browser','e1b.review_events','DELETE')
 THEN RAISE EXCEPTION 'BROWSER_CAN_MUTATE_EVENTS'; END IF;
 IF has_table_privilege('e1b_review_service','e1b.review_events','INSERT')
 THEN RAISE EXCEPTION 'SERVICE_HAS_DIRECT_INSERT'; END IF;
END $$;
SET ROLE e1b_browser;
UPDATE e1b.projects SET status='launched' WHERE id='GFLOProject0001';
RESET ROLE;
DO $$
BEGIN
 IF (SELECT status FROM e1b.projects WHERE id='GFLOProject0001')<>'launched' OR
 EXISTS(SELECT 1 FROM e1b.review_events) THEN RAISE EXCEPTION 'BROWSER_STATUS_LEAKED_TO_PROOF'; END IF;
END $$;
-- Probe actual browser DML and EXECUTE, not just grants.
SET ROLE e1b_browser;
DO $$ BEGIN
 BEGIN
  INSERT INTO e1b.review_events(event_id,project_id,revision,owner_id,reviewer_id,issuer_id,type,evidence_digest,issued_at)
  VALUES('fake_event_12345','GFLOProject0001',1,'gflo:person:alpha','gflo:person:reviewer','octopush:review-issuer','builder.reviewed',repeat('a',64),1);
  RAISE EXCEPTION 'BROWSER_INSERT_BYPASS';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
  PERFORM e1b.server_issue_review('GFLOProject0001','gflo:person:reviewer',1,repeat('a',64),'APPROVED');
  RAISE EXCEPTION 'BROWSER_RPC_BYPASS';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
-- Authenticated service invokes restricted RPC; owner/self and inactive reviewers fail.
SET ROLE e1b_review_service;
DO $$ BEGIN
 BEGIN
  PERFORM e1b.server_issue_review('GFLOProject0001','gflo:person:alpha',1,repeat('a',64),'APPROVED');
  RAISE EXCEPTION 'SELF_REVIEW_BYPASS';
 EXCEPTION WHEN raise_exception THEN
  IF SQLERRM='SELF_REVIEW_BYPASS' THEN RAISE; END IF; END;
 BEGIN
  PERFORM e1b.server_issue_review('GFLOProject0001','gflo:person:disabled',1,repeat('a',64),'APPROVED');
  RAISE EXCEPTION 'INACTIVE_REVIEWER_BYPASS';
 EXCEPTION WHEN raise_exception THEN
  IF SQLERRM='INACTIVE_REVIEWER_BYPASS' THEN RAISE; END IF; END;
END $$;
SELECT e1b.server_issue_review('GFLOProject0001','gflo:person:reviewer',1,repeat('a',64),'APPROVED') AS event_id;
DO $$ BEGIN
 BEGIN
  PERFORM e1b.server_issue_review('GFLOProject0001','gflo:person:reviewer',1,repeat('a',64),'APPROVED');
  RAISE EXCEPTION 'REPLAY_BYPASS';
 EXCEPTION WHEN raise_exception THEN
  IF SQLERRM='REPLAY_BYPASS' THEN RAISE; END IF; END;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF (SELECT count(*) FROM e1b.review_decisions)<>1 OR (SELECT count(*) FROM e1b.review_events)<>1
 THEN RAISE EXCEPTION 'ATOMICITY_INVARIANT'; END IF;
 IF (SELECT event_id FROM e1b.review_events LIMIT 1) !~ '^review_event_[0-9a-f]{32}$'
 THEN RAISE EXCEPTION 'EVENT_ID_INVALID'; END IF;
END $$;
SET ROLE e1b_reader;
SELECT event_id,project_id,reviewer_id,issuer_id,type,evidence_digest FROM e1b.review_events;
RESET ROLE;
\echo E1B_POSTGRES_PRIVILEGE_ATOMIC_EVENT_LAB_PASS

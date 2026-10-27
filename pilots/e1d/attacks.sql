\set ON_ERROR_STOP on
-- E1-D isolated mock of PostgREST's browser/database role, NOT live JWT security.
DO $$
BEGIN
 IF has_table_privilege('e1b_browser','e1b.projects','TRUNCATE') OR has_table_privilege('e1b_browser','e1b.projects','TRIGGER')
 THEN RAISE EXCEPTION 'BROWSER_OVERPRIVILEGED_PROJECTS'; END IF;
 IF has_table_privilege('e1b_browser','e1b.review_decisions','SELECT')
 THEN RAISE EXCEPTION 'BROWSER_CAN_READ_REVIEW_DECISIONS'; END IF;
 IF has_table_privilege('e1b_browser','e1b.review_events','DELETE') OR has_table_privilege('e1b_browser','e1b.review_events','UPDATE')
 THEN RAISE EXCEPTION 'BROWSER_CAN_EDIT_PROOFS'; END IF;
END $$;
SET ROLE e1b_browser;
DO $$
BEGIN
 BEGIN
  EXECUTE 'TRUNCATE e1b.projects CASCADE';
  RAISE EXCEPTION 'BROWSER_TRUNCATE_BYPASS';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
  EXECUTE 'UPDATE e1b.review_events SET evidence_digest=repeat(''f'',64)';
  RAISE EXCEPTION 'BROWSER_PROOF_TAMPER_BYPASS';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
  EXECUTE 'DELETE FROM e1b.review_events';
  RAISE EXCEPTION 'BROWSER_PROOF_DELETE_BYPASS';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
  EXECUTE 'SELECT * FROM e1b.reviewers';
  RAISE EXCEPTION 'BROWSER_REVIEW_ROLE_ENUM_BYPASS';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
-- The synthetic Builder status can change, but must not alter the recorded proof.
DO $$
BEGIN
 IF (SELECT status FROM e1b.projects WHERE id='GFLOProject0001') <> 'launched'
 THEN RAISE EXCEPTION 'USER_WORKFLOW_REGRESSION'; END IF;
 IF (SELECT count(*) FROM e1b.review_events) <> 1
 THEN RAISE EXCEPTION 'EVENT_INTEGRITY_REGRESSION'; END IF;
END $$;
\echo E1D_STAGING_ACL_NEGATIVE_TEST_PASS

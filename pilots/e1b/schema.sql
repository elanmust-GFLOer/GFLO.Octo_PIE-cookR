-- E1-B isolated PostgreSQL laboratory ONLY; never apply to live Supabase.
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='e1b_browser') THEN CREATE ROLE e1b_browser NOLOGIN; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='e1b_review_service') THEN CREATE ROLE e1b_review_service NOLOGIN; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='e1b_reader') THEN CREATE ROLE e1b_reader NOLOGIN; END IF;
END $$;
CREATE SCHEMA IF NOT EXISTS e1b;
REVOKE ALL ON SCHEMA e1b FROM PUBLIC;
GRANT USAGE ON SCHEMA e1b TO e1b_browser,e1b_reader,e1b_review_service;
CREATE TABLE e1b.projects(
 id text PRIMARY KEY, owner_id text NOT NULL, status text NOT NULL DEFAULT 'idea',
 revision integer NOT NULL DEFAULT 1,
 CHECK(id ~ '^[a-zA-Z0-9_-]{12,128}$'),
 CHECK(owner_id ~ '^gflo:person:[a-z0-9:_-]{4,128}$')
);
CREATE TABLE e1b.reviewers(
 id text PRIMARY KEY, active boolean NOT NULL DEFAULT false,
 CHECK(id ~ '^gflo:person:[a-z0-9:_-]{4,128}$')
);
CREATE TABLE e1b.review_decisions(
 project_id text NOT NULL REFERENCES e1b.projects(id),
 revision integer NOT NULL,
 reviewer_id text NOT NULL REFERENCES e1b.reviewers(id),
 decision text NOT NULL CHECK(decision IN('APPROVED','REJECTED')),
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[0-9a-f]{64}$'),
 decided_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 PRIMARY KEY(project_id,revision)
);
CREATE TABLE e1b.review_events(
 event_id text PRIMARY KEY,
 project_id text NOT NULL,
 revision integer NOT NULL,
 owner_id text NOT NULL,
 reviewer_id text NOT NULL,
 issuer_id text NOT NULL,
 type text NOT NULL CHECK(type='builder.reviewed'),
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[0-9a-f]{64}$'),
 issued_at bigint NOT NULL,
 UNIQUE(project_id,revision),
 FOREIGN KEY(project_id,revision) REFERENCES e1b.review_decisions(project_id,revision)
);
REVOKE ALL ON ALL TABLES IN SCHEMA e1b FROM PUBLIC,e1b_browser,e1b_reader,e1b_review_service;
GRANT SELECT ON e1b.projects TO e1b_browser,e1b_reader;
GRANT UPDATE(status) ON e1b.projects TO e1b_browser; -- legacy user workflow only (lab role shared)
GRANT SELECT ON e1b.review_events TO e1b_reader;
ALTER TABLE e1b.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE e1b.reviewers ENABLE ROW LEVEL SECURITY;
ALTER TABLE e1b.review_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE e1b.review_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY project_browser_read ON e1b.projects FOR SELECT TO e1b_browser USING(true);
CREATE POLICY project_reader_read ON e1b.projects FOR SELECT TO e1b_reader USING(true);
CREATE POLICY project_browser_status ON e1b.projects FOR UPDATE TO e1b_browser USING(true) WITH CHECK(true);
CREATE POLICY event_reader_read ON e1b.review_events FOR SELECT TO e1b_reader USING(true);
-- No policy or direct DML grant for browser roles on review decisions or events.
CREATE OR REPLACE FUNCTION e1b.server_issue_review(
 p_project text,p_reviewer text,p_revision integer,p_evidence text,p_decision text
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,e1b
AS $$
DECLARE v_owner text;v_revision integer;v_id text;
BEGIN
 -- This function is callable ONLY by an independently authenticated server role.
 -- Server must independently bind p_reviewer to the authenticated reviewer session.
 IF p_decision<>'APPROVED' OR p_evidence !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'INVALID_REVIEW'; END IF;
 SELECT owner_id,revision INTO v_owner,v_revision FROM e1b.projects WHERE id=p_project FOR UPDATE;
 IF NOT FOUND OR v_revision<>p_revision THEN RAISE EXCEPTION 'REVISION_MISMATCH'; END IF;
 IF p_reviewer=v_owner OR NOT EXISTS(SELECT 1 FROM e1b.reviewers WHERE id=p_reviewer AND active)
 THEN RAISE EXCEPTION 'REVIEWER_UNAUTHORIZED'; END IF;
 IF EXISTS(SELECT 1 FROM e1b.review_decisions WHERE project_id=p_project AND revision=p_revision)
 THEN RAISE EXCEPTION 'DUPLICATE_REVIEW'; END IF;
 INSERT INTO e1b.review_decisions(project_id,revision,reviewer_id,decision,evidence_digest)
 VALUES(p_project,p_revision,p_reviewer,p_decision,p_evidence);
 v_id='review_event_'||replace(gen_random_uuid()::text,'-','');
 INSERT INTO e1b.review_events(event_id,project_id,revision,owner_id,reviewer_id,issuer_id,type,evidence_digest,issued_at)
 VALUES(v_id,p_project,p_revision,v_owner,p_reviewer,'octopush:review-issuer','builder.reviewed',p_evidence,extract(epoch from statement_timestamp())::bigint);
 RETURN v_id;
END $$;
REVOKE ALL ON FUNCTION e1b.server_issue_review(text,text,integer,text,text) FROM PUBLIC,e1b_browser,e1b_reader;
GRANT EXECUTE ON FUNCTION e1b.server_issue_review(text,text,integer,text,text) TO e1b_review_service;
COMMIT;

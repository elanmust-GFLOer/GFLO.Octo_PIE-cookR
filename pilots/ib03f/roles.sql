-- GFLO IB-03F isolated PostgreSQL 16 RBAC admission facade.
-- SECURITY DEFINER is only acceptable with sealed search_path + reviewed owner.
BEGIN;
CREATE ROLE gflo_admission_lab LOGIN PASSWORD 'lab-service-only' NOINHERIT;
CREATE ROLE gflo_browser_lab LOGIN PASSWORD 'lab-browser-only' NOINHERIT;
CREATE SCHEMA ib03f;
REVOKE ALL ON SCHEMA ib03d2 FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA ib03d2 FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ib03d2 FROM PUBLIC;
GRANT USAGE ON SCHEMA ib03d2 TO gflo_admission_lab;
GRANT USAGE ON SCHEMA ib03f TO gflo_admission_lab;
CREATE FUNCTION ib03f.lookup_challenge(p_nonce text)
RETURNS TABLE(id text,subject_id text,wallet text,chain_id bigint,domain text,expires_at timestamptz,nonce text,proof_digest text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT c.id,c.subject_id,c.wallet,c.chain_id,c.domain,c.expires_at,c.id,c.proof_digest
 FROM ib03d2.challenges c WHERE c.id=p_nonce AND c.consumed_at IS NULL AND c.expires_at>clock_timestamp();
$$;
CREATE FUNCTION ib03f.issue_session(p_challenge text,p_subject text,p_chain bigint,p_wallet text,p_digest text,p_session text,p_bg bigint,p_cg bigint,p_ttl integer)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT ib03d2.issue_verified_session(p_challenge,p_subject,p_chain,p_wallet,p_digest,p_session,p_bg,p_cg,p_ttl);
$$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ib03f FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ib03f.lookup_challenge(text) TO gflo_admission_lab;
GRANT EXECUTE ON FUNCTION ib03f.issue_session(text,text,bigint,text,text,text,bigint,bigint,integer) TO gflo_admission_lab;
COMMIT;

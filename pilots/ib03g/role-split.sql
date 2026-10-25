-- IB-03G: isolated PostgreSQL attested admission. NOT a production migration.
-- Security boundary: separate verifier and admission roles. Signature is verified by
-- the isolated verifier process BEFORE it invokes register_verification.
BEGIN;
CREATE ROLE gflo_verifier_lab LOGIN PASSWORD 'lab-verifier-only' NOINHERIT;
CREATE SCHEMA ib03g;
REVOKE ALL ON SCHEMA ib03g FROM PUBLIC;
GRANT USAGE ON SCHEMA ib03g TO gflo_verifier_lab, gflo_admission_lab;
CREATE TABLE ib03g.verified_proofs (
 challenge_id text PRIMARY KEY REFERENCES ib03d2.challenges(id),
 subject_id text NOT NULL, chain_id bigint NOT NULL, wallet text NOT NULL,
 proof_digest text NOT NULL, expires_at timestamptz NOT NULL,
 consumed_at timestamptz
);
REVOKE ALL ON ALL TABLES IN SCHEMA ib03g FROM PUBLIC;
-- Kill IB-03F bypass before granting the new attested path.
REVOKE EXECUTE ON FUNCTION ib03f.issue_session(text,text,bigint,text,text,text,bigint,bigint,integer) FROM gflo_admission_lab;
CREATE FUNCTION ib03g.register_verification(
 p_challenge text,p_subject text,p_chain bigint,p_wallet text,p_digest text
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c ib03d2.challenges%ROWTYPE;
BEGIN
 SELECT * INTO c FROM ib03d2.challenges WHERE id=p_challenge FOR UPDATE;
 IF NOT FOUND OR c.consumed_at IS NOT NULL OR c.expires_at<=clock_timestamp()
 OR c.subject_id<>p_subject OR c.chain_id<>p_chain OR c.wallet<>p_wallet
 OR c.proof_digest<>p_digest THEN RETURN false; END IF;
 INSERT INTO ib03g.verified_proofs(challenge_id,subject_id,chain_id,wallet,proof_digest,expires_at)
 VALUES(c.id,c.subject_id,c.chain_id,c.wallet,c.proof_digest,least(c.expires_at,clock_timestamp()+interval '2 minutes'))
 ON CONFLICT DO NOTHING;
 RETURN FOUND;
END $$;
CREATE FUNCTION ib03g.redeem_verified_session(
 p_challenge text,p_subject text,p_chain bigint,p_wallet text,p_digest text,
 p_session text,p_bg bigint,p_cg bigint,p_ttl integer
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a ib03g.verified_proofs%ROWTYPE;issued boolean;
BEGIN
 SELECT * INTO a FROM ib03g.verified_proofs WHERE challenge_id=p_challenge FOR UPDATE;
 IF NOT FOUND OR a.consumed_at IS NOT NULL OR a.expires_at<=clock_timestamp()
 OR a.subject_id<>p_subject OR a.chain_id<>p_chain OR a.wallet<>p_wallet
 OR a.proof_digest<>p_digest THEN RETURN false; END IF;
 SELECT ib03d2.issue_verified_session(p_challenge,p_subject,p_chain,p_wallet,p_digest,p_session,p_bg,p_cg,p_ttl) INTO issued;
 IF issued IS DISTINCT FROM true THEN RETURN false; END IF;
 UPDATE ib03g.verified_proofs SET consumed_at=clock_timestamp() WHERE challenge_id=p_challenge;
 RETURN true;
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ib03g FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ib03g.register_verification(text,text,bigint,text,text) TO gflo_verifier_lab;
GRANT EXECUTE ON FUNCTION ib03g.redeem_verified_session(text,text,bigint,text,text,text,bigint,bigint,integer) TO gflo_admission_lab;
COMMIT;

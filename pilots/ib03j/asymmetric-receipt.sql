-- GFLO IB-03J: Ed25519 verifier-receipt to transactional PostgreSQL session; CI-only.
-- PostgreSQL pgcrypto does not verify Ed25519; verifier-role compromise is NOT solved.
BEGIN;
CREATE SCHEMA ib03j;
REVOKE ALL ON SCHEMA ib03j FROM PUBLIC;
GRANT USAGE ON SCHEMA ib03j TO gflo_verifier_lab,gflo_admission_lab;
CREATE TABLE ib03j.keys (
 key_id text PRIMARY KEY,
 public_spki text NOT NULL,
 active boolean NOT NULL DEFAULT true,
 generation bigint NOT NULL DEFAULT 1
);
CREATE TABLE ib03j.receipts (
 challenge_id text PRIMARY KEY REFERENCES ib03d2.challenges(id),
 key_id text NOT NULL REFERENCES ib03j.keys(key_id),
 key_generation bigint NOT NULL,
 subject_id text NOT NULL, chain_id bigint NOT NULL, wallet text NOT NULL,
 digest text NOT NULL, session_id text NOT NULL,
 binding_generation bigint NOT NULL,consent_generation bigint NOT NULL,
 expires_at timestamptz NOT NULL,signature text NOT NULL,
 consumed_at timestamptz
);
REVOKE ALL ON ALL TABLES IN SCHEMA ib03j FROM PUBLIC;
-- Remove all previously demonstrated legacy application ingress functions.
REVOKE EXECUTE ON FUNCTION ib03h.issue_attested_session(text,text,bigint,text,text,text,bigint,bigint,integer,bigint,text,text) FROM gflo_admission_lab;
REVOKE EXECUTE ON FUNCTION ib03g.redeem_verified_session(text,text,bigint,text,text,text,bigint,bigint,integer) FROM gflo_admission_lab;
REVOKE EXECUTE ON FUNCTION ib03g.register_verification(text,text,bigint,text,text) FROM gflo_verifier_lab;
REVOKE EXECUTE ON FUNCTION ib03f.issue_session(text,text,bigint,text,text,text,bigint,bigint,integer) FROM gflo_admission_lab;
-- Public key read is allowed only through a narrow function to verifier role.
CREATE FUNCTION ib03j.verifier_key(p_key text)
RETURNS TABLE(public_spki text,generation bigint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT k.public_spki,k.generation FROM ib03j.keys k
 WHERE k.key_id=p_key AND k.active=true
$$;
CREATE FUNCTION ib03j.register_receipt(
 p_challenge text,p_keyid text,p_key_generation bigint,p_subject text,p_chain bigint,
 p_wallet text,p_digest text,p_session text,p_bg bigint,p_cg bigint,
 p_expires bigint,p_signature text
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c ib03d2.challenges%ROWTYPE;k ib03j.keys%ROWTYPE;
BEGIN
 IF p_signature !~ '^[A-Za-z0-9_-]{80,100}$'
 OR p_digest !~ '^[0-9a-f]{64}$' OR p_wallet !~ '^0x[0-9A-Fa-f]{40}$'
 OR p_session !~ '^[A-Za-z0-9_-]{16,128}$'
 OR p_expires <= extract(epoch from clock_timestamp())::bigint
 OR p_expires > extract(epoch from clock_timestamp())::bigint+120 THEN RETURN false; END IF;
 SELECT * INTO k FROM ib03j.keys WHERE key_id=p_keyid FOR SHARE;
 IF NOT FOUND OR NOT k.active OR k.generation<>p_key_generation THEN RETURN false; END IF;
 SELECT * INTO c FROM ib03d2.challenges WHERE id=p_challenge FOR UPDATE;
 IF NOT FOUND OR c.consumed_at IS NOT NULL OR c.expires_at<=clock_timestamp()
 OR c.subject_id<>p_subject OR c.chain_id<>p_chain OR c.wallet<>p_wallet
 OR c.proof_digest<>p_digest THEN RETURN false; END IF;
 INSERT INTO ib03j.receipts(challenge_id,key_id,key_generation,subject_id,chain_id,wallet,digest,
 session_id,binding_generation,consent_generation,expires_at,signature)
 VALUES(p_challenge,p_keyid,p_key_generation,p_subject,p_chain,p_wallet,p_digest,
 p_session,p_bg,p_cg,to_timestamp(p_expires),p_signature)
 ON CONFLICT DO NOTHING;
 RETURN FOUND;
END $$;
CREATE FUNCTION ib03j.redeem_receipt(p_challenge text,p_session text,p_ttl integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r ib03j.receipts%ROWTYPE;k ib03j.keys%ROWTYPE; issued boolean;
BEGIN
 SELECT * INTO r FROM ib03j.receipts WHERE challenge_id=p_challenge FOR UPDATE;
 IF NOT FOUND OR r.consumed_at IS NOT NULL OR r.expires_at<=clock_timestamp()
 OR r.session_id<>p_session THEN RETURN false; END IF;
 SELECT * INTO k FROM ib03j.keys WHERE key_id=r.key_id FOR SHARE;
 IF NOT FOUND OR NOT k.active OR k.generation<>r.key_generation THEN RETURN false; END IF;
 SELECT ib03d2.issue_verified_session(r.challenge_id,r.subject_id,r.chain_id,r.wallet,r.digest,
 r.session_id,r.binding_generation,r.consent_generation,p_ttl) INTO issued;
 IF issued IS DISTINCT FROM true THEN RETURN false; END IF;
 UPDATE ib03j.receipts SET consumed_at=clock_timestamp() WHERE challenge_id=r.challenge_id;
 RETURN true;
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ib03j FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ib03j.verifier_key(text) TO gflo_verifier_lab;
GRANT EXECUTE ON FUNCTION ib03j.register_receipt(text,text,bigint,text,bigint,text,text,text,bigint,bigint,bigint,text) TO gflo_verifier_lab;
GRANT EXECUTE ON FUNCTION ib03j.redeem_receipt(text,text,integer) TO gflo_admission_lab;
COMMIT;

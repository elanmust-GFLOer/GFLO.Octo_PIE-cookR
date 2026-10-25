-- GFLO IB-03K: verifier-compromise mitigation by a separate public-key enforcer.
-- PostgreSQL itself still does not perform Ed25519 verification.
BEGIN;
CREATE ROLE gflo_enforcer_lab LOGIN PASSWORD 'lab-enforcer-only' NOINHERIT;
CREATE SCHEMA ib03k;
REVOKE ALL ON SCHEMA ib03k FROM PUBLIC;
GRANT USAGE ON SCHEMA ib03k TO gflo_enforcer_lab;
GRANT USAGE ON SCHEMA ib03j TO gflo_enforcer_lab;
REVOKE EXECUTE ON FUNCTION ib03j.redeem_receipt(text,text,integer) FROM gflo_admission_lab;
GRANT EXECUTE ON FUNCTION ib03j.redeem_receipt(text,text,integer) TO gflo_enforcer_lab;
-- Only enforcer can look up evidence and the public key, and must validate signature.
CREATE FUNCTION ib03k.read_for_enforcement(p_challenge text)
RETURNS TABLE(
 challenge_id text,key_id text,key_generation bigint,subject_id text,chain_id bigint,
 wallet text,digest text,session_id text,binding_generation bigint,
 consent_generation bigint,expiry_epoch bigint,signature text,public_key_hex text
) LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT r.challenge_id,r.key_id,r.key_generation,r.subject_id,r.chain_id,
 r.wallet,r.digest,r.session_id,r.binding_generation,r.consent_generation,
 extract(epoch from r.expires_at)::bigint,r.signature,
 encode(convert_to(k.public_spki,'UTF8'),'hex')
 FROM ib03j.receipts r JOIN ib03j.keys k ON k.key_id=r.key_id
 WHERE r.challenge_id=p_challenge AND r.consumed_at IS NULL AND k.active
 AND k.generation=r.key_generation AND r.expires_at>clock_timestamp()
$$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ib03k FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ib03k.read_for_enforcement(text) TO gflo_enforcer_lab;
COMMIT;

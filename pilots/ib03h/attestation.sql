-- GFLO IB-03H: isolated HMAC-SHA256 attestation gate; disposable PG16 only.
BEGIN;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA ib03h;
REVOKE ALL ON SCHEMA ib03h FROM PUBLIC;
GRANT USAGE ON SCHEMA ib03h TO gflo_admission_lab;
CREATE TABLE ib03h.attestation_keys (key_id text PRIMARY KEY, key_bytes bytea NOT NULL CHECK(octet_length(key_bytes)=32), active boolean NOT NULL DEFAULT true);
REVOKE ALL ON ib03h.attestation_keys FROM PUBLIC;
-- The IB03G unsigned attestation is no longer authorized.
REVOKE EXECUTE ON FUNCTION ib03g.register_verification(text,text,bigint,text,text) FROM gflo_verifier_lab;
REVOKE EXECUTE ON FUNCTION ib03g.redeem_verified_session(text,text,bigint,text,text,text,bigint,bigint,integer) FROM gflo_admission_lab;
-- Canonical payload is restricted to separator-free ASCII fields: no JSON/Unicode ambiguity.
CREATE FUNCTION ib03h.issue_attested_session(
 p_challenge text,p_subject text,p_chain bigint,p_wallet text,p_digest text,
 p_session text,p_bg bigint,p_cg bigint,p_ttl integer,p_expires bigint,p_keyid text,p_mac text
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE k bytea;payload text;expect_mac text;issued boolean;
BEGIN
 IF p_challenge !~ '^[A-Za-z0-9_-]{8,128}$' OR p_subject !~ '^[A-Za-z0-9_-]{1,128}$' OR
 p_wallet !~ '^0x[0-9A-Fa-f]{40}$' OR p_digest !~ '^[0-9a-f]{64}$' OR
 p_session !~ '^[A-Za-z0-9_-]{16,128}$' OR p_keyid !~ '^[A-Za-z0-9_-]{1,64}$' OR
 p_mac !~ '^[0-9a-f]{64}$' OR p_chain<1 OR p_bg<1 OR p_cg<1 OR
 p_ttl<1 OR p_ttl>3600 OR p_expires<extract(epoch from clock_timestamp())::bigint OR
 p_expires>extract(epoch from clock_timestamp())::bigint+120 THEN RETURN false; END IF;
 SELECT key_bytes INTO k FROM ib03h.attestation_keys WHERE key_id=p_keyid AND active=true;
 IF NOT FOUND THEN RETURN false; END IF;
 payload=concat_ws('|','GFLO_IB03H_V1',p_keyid,p_challenge,p_subject,p_chain::text,lower(p_wallet),p_digest,p_session,p_bg::text,p_cg::text,p_ttl::text,p_expires::text);
 expect_mac=encode(public.hmac(convert_to(payload,'UTF8'),k,'sha256'),'hex');
 IF expect_mac<>p_mac THEN RETURN false; END IF;
 SELECT ib03d2.issue_verified_session(p_challenge,p_subject,p_chain,p_wallet,p_digest,p_session,p_bg,p_cg,p_ttl) INTO issued;
 RETURN issued IS TRUE;
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ib03h FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ib03h.issue_attested_session(text,text,bigint,text,text,text,bigint,bigint,integer,bigint,text,text) TO gflo_admission_lab;
COMMIT;

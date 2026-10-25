-- IB-03L isolated PostgreSQL 16: atomic HMAC admission gate.
-- The DB verifies HMAC, NOT Ed25519. The signing service remains trusted.
BEGIN;
CREATE SCHEMA ib03l;
REVOKE ALL ON SCHEMA ib03l FROM PUBLIC;
GRANT USAGE ON SCHEMA ib03l TO gflo_enforcer_lab;
CREATE TABLE ib03l.keys(kid text PRIMARY KEY,secret bytea NOT NULL CHECK(octet_length(secret)=32),enabled boolean NOT NULL DEFAULT true,epoch bigint NOT NULL DEFAULT 1);
REVOKE ALL ON ib03l.keys FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION ib03j.redeem_receipt(text,text,integer) FROM gflo_enforcer_lab;
CREATE FUNCTION ib03l.admit(
 challenge text,subject text,chain bigint,wallet text,digest text,session text,
 binding_gen bigint,consent_gen bigint,ttl integer,expires bigint,kid text,key_epoch bigint,mac text
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE k ib03l.keys%ROWTYPE; body text; expected text; issued boolean; now_s bigint;
BEGIN
 now_s=extract(epoch from clock_timestamp())::bigint;
 IF challenge !~ '^[A-Za-z0-9_-]{8,128}$'
 OR subject !~ '^[A-Za-z0-9_-]{1,128}$'
 OR wallet !~ '^0x[0-9a-f]{40}$'
 OR digest !~ '^[0-9a-f]{64}$'
 OR session !~ '^[A-Za-z0-9_-]{16,128}$'
 OR kid !~ '^[A-Za-z0-9_-]{1,64}$'
 OR mac !~ '^[0-9a-f]{64}$'
 OR chain<1 OR binding_gen<1 OR consent_gen<1
 OR ttl<1 OR ttl>600 OR expires<=now_s OR expires>now_s+90 THEN
 RETURN false;
 END IF;
 SELECT * INTO k FROM ib03l.keys WHERE keys.kid=admit.kid FOR SHARE;
 IF NOT FOUND OR NOT k.enabled OR k.epoch<>key_epoch THEN RETURN false; END IF;
 body=concat_ws('|','GFLO_IB03L_V1',kid,key_epoch,challenge,subject,chain,
 wallet,digest,session,binding_gen,consent_gen,ttl,expires);
 expected=encode(public.hmac(convert_to(body,'UTF8'),k.secret,'sha256'),'hex');
 IF expected<>mac THEN RETURN false; END IF;
 SELECT ib03d2.issue_verified_session(challenge,subject,chain,wallet,digest,session,
 binding_gen,consent_gen,ttl) INTO issued;
 RETURN issued IS TRUE;
END $$;
REVOKE ALL ON FUNCTION ib03l.admit(text,text,bigint,text,text,text,bigint,bigint,integer,bigint,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ib03l.admit(text,text,bigint,text,text,text,bigint,bigint,integer,bigint,text,bigint,text) TO gflo_enforcer_lab;
COMMIT;

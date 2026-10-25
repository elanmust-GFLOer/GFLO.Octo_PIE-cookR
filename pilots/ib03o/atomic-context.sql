-- IB-03O: DB re-verifies immutable SIWE context and HMAC in same transaction.
-- Disposable PG16 ONLY. Owner is still a trusted root. Not Ed25519.
BEGIN;
CREATE SCHEMA ib03o;
REVOKE ALL ON SCHEMA ib03o FROM PUBLIC;
GRANT USAGE ON SCHEMA ib03o TO gflo_enforcer_lab;
-- Deliberately revoke prior HMAC route and earlier paths.
REVOKE EXECUTE ON FUNCTION ib03l.admit(text,text,bigint,text,text,text,bigint,bigint,integer,bigint,text,bigint,text) FROM gflo_enforcer_lab;
REVOKE EXECUTE ON FUNCTION ib03j.redeem_receipt(text,text,integer) FROM gflo_enforcer_lab;
CREATE FUNCTION ib03o.admit_atomic(
 p_challenge text,p_subject text,p_chain bigint,p_wallet text,p_digest text,
 p_session text,p_bg bigint,p_cg bigint,p_ttl integer,p_exp bigint,p_kid text,p_epoch bigint,p_mac text
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
 k ib03l.keys%ROWTYPE;
 c ib03n.context%ROWTYPE;
 n ib03d2.challenges%ROWTYPE;
 payload text;mac text;issued boolean;
 now_s bigint;issued_s bigint;context_end bigint;
BEGIN
 now_s=extract(epoch from clock_timestamp())::bigint;
 IF p_challenge !~ '^[A-Za-z0-9]{8,128}$' OR
 p_subject !~ '^[A-Za-z0-9_-]{1,128}$' OR
 p_wallet !~ '^0x[0-9a-f]{40}$' OR
 p_digest !~ '^[0-9a-f]{64}$' OR
 p_session !~ '^[A-Za-z0-9_-]{16,128}$' OR
 p_kid !~ '^[A-Za-z0-9_-]{1,64}$' OR
 p_mac !~ '^[0-9a-f]{64}$' OR
 p_chain<1 OR p_bg<1 OR p_cg<1 OR p_ttl<1 OR p_ttl>600 OR
 p_epoch<1 OR p_exp<=now_s OR p_exp>now_s+60 THEN RETURN false; END IF;
 -- Read canonical challenge and frozen context in this exact DB transaction.
 SELECT * INTO c FROM ib03n.context WHERE challenge_id=p_challenge FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO n FROM ib03d2.challenges WHERE id=p_challenge FOR UPDATE;
 IF NOT FOUND OR n.consumed_at IS NOT NULL OR n.expires_at<=clock_timestamp() THEN RETURN false; END IF;
 issued_s=extract(epoch from c.issued_at)::bigint;
 context_end=extract(epoch from c.expires_at)::bigint;
 IF c.expires_at<=clock_timestamp() OR c.issued_at>clock_timestamp()
 OR c.subject_id<>p_subject OR c.wallet<>p_wallet OR c.chain_id<>p_chain OR
 c.message_digest<>p_digest OR c.binding_generation<>p_bg OR c.consent_generation<>p_cg OR
 c.scope<>'pie:xp:read' OR
 n.subject_id<>c.subject_id OR n.wallet<>c.wallet OR n.chain_id<>c.chain_id OR
 n.domain<>c.domain OR n.proof_digest<>c.message_digest OR
 n.expires_at<c.expires_at OR c.domain !~ '^[A-Za-z0-9.-]+(:[0-9]{1,5})?$'
 OR c.uri !~ '^https://' OR c.uri ~ '[|[:cntrl:]]' THEN RETURN false; END IF;
 -- MAC key is never exposed to application roles.
 SELECT * INTO k FROM ib03l.keys WHERE kid=p_kid FOR SHARE;
 IF NOT FOUND OR NOT k.enabled OR k.epoch<>p_epoch THEN RETURN false; END IF;
 payload=concat_ws('|','GFLO_IB03O_V1',p_kid,p_epoch,p_challenge,p_subject,p_chain,
 p_wallet,p_digest,p_session,p_bg,p_cg,p_ttl,p_exp,
 c.domain,c.uri,c.scope,issued_s,context_end);
 mac=encode(public.hmac(convert_to(payload,'UTF8'),k.secret,'sha256'),'hex');
 IF mac<>p_mac THEN RETURN false; END IF;
 SELECT ib03d2.issue_verified_session(p_challenge,p_subject,p_chain,p_wallet,p_digest,
 p_session,p_bg,p_cg,p_ttl) INTO issued;
 RETURN issued IS TRUE;
END $$;
REVOKE ALL ON FUNCTION ib03o.admit_atomic(text,text,bigint,text,text,text,bigint,bigint,integer,bigint,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ib03o.admit_atomic(text,text,bigint,text,text,text,bigint,bigint,integer,bigint,text,bigint,text) TO gflo_enforcer_lab;
COMMIT;

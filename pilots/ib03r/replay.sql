-- IB-03R disposable PostgreSQL shared issuer replay and key epoch registry.
BEGIN;
CREATE ROLE gflo_issuer_replay_lab LOGIN PASSWORD 'lab-replay-only' NOINHERIT;
CREATE SCHEMA ib03r;
REVOKE ALL ON SCHEMA ib03r FROM PUBLIC;
GRANT USAGE ON SCHEMA ib03r TO gflo_issuer_replay_lab;
CREATE TABLE ib03r.keys(
 kid text PRIMARY KEY, epoch bigint NOT NULL CHECK(epoch>0),
 active boolean NOT NULL, public_key text NOT NULL
);
CREATE TABLE ib03r.claims(
 kid text NOT NULL, nonce text NOT NULL, epoch bigint NOT NULL,
 expires_at timestamptz NOT NULL,
 claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(kid,nonce)
);
REVOKE ALL ON ALL TABLES IN SCHEMA ib03r FROM PUBLIC;
CREATE FUNCTION ib03r.claim_authenticated_request(p_kid text,p_epoch bigint,p_nonce text,p_exp bigint)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE k ib03r.keys%ROWTYPE;obtained text; now_s bigint;
BEGIN
 now_s=extract(epoch from clock_timestamp())::bigint;
 IF p_kid !~ '^[A-Za-z0-9_-]{1,64}$' OR p_nonce !~ '^[0-9a-f]{32}$'
 OR p_exp<=now_s OR p_exp>now_s+30 THEN RETURN false; END IF;
 SELECT * INTO k FROM ib03r.keys WHERE kid=p_kid FOR SHARE;
 IF NOT FOUND OR NOT k.active OR k.epoch<>p_epoch THEN RETURN false; END IF;
 INSERT INTO ib03r.claims(kid,nonce,epoch,expires_at)
 VALUES(p_kid,p_nonce,p_epoch,to_timestamp(p_exp)) ON CONFLICT DO NOTHING
 RETURNING nonce INTO obtained;
 RETURN obtained IS NOT NULL;
END $$;
CREATE FUNCTION ib03r.active_key(p_kid text)
RETURNS TABLE(epoch bigint,public_key text) LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT k.epoch,k.public_key FROM ib03r.keys k WHERE k.kid=p_kid AND k.active=true
$$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ib03r FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ib03r.active_key(text) TO gflo_issuer_replay_lab;
GRANT EXECUTE ON FUNCTION ib03r.claim_authenticated_request(text,bigint,text,bigint) TO gflo_issuer_replay_lab;
COMMIT;

-- GFLO IB-03D.2: disposable PostgreSQL 16 fixture; NOT a production migration.
BEGIN;
CREATE SCHEMA IF NOT EXISTS ib03d2;
CREATE TABLE ib03d2.challenges (
 id text PRIMARY KEY, subject_id text NOT NULL, wallet text NOT NULL,
 chain_id bigint NOT NULL, domain text NOT NULL, expires_at timestamptz NOT NULL,
 consumed_at timestamptz, proof_digest text NOT NULL
);
CREATE TABLE ib03d2.bindings (
 subject_id text NOT NULL, chain_id bigint NOT NULL, wallet text NOT NULL,
 status text NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED')),
 generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
 PRIMARY KEY(subject_id,chain_id)
);
CREATE TABLE ib03d2.consents (
 subject_id text NOT NULL, chain_id bigint NOT NULL,
 scope text NOT NULL CHECK(scope='pie:xp:read'),
 active boolean NOT NULL, expires_at timestamptz NOT NULL,
 generation bigint NOT NULL DEFAULT 1 CHECK(generation>0),
 PRIMARY KEY(subject_id,chain_id,scope),
 FOREIGN KEY(subject_id,chain_id) REFERENCES ib03d2.bindings(subject_id,chain_id)
);
CREATE TABLE ib03d2.sessions(
 session_id text PRIMARY KEY,subject_id text NOT NULL,chain_id bigint NOT NULL,
 wallet text NOT NULL,expires_at timestamptz NOT NULL,
 revoked boolean NOT NULL DEFAULT false,generation bigint NOT NULL DEFAULT 1,
 FOREIGN KEY(subject_id,chain_id) REFERENCES ib03d2.bindings(subject_id,chain_id)
);
CREATE OR REPLACE FUNCTION ib03d2.consume_challenge(p_id text,p_subject text,p_wallet text,p_digest text)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE got text;
BEGIN
 UPDATE ib03d2.challenges SET consumed_at=clock_timestamp()
 WHERE id=p_id AND subject_id=p_subject AND wallet=p_wallet AND proof_digest=p_digest
 AND consumed_at IS NULL AND expires_at>clock_timestamp()
 RETURNING id INTO got;
 RETURN got IS NOT NULL;
END $$;
CREATE OR REPLACE FUNCTION ib03d2.revoke_consent(p_subject text,p_chain bigint)
RETURNS bigint LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE gen bigint;
BEGIN
 UPDATE ib03d2.consents SET active=false,generation=generation+1
 WHERE subject_id=p_subject AND chain_id=p_chain AND scope='pie:xp:read'
 RETURNING generation INTO gen;
 RETURN gen;
END $$;
CREATE OR REPLACE FUNCTION ib03d2.suspend_binding(p_subject text,p_chain bigint)
RETURNS bigint LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE gen bigint;
BEGIN
 UPDATE ib03d2.bindings SET status='SUSPENDED',generation=generation+1
 WHERE subject_id=p_subject AND chain_id=p_chain RETURNING generation INTO gen;
 UPDATE ib03d2.consents SET active=false,generation=generation+1
 WHERE subject_id=p_subject AND chain_id=p_chain;
 UPDATE ib03d2.sessions SET revoked=true,generation=generation+1
 WHERE subject_id=p_subject AND chain_id=p_chain;
 RETURN gen;
END $$;
-- Fencing decision: consent and binding FOR UPDATE locks held to transaction commit.
-- Revocation must acquire same consent row lock; successful prior decisions linearize first.
CREATE OR REPLACE FUNCTION ib03d2.authorize_read(
 p_session text,p_scope text,p_expected_binding bigint,p_expected_consent bigint
) RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE s ib03d2.sessions%ROWTYPE; b ib03d2.bindings%ROWTYPE; c ib03d2.consents%ROWTYPE;
BEGIN
 IF p_scope<>'pie:xp:read' THEN RETURN false; END IF;
 SELECT * INTO s FROM ib03d2.sessions WHERE session_id=p_session FOR UPDATE;
 IF NOT FOUND OR s.revoked OR s.expires_at<=clock_timestamp() THEN RETURN false; END IF;
 SELECT * INTO b FROM ib03d2.bindings
 WHERE subject_id=s.subject_id AND chain_id=s.chain_id FOR UPDATE;
 IF NOT FOUND OR b.status<>'ACTIVE' OR b.wallet<>s.wallet
 OR b.generation<>p_expected_binding THEN RETURN false; END IF;
 SELECT * INTO c FROM ib03d2.consents
 WHERE subject_id=s.subject_id AND chain_id=s.chain_id AND scope=p_scope FOR UPDATE;
 IF NOT FOUND OR NOT c.active OR c.expires_at<=clock_timestamp()
 OR c.generation<>p_expected_consent THEN RETURN false; END IF;
 RETURN true;
END $$;
REVOKE ALL ON SCHEMA ib03d2 FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA ib03d2 FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ib03d2 FROM PUBLIC;
COMMIT;

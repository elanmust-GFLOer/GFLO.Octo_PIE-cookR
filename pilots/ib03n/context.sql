-- IB-03N disposable PostgreSQL 16 canonical immutable challenge context.
-- Schema-level immutability only against non-owner roles; DB owner is trust root.
BEGIN;
CREATE ROLE gflo_challenge_reader_lab LOGIN PASSWORD 'lab-reader-only' NOINHERIT;
CREATE ROLE gflo_attestation_issuer_lab LOGIN PASSWORD 'lab-issuer-only' NOINHERIT;
CREATE SCHEMA ib03n;
REVOKE ALL ON SCHEMA ib03n FROM PUBLIC;
GRANT USAGE ON SCHEMA ib03n TO gflo_challenge_reader_lab;
CREATE TABLE ib03n.context (
 challenge_id text PRIMARY KEY REFERENCES ib03d2.challenges(id),
 subject_id text NOT NULL,
 wallet text NOT NULL CHECK(wallet ~ '^0x[0-9a-f]{40}$'),
 chain_id bigint NOT NULL CHECK(chain_id>0),
 domain text NOT NULL CHECK(length(domain) BETWEEN 1 AND 255 AND domain !~ '[|[:cntrl:]]'),
 uri text NOT NULL CHECK(length(uri) BETWEEN 1 AND 2048 AND uri !~ '[|[:cntrl:]]'),
 message_digest text NOT NULL CHECK(message_digest ~ '^[0-9a-f]{64}$'),
 scope text NOT NULL CHECK(scope='pie:xp:read'),
 binding_generation bigint NOT NULL CHECK(binding_generation>0),
 consent_generation bigint NOT NULL CHECK(consent_generation>0),
 issued_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '10 minutes'),
 CHECK(challenge_id ~ '^[A-Za-z0-9]{8,128}$')
);
CREATE FUNCTION ib03n.immutable_context() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'IMMUTABLE_CHALLENGE_CONTEXT'; END $$;
CREATE TRIGGER immutable_context BEFORE UPDATE OR DELETE ON ib03n.context
FOR EACH ROW EXECUTE FUNCTION ib03n.immutable_context();
REVOKE ALL ON ALL TABLES IN SCHEMA ib03n FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ib03n FROM PUBLIC;
CREATE FUNCTION ib03n.read_context(p_nonce text)
RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT to_jsonb(c) FROM ib03n.context c
 JOIN ib03d2.challenges n ON n.id=c.challenge_id
 WHERE c.challenge_id=p_nonce
 AND n.consumed_at IS NULL AND n.expires_at>clock_timestamp()
 AND c.expires_at>clock_timestamp()
 AND n.subject_id=c.subject_id AND n.wallet=c.wallet
 AND n.chain_id=c.chain_id AND n.domain=c.domain
 AND n.proof_digest=c.message_digest
$$;
REVOKE ALL ON FUNCTION ib03n.read_context(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ib03n.read_context(text) TO gflo_challenge_reader_lab;
COMMIT;

-- GFLO OctoPass Backend-2 B2.2 — disposable PostgreSQL 16 candidate, NOT a production migration
DO $guard$
BEGIN
 IF current_database() NOT LIKE 'b2test\_%' ESCAPE '\'
    OR current_setting('gflo.b2_disposable_ok', true) IS DISTINCT FROM 'YES'
 THEN RAISE EXCEPTION 'B2.2 refuses non-disposable database or missing acknowledgement'; END IF;
END $guard$;

BEGIN;
CREATE SCHEMA IF NOT EXISTS private;
REVOKE ALL ON SCHEMA private FROM PUBLIC;
CREATE TYPE private.wallet_controller_status AS ENUM ('unbound','active','suspended','revoked','recovery_pending');
CREATE TYPE private.wallet_challenge_status AS ENUM ('pending','consumed','expired','invalidated');
CREATE TYPE private.wallet_binding_status AS ENUM ('active','suspended','revoked');
CREATE TYPE private.wallet_recovery_status AS ENUM ('requested','pending_verification','waiting_period','approved','rejected','completed');

CREATE TABLE private.wallet_binding_state (
 user_id uuid NOT NULL,
 chain_id bigint NOT NULL CHECK (chain_id > 0),
 epoch bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0 AND epoch < 9223372036854775807),
 auth_generation bigint NOT NULL DEFAULT 0 CHECK (auth_generation >= 0 AND auth_generation < 9223372036854775807),
 binding_status private.wallet_controller_status NOT NULL DEFAULT 'unbound',
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 last_revoked_at timestamptz,
 CONSTRAINT wallet_binding_state_pk PRIMARY KEY(user_id,chain_id)
);
CREATE TABLE private.wallet_binding_challenges (
 challenge_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 proposed_binding_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL,
 chain_id bigint NOT NULL,
 wallet_address bytea NOT NULL CHECK (octet_length(wallet_address)=20),
 nonce_hash bytea NOT NULL UNIQUE CHECK (octet_length(nonce_hash)=32),
 epoch bigint NOT NULL CHECK (epoch >= 0),
 auth_session_id uuid NOT NULL,
 auth_generation bigint NOT NULL CHECK (auth_generation >= 0),
 domain text NOT NULL CHECK (length(domain)>0),
 uri text NOT NULL CHECK (length(uri)>0),
 siwe_message_digest bytea NOT NULL CHECK (octet_length(siwe_message_digest)=32),
 consent_digest bytea NOT NULL CHECK (octet_length(consent_digest)=32),
 consent_version text NOT NULL CHECK (length(consent_version)>0),
 scopes text[] NOT NULL CHECK (cardinality(scopes)>0),
 issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 status private.wallet_challenge_status NOT NULL DEFAULT 'pending',
 consumed_at timestamptz,
 CONSTRAINT challenge_state_fk FOREIGN KEY(user_id,chain_id) REFERENCES private.wallet_binding_state(user_id,chain_id),
 CONSTRAINT challenge_ttl_ck CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes'),
 CONSTRAINT challenge_consumption_ck CHECK((status='consumed' AND consumed_at IS NOT NULL)
   OR(status<>'consumed' AND consumed_at IS NULL))
);
CREATE UNIQUE INDEX one_pending_binding_challenge_per_profile_chain
 ON private.wallet_binding_challenges(user_id,chain_id) WHERE status='pending';

CREATE TABLE private.wallet_bindings (
 binding_id uuid PRIMARY KEY,
 user_id uuid NOT NULL,
 chain_id bigint NOT NULL CHECK(chain_id>0),
 wallet_address bytea NOT NULL CHECK(octet_length(wallet_address)=20),
 status private.wallet_binding_status NOT NULL DEFAULT 'active',
 epoch bigint NOT NULL CHECK(epoch>=0),
 consent_version text NOT NULL CHECK(length(consent_version)>0),
 consent_digest bytea NOT NULL CHECK(octet_length(consent_digest)=32),
 scopes text[] NOT NULL CHECK(cardinality(scopes)>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 suspended_at timestamptz,
 revoked_at timestamptz,
 recovery_case_id uuid,
 CONSTRAINT binding_state_fk FOREIGN KEY(user_id,chain_id) REFERENCES private.wallet_binding_state(user_id,chain_id),
 CONSTRAINT binding_status_dates_ck CHECK (
  (status='active' AND suspended_at IS NULL AND revoked_at IS NULL)
  OR (status='suspended' AND suspended_at IS NOT NULL AND revoked_at IS NULL)
  OR (status='revoked' AND revoked_at IS NOT NULL))
);
CREATE UNIQUE INDEX one_reserved_binding_per_profile_chain
 ON private.wallet_bindings(user_id,chain_id) WHERE status IN ('active','suspended');
CREATE UNIQUE INDEX one_reserved_profile_per_wallet_chain
 ON private.wallet_bindings(chain_id,wallet_address) WHERE status IN ('active','suspended');

CREATE TABLE private.wallet_recovery_cases (
 case_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL,
 chain_id bigint NOT NULL,
 old_binding_id uuid NOT NULL REFERENCES private.wallet_bindings(binding_id),
 requested_wallet bytea NOT NULL CHECK(octet_length(requested_wallet)=20),
 recovery_method text NOT NULL,
 step_up_evidence_ref text,
 status private.wallet_recovery_status NOT NULL DEFAULT 'requested',
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 eligible_at timestamptz,
 approved_at timestamptz,
 closed_at timestamptz,
 CONSTRAINT recovery_state_fk FOREIGN KEY(user_id,chain_id) REFERENCES private.wallet_binding_state(user_id,chain_id),
 CONSTRAINT recovery_wait_ck CHECK(eligible_at IS NULL OR eligible_at>=created_at)
);
CREATE UNIQUE INDEX one_open_recovery_per_profile_chain ON private.wallet_recovery_cases(user_id,chain_id)
 WHERE status IN ('requested','pending_verification','waiting_period','approved');
ALTER TABLE private.wallet_bindings ADD CONSTRAINT binding_recovery_case_fk
 FOREIGN KEY(recovery_case_id) REFERENCES private.wallet_recovery_cases(case_id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE private.wallet_binding_audit (
 event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 request_id uuid NOT NULL,
 actor_ref text NOT NULL,
 object_ref text NOT NULL,
 event_type text NOT NULL,
 result text NOT NULL,
 reason_code text,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 policy_version text NOT NULL CHECK(length(policy_version)>0)
);
CREATE INDEX wallet_binding_audit_request_idx ON private.wallet_binding_audit(request_id,occurred_at);
CREATE FUNCTION private.forbid_wallet_audit_rewrite() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN RAISE EXCEPTION 'wallet_binding_audit is append-only'; END $fn$;
REVOKE ALL ON FUNCTION private.forbid_wallet_audit_rewrite() FROM PUBLIC;
CREATE TRIGGER wallet_binding_audit_immutable BEFORE UPDATE OR DELETE
 ON private.wallet_binding_audit FOR EACH ROW EXECUTE FUNCTION private.forbid_wallet_audit_rewrite();

ALTER TABLE private.wallet_binding_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.wallet_binding_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.wallet_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.wallet_recovery_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE private.wallet_binding_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON ALL TABLES IN SCHEMA private FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA private FROM PUBLIC;
COMMIT;

-- GFLO IB-03D.3 disposable PG gate. Requires ledger.sql D.2. Not production migration.
BEGIN;
-- Every same-wallet authorization operation locks binding -> consent -> session.
-- Session issuance additionally locks challenge last.
CREATE OR REPLACE FUNCTION ib03d2.authorize_read(
 p_session text,p_scope text,p_expected_binding bigint,p_expected_consent bigint
) RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE s ib03d2.sessions%ROWTYPE; b ib03d2.bindings%ROWTYPE; c ib03d2.consents%ROWTYPE;
BEGIN
 IF p_scope<>'pie:xp:read' THEN RETURN false; END IF;
 SELECT * INTO s FROM ib03d2.sessions WHERE session_id=p_session;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO b FROM ib03d2.bindings
 WHERE subject_id=s.subject_id AND chain_id=s.chain_id FOR UPDATE;
 IF NOT FOUND OR b.status<>'ACTIVE' OR b.wallet<>s.wallet
 OR b.generation<>p_expected_binding THEN RETURN false; END IF;
 SELECT * INTO c FROM ib03d2.consents
 WHERE subject_id=s.subject_id AND chain_id=s.chain_id AND scope=p_scope FOR UPDATE;
 IF NOT FOUND OR NOT c.active OR c.expires_at<=clock_timestamp()
 OR c.generation<>p_expected_consent THEN RETURN false; END IF;
 SELECT * INTO s FROM ib03d2.sessions WHERE session_id=p_session FOR UPDATE;
 IF NOT FOUND OR s.revoked OR s.expires_at<=clock_timestamp() OR
    s.wallet<>b.wallet OR s.subject_id<>b.subject_id OR s.chain_id<>b.chain_id
 THEN RETURN false; END IF;
 RETURN true;
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

-- Caller MUST prove SIWE EOA/ERC1271 against EXACT challenge outside SQL.
-- Connection role for this function MUST be exclusively the trusted backend.
-- Null/bad challenge/session/consent => entire transaction rolls back, no nonce consumed.
CREATE OR REPLACE FUNCTION ib03d2.issue_verified_session(
 p_challenge text,p_subject text,p_chain bigint,p_wallet text,p_proof_digest text,
 p_session text,p_binding_gen bigint,p_consent_gen bigint,p_session_seconds integer
) RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE b ib03d2.bindings%ROWTYPE;c ib03d2.consents%ROWTYPE;ch ib03d2.challenges%ROWTYPE;got text;
BEGIN
 IF p_session_seconds<1 OR p_session_seconds>3600 OR length(p_session)<16 OR
    p_binding_gen<1 OR p_consent_gen<1 THEN RETURN false; END IF;
 SELECT * INTO b FROM ib03d2.bindings WHERE subject_id=p_subject AND chain_id=p_chain FOR UPDATE;
 IF NOT FOUND OR b.status<>'ACTIVE' OR b.wallet<>p_wallet OR b.generation<>p_binding_gen THEN RETURN false; END IF;
 SELECT * INTO c FROM ib03d2.consents WHERE subject_id=p_subject AND chain_id=p_chain
 AND scope='pie:xp:read' FOR UPDATE;
 IF NOT FOUND OR NOT c.active OR c.expires_at<=clock_timestamp() OR c.generation<>p_consent_gen THEN RETURN false; END IF;
 UPDATE ib03d2.challenges SET consumed_at=clock_timestamp()
 WHERE id=p_challenge AND subject_id=p_subject AND wallet=p_wallet AND chain_id=p_chain
 AND proof_digest=p_proof_digest AND consumed_at IS NULL AND expires_at>clock_timestamp()
 RETURNING id INTO got;
 IF got IS NULL THEN RETURN false; END IF;
 INSERT INTO ib03d2.sessions(session_id,subject_id,chain_id,wallet,expires_at,revoked,generation)
 VALUES(p_session,p_subject,p_chain,p_wallet,least(clock_timestamp() + p_session_seconds * interval '1 second',c.expires_at),false,1);
 RETURN true;
EXCEPTION WHEN unique_violation THEN
 -- PL/pgSQL exception subtransaction rolls back consumed nonce as well.
 RETURN false;
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ib03d2 FROM PUBLIC;
COMMIT;

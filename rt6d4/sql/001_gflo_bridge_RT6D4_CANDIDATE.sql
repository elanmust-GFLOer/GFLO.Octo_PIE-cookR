-- GFLO RT6D.4 REVIEW-ONLY PostgreSQL candidate.
-- NEVER apply to production without owner/role, provenance, audit and migration review.
-- Requires dedicated pre-created service roles gflo_rt_ingest and gflo_rt_worker.
BEGIN;
CREATE SCHEMA gflo_bridge;
REVOKE ALL ON SCHEMA gflo_bridge FROM PUBLIC;
CREATE TABLE gflo_bridge.source_events (
  event_id uuid PRIMARY KEY,
  source_kind text NOT NULL DEFAULT 'octopush.builder.reviewed.v1'
    CHECK(source_kind = 'octopush.builder.reviewed.v1'),
  subject_user_id uuid NOT NULL,
  project_id uuid NOT NULL,
  task_id uuid NOT NULL,
  source_revision text NOT NULL
    CHECK(length(source_revision) BETWEEN 1 AND 100 AND source_revision ~ '^[A-Za-z0-9_.:-]+$'),
  evidence_digest text NOT NULL CHECK(evidence_digest ~ '^0x[0-9a-f]{64}$'),
  reviewer_user_id uuid NOT NULL,
  reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(source_kind,task_id,source_revision),
  CHECK(subject_user_id <> reviewer_user_id)
);
CREATE TABLE gflo_bridge.used_source_keys (
  replay_key text PRIMARY KEY,
  event_id uuid NOT NULL REFERENCES gflo_bridge.source_events(event_id),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE gflo_bridge.attestation_outbox (
  outbox_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid NOT NULL UNIQUE REFERENCES gflo_bridge.source_events(event_id),
  state text NOT NULL DEFAULT 'pending'
    CHECK(state IN ('pending','leased','ready','rejected')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
  lease_token uuid,
  leased_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK((state = 'leased') = (lease_token IS NOT NULL AND leased_until IS NOT NULL))
);
CREATE INDEX rt6d4_outbox_pending_idx ON gflo_bridge.attestation_outbox(state,created_at,outbox_id)
  WHERE state IN ('pending','leased');
ALTER TABLE gflo_bridge.source_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE gflo_bridge.attestation_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE gflo_bridge.used_source_keys ENABLE ROW LEVEL SECURITY;

-- Only a separately authenticated, audited back-end review service may call this.
-- WARNING: no actual OctoPush source lookup/reviewer verification happens inside this prototype.
CREATE FUNCTION gflo_bridge.record_reviewed_event(
  p_event_id uuid, p_subject_user_id uuid, p_project_id uuid, p_task_id uuid,
  p_source_revision text, p_evidence_digest text, p_reviewer_user_id uuid, p_nonce text
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF p_event_id IS NULL OR p_subject_user_id IS NULL OR p_project_id IS NULL OR
     p_task_id IS NULL OR p_reviewer_user_id IS NULL OR
     p_nonce IS NULL OR length(p_nonce) NOT BETWEEN 3 AND 100 OR
     p_nonce !~ '^[A-Za-z0-9_.:-]+$' THEN
    RAISE EXCEPTION 'INVALID_SOURCE_EVENT' USING ERRCODE='23514';
  END IF;
  INSERT INTO gflo_bridge.source_events(event_id,subject_user_id,project_id,task_id,
    source_revision,evidence_digest,reviewer_user_id)
    VALUES(p_event_id,p_subject_user_id,p_project_id,p_task_id,
      p_source_revision,p_evidence_digest,p_reviewer_user_id);
  INSERT INTO gflo_bridge.used_source_keys(replay_key,event_id) VALUES
    ('event:octopush.builder.reviewed.v1:'||p_task_id::text||':'||p_source_revision,p_event_id),
    ('nonce:octopush.builder.reviewed.v1:'||p_nonce,p_event_id),
    ('evidence:'||p_evidence_digest,p_event_id);
  INSERT INTO gflo_bridge.attestation_outbox(event_id) VALUES(p_event_id);
  RETURN p_event_id;
END $$;

-- Lease safely for multiple workers: SKIP LOCKED with a fencing token.
CREATE FUNCTION gflo_bridge.lease_next_event(p_lease_seconds integer DEFAULT 60)
RETURNS TABLE(outbox_id uuid,event_id uuid,lease_token uuid,attempt_count integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 10 AND 300 THEN
    RAISE EXCEPTION 'INVALID_LEASE_WINDOW' USING ERRCODE='23514';
  END IF;
  RETURN QUERY
    WITH next_row AS (
      SELECT q.outbox_id
      FROM gflo_bridge.attestation_outbox q
      WHERE q.state='pending' OR (q.state='leased' AND q.leased_until <= clock_timestamp())
      ORDER BY q.created_at,q.outbox_id
      FOR UPDATE SKIP LOCKED LIMIT 1
    ), moved AS (
      UPDATE gflo_bridge.attestation_outbox q SET
        state='leased',lease_token=gen_random_uuid(),
        leased_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
        attempt_count=q.attempt_count+1,updated_at=clock_timestamp()
      FROM next_row n WHERE q.outbox_id=n.outbox_id
      RETURNING q.outbox_id,q.event_id,q.lease_token,q.attempt_count
    ) SELECT moved.outbox_id,moved.event_id,moved.lease_token,moved.attempt_count FROM moved;
END $$;

-- This ACK is NOT XP authorization and does NOT sign EIP-712 payloads.
CREATE FUNCTION gflo_bridge.mark_ready(p_outbox_id uuid,p_lease_token uuid)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE changed integer;
BEGIN
  UPDATE gflo_bridge.attestation_outbox SET
    state='ready',lease_token=NULL,leased_until=NULL,updated_at=clock_timestamp()
  WHERE outbox_id=p_outbox_id AND state='leased' AND lease_token=p_lease_token
    AND leased_until > clock_timestamp();
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed=1;
END $$;

-- PostgreSQL grants EXECUTE on new functions to PUBLIC unless revoked explicitly.
REVOKE ALL ON SCHEMA gflo_bridge FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA gflo_bridge FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA gflo_bridge FROM PUBLIC;
GRANT USAGE ON SCHEMA gflo_bridge TO gflo_rt_ingest,gflo_rt_worker;
GRANT EXECUTE ON FUNCTION gflo_bridge.record_reviewed_event(uuid,uuid,uuid,uuid,text,text,uuid,text) TO gflo_rt_ingest;
GRANT EXECUTE ON FUNCTION gflo_bridge.lease_next_event(integer) TO gflo_rt_worker;
GRANT EXECUTE ON FUNCTION gflo_bridge.mark_ready(uuid,uuid) TO gflo_rt_worker;
COMMIT;

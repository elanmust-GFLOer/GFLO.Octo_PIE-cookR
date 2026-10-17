# GFLO RED TEAM 6D.4 — Postgres transaction and access-control gate

**Status: review-only / unexecuted in native PostgreSQL as of 2026-10-17.** The creation environment does not have PostgreSQL server, `initdb`, `psql` or Docker; no genuine PostgreSQL success is claimed. The runner script passed `bash -n`, but that is **not** a database test.

## Based on actual 6D.3 draft

The predecessor `001_gflo_source_outbox_DRAFT.sql` established three proposed tables: `gflo_bridge.source_events`, `gflo_bridge.attestation_outbox` and `gflo_bridge.used_source_keys`. The reviewed user-editable OctoPush statuses `project_tasks.status='done'` and `projects.status='launched'` **cannot alone authorize XP**. This 6D.4 candidate preserves those distinctions while adding narrower service functions, transactional insertion, outbox leasing and SQL tests.

## Files

- `sql/001_gflo_bridge_RT6D4_CANDIDATE.sql`: transactional reviewed-event insert + three uniqueness keys + outbox; RLS on all tables, no direct grants, restricted SECURITY DEFINER entrypoints, leased worker with SKIP LOCKED and a one-use fencing token. **Never run in production.**
- `tests/00_disposable_roles.sql`: creates `anon`, `authenticated`, `gflo_rt_ingest` and `gflo_rt_worker` in test DB only. Do not run against Supabase where roles may already exist.
- `tests/01_postgres_security.sql`: nine logical test groups: role segregation, browser direct-write/read denial, function-only ingest, replay atomic rollback, no self-review, worker restrictions, lease fencing and expiry/reclaim, no XP writer.
- `tests/02_concurrency.sh`: two independent PostgreSQL sessions; verifies SKIP LOCKED does not block behind an already locked event and selects a second event.
- `tests/run_ephemeral_postgres.sh`: guardrails to refuse anything except database `rt6d4_*` and explicit `RT6D4_DISPOSABLE_DB_ACK=YES`.
- `.github/workflows/rt6d4-postgres.yml`: optional isolated PostgreSQL 16 CI; archive places this path at repository **root** `.github/workflows/` after extraction.

## How to run (separate disposable Postgres instance, superuser test credentials)

Create and connect to an empty database named `rt6d4_ci`, then:

```bash
export PGHOST=localhost PGPORT=5432 PGUSER=postgres PGDATABASE=rt6d4_ci
export RT6D4_DISPOSABLE_DB_ACK=YES
bash rt6d4/tests/run_ephemeral_postgres.sh
bash rt6d4/tests/02_concurrency.sh
```

The test fixture creates roles using `CREATE ROLE` and SQL functions using `SECURITY DEFINER`, so it **must not** be pointed to a shared or production database. The scripts make persistent DDL changes inside the disposable test DB. Don't use production credentials or read production data.

## Preliminary checks already run

`node --test rt6d4/tests/00_static_gate.test.mjs`: **8/8 static checks PASS**. Shell scripts passed `bash -n`. These do not validate PostgreSQL semantics; PostgreSQL SQL and independent-connection tests remain **NOT RUN** until CI or a disposable PostgreSQL host executes them.

## Mandatory security limitations

1. **Independent review truth is NOT enforced in SQL.** The only ingress is callable by a backend role. A compromised `gflo_rt_ingest` service can fabricate `subject_user_id`, `reviewer_user_id`, `evidence_digest`. `CHECK(subject<>reviewer)` is necessary but not a conflict-of-interest check. Source event provenance, actual reviewer authentication, task/project ownership, wallet link and reviewer conflict checks are still external preconditions.
2. **No XPPolicyV03 access enforced.** Attestor and verifier can still directly submit validly signed fake EIP-712 XP evidence. RT6C HIGH is OPEN; pass at the Postgres gate cannot close it.
3. **`ready` is not signed or on-chain.** Outbox state is explicitly `ready`, not `signed`; there is no signature, broadcast, or on-chain XP award.
4. **The DB and EVM are separate.** `mark_ready` is an idempotent, fenced lease ACK; it does not prove a crash-safe DB→EVM transaction, exactly-once on-chain submission, or source authenticity. Future stage needs transactional outbox with deterministic EVM proof IDs, durable signer receipts, pending/retry/resubmission handling and nullifiers.
5. **Test-role hardening is insufficient for production.** Service role names and production role ownership, credentials, key management, Postgres version, schema search paths, default privileges, migrations and RLS must be reviewed with the actual Supabase identity architecture. PostgreSQL owners and superusers can bypass RLS.
6. **No external DB tested yet** unless a separately reported disposable PostgreSQL 16 run passes. Treat all test expectations as UNVERIFIED until actual output is captured.

## Interpretation

A prospective 10/10 logical test-group result (9 SQL groups + 1 independent-connection race test) from isolated PostgreSQL would show only **DB boundary behavior** in these fixtures. The boundary is a prerequisite, not a security proof, a smart contract audit or an OctoPush production integration.

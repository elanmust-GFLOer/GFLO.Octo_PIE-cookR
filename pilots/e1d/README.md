# E1-D — OctoPush Staging Integration: Auth/RLS Red-Team preflight

## Status: SOURCE + LIVE READ-ONLY INSPECTION; SYNTHETIC PostgreSQL ATTACK TESTS

Date: 2026-10-26. OctoPush Lovable project `fafc7193-490d-4527-be77-4296369a300b`, commit `e5d89445995e2f73c0f954552a17e847934e5ae8`.

### Observed facts (live Supabase system catalogs, SELECT only)
- `public.projects` columns: `id,user_id,name,description,type,status,created_at,updated_at,room_id`.
- RLS project policies: SELECT owner or room member; owner-only INSERT/UPDATE/DELETE for authenticated role.
- No table or public RPC whose name includes `review` or `proof` observed. This does NOT prove there are no other server review implementations.
- `information_schema.role_table_grants` reports `TRUNCATE`, `TRIGGER`, `REFERENCES` privileges for `anon` and `authenticated` on `public.projects`, in addition to standard CRUD. **Risk to investigate:** TRUNCATE operates outside row-level checks. Do not exercise destructive operations on production. This is a privilege listing, not proof of exploitability under the full PostgREST/JWT path.
- OctoPush Builder code issues browser `supabase.from('projects').update({status})`; this status MUST NOT become authoritative builder.reviewed evidence.
- OctoPush `requireSupabaseAuth` authenticates a Supabase bearer via getClaims and yields `context.userId`; admin moderation server functions exist but do not establish dedicated Builder reviewer authentication.

### Design for staging, not migration script against production
1. Clone/synthetic database only. Separate role for project-owner workflow and internal `builder_review_decisions` / append-only `builder_review_events`. No browser DML on proof tables. Do not copy privileged grants from `public.projects` to proof tables.
2. Auth-bound review endpoint: use `context.userId` from validated server middleware; check **server-resolved** reviewer role, project owner mismatch and immutable project revision. Do not accept reviewerId, ownerId or issuerId from request body. Server-derived caller context must bind to database procedure; E1-B currently trusts the service-supplied reviewer ID, so still **BLOCK**.
3. Transactional event issuance, unique project/revision and event ID, replay DB; signing only after successful committed decision and event readback. Durable outbox recommended to avoid missing sign events on process failures.
4. Owner read permissions must be consent scoped; project row-level policy does not imply read authorization for proof event by external agent or PIE.
5. Stage full negative HTTP/PostgREST tests: arbitrary JWT, valid non-reviewer JWT, different project owner, agent identity without grant, self-review, duplicate/concurrent attempts, bypass direct REST and exposed RPC, signed envelope modification, revoke/expiry.
6. Review actual public.projects grants using DB administrator with explicit change approval. Consider targeted revocation of `TRUNCATE`, `TRIGGER` and excessive privileges with an application compatibility test. No live ALTER/REVOKE carried out here.

### Evidence limits
This staging test harness uses PostgreSQL roles and `SET ROLE`, **not** actual Supabase JWT claims / RLS, HTTP PostgREST or live Lovable server functions. It proves isolation in its own synthetic schema, not a production security guarantee.
R1E integrated CI and independent clean-room Codex are still BLOCK. No production migrations, merges or deployments were performed.

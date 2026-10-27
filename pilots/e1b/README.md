# GFLO Pilot E1-B — Server-Attested Builder Event Source

Status: **isolated PostgreSQL & E1-A integration laboratory**, not a deployed OctoPush feature.
Target: `builder.reviewed` is issued by a server-only review pathway after separate reviewer permission checks; never inferred from client-editable `projects.status`.

## Security contract
- Separate review decision vs immutable proof-event tables. One event per (project,revision), with FK to its decision.
- Transaction-atomic approval + event insertion through restricted SECURITY DEFINER procedure, fixed search_path.
- Browser/test roles cannot insert/update/delete review events or call review RPC. Only dedicated server role may execute review procedure; no direct event-table write grants.
- Reviewer active and not the project owner, exact project revision, explicit evidence digest. Duplicate request FAIL.
- E1-A Ed25519 test bridge re-checks issuer, digest and replay (simulation only).

## Evidence limitations — mandatory
- SQL grants are a **labor simulation**, not a live Supabase schema or production JWT/RLS certification. Existing OctoPush tables must not be changed without a separate migration approval.
- SQL procedure accepts `reviewerId` from a trusted server. The app server must authenticate the reviewer session independently and disallow a compromised service from forging the parameter; add integration tests before deployment.
- The procedure currently validates **shape** of evidence digest, NOT objective review validity, external fact correctness, or source-document content.
- SQL uses `e1b_browser` as a synthetic combined user, NOT real owner-scoped Supabase auth. Production RLS must bind `auth.uid()` for projects, prove service-only write access for reviews, and defend direct REST and RPC.
- Ed25519 keys are ephemeral synthetic lab keys; no custody/rotation/KMS, replay DB consumer, wallet/PIE production connection, XP, or live transaction.
- Independent Codex revalidation of PR #20 and failing previous integrated workflows remains BLOCK.

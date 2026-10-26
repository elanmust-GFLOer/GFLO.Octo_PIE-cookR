# E1-C — OctoPush Authenticated Review Adapter & OctoPass Proof Bridge

**ISOLATED lab only. No writes to Lovable / Supabase production.**

The observed OctoPush Lovable source has `requireSupabaseAuth` in `src/integrations/supabase/auth-middleware.ts` which verifies bearer claims and yields server-side `context.userId`; `src/lib/reports.functions.ts` shows role checking for moderation. The Builder UI writes `projects.status` directly; it is NOT a reviewed proof.

The `createAuthenticatedReviewHandler` protocol accepts only `projectId/revision/evidenceDigest/decision`. It resolves the authenticated reviewer through injected trusted server functions and rejects any request-supplied `reviewerId`, `ownerId`, or `issuerId`.

CI:
- PostgreSQL E1-B schema + negative role/RPC tests and stored review event
- Export the **actually inserted** PostgreSQL event as JSON
- Map actual row to E1-A lab Ed25519 signed envelope
- OctoPass verified-read bridge checks profile ownership, explicit scope, revocation and replay rejection

Production gaps:
1. Current Node adapter simulates a validated session (a mocked `verifySession`); it does not call the live Supabase Auth service. Integrate trusted `context.userId` plus role check and service-only RPC in OctoPush server route, not client code.
2. E1-B lab RPC still has a `p_reviewer` argument. Only the trusted session-backed server may fill it; a compromised service may forge it. Stronger PostgreSQL reviewer binding or cryptographic source authentication is required before production.
3. Current PostgreSQL review checks digest format and reviewer eligibility, not reviewer *truth*. Add snapshot evidence, independent review policy, retention, challenge/correction path.
4. E1-A signing is synthetic; no live signing key custody, issuer rotation, published certificate, durable consumer replay store, wallet session, onchain V04, XP issuance.
5. Browser control `projects.status` must stay separated from read-only `builder.reviewed` evidence. Enforce application-specific privacy permissions, owner consent and server-side authorization for every proof read.
6. The full IB-03 R1E integrated suite still has failing workflows; Codex independent clean-room revalidation pending.

OctoPush changes that will be necessary in a later approved staging phase:
- `builder-review.functions.ts` authenticated server function, role/session policy, rate limits and tamper proof source checks.
- Add protected review decision/event Supabase migration with RLS, minimal grants and review RPC, tested in an isolated clone.
- Builder UX `Submit for review` and authorized `Review` controls, distinct from owner-editable status.
- OctoPass UX `Connected Apps` / `Delegated Agents` / `Verified Activities`, with revocable scoped consent.
- Proof read-only explorer; canonical V04 acceptance is a separate security gate.

No production merge, database schema change, Lovable publish/deploy, or onchain interaction.

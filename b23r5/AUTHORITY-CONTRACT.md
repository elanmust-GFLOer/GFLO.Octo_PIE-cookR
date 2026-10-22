# GFLO OctoPass B2.3-R5 — External Supabase Auth Authority Contract (DESIGN ONLY)

Date: 2026-10-22. Status: **candidate architecture — implementation NOT authorized**.

## D0 — Division of authority
- **OctoPush / Supabase Auth** authenticates the human account and issues signed access tokens.
- **OctoPass adapter** verifies a Supabase-signed access token and (for security-sensitive operations) performs a fresh server-side Auth lookup. The adapter independently derives principal `sub` (user), `session_id`, token issuer, audience, expiration, and tenant/project. Caller-provided SQL user/session arguments are NEVER authoritative; browser must not obtain a lab-owner/definer credential.
- **OctoPass PostgreSQL** owns chain-specific wallet binding, auth_generation, suspension, epoch, durable nonce, request idempotency and atomic binding audit. Separate SIWE+signed consent required before any activation.
- **PIE / XP / token / governance** never derives privileges just from wallet possession or profile binding.

## D1 — Supported verification modes
**Mode A / signed JWT**: Supabase Auth `getClaims(jwt)` or a trusted JWT library verifying issuer, audience, key ID/signing algorithm, signature, `exp`, `nbf` (if present), `sub`, `session_id`. JWKS rotation and cache rules must be honored. This confirms token authenticity but does NOT prove that a previously issued token's session remains active.

**Mode B / sensitive request**: per-request, server-to-Supabase `getUser(jwt)` in addition to the validated claims and local binding-generation check. Validate the returned user ID equals token `sub`. Fail closed on 401, user mismatch, timeout, network error or malformed auth result. Never trust `getSession()`'s locally cached user object as authorization proof.

**Crucial limitation**: Even a fresh external Auth lookup cannot atomically serialize a later OctoPass PostgreSQL commit with an independent Supabase sign-out/session deletion unless a common authority/locking mechanism is implemented. No 'instant globally authoritative revocation' claim is allowed on Mode B alone.

## D2 — Parallel operation / explicit consistency guarantee
- **Local immediate suspend:** OctoPass suspension becomes effective on the same primary DB after its commit. All OctoPass sensitive consumers must fetch authoritative primary binding status and auth_generation; never rely solely on browser state, cache or asynchronous replicas.
- **Supabase sign-out** may leave access tokens cryptographically valid until expiry; adapter asks Auth about the user/session for sensitive operations. Session liveness is a *fresh observation*, not an atomic lease across cross-system commit.
- **OctoPass-initiated revocation:** commit local deny-state / generation advancement first, ensuring fail-closed local operations; coordinate signout and notifications separately. Retry/failure tracking required.
- **Externally initiated Supabase sign-out:** local adapter verifies freshness at every high-risk operation; any temporal race is an unresolved architectural risk. Either explicitly accept a bounded external revocation window in a separately approved threat model or introduce an actual common serialized authority; never call an async event mirror immediate.
- Fail closed for sensitive mutations whenever verification status cannot be established.

## D3 — Consent, wallet and recovery fences
- EOA pilot only; SIWE/EIP-4361 signing and separate binding-consent signature validated in a reviewed verifier.
- Activation/replacement unavailable before crypto verifier, D3 strong recovery policy, nonce replay protection, and audited mutations.
- No binding-triggered XP/Tier/mint/token grants.

## D4 — Minimum adapter contract (proposal, not runtime code)
TrustedAdapter.authorize(jwt, operation, requestId) -> AuthContext {
  issuer, audience, verifiedUserId, verifiedSessionId,
  verifiedAt, authGeneration, tokenExpiresAt, authVerificationMode,
  operation, requestId
}
Reject missing subject/session_id, invalid signature/claims, stale generation, Auth timeout and any mismatch. Never accept the principal from an untrusted request body or a mutable SQL session setting.

## D5 — Decision gates
- G-A: review Supabase API guarantees (getUser does network user lookup; whether specific session liveness and deletion are provably checked must be independently demonstrated by nonproduction tests).
- G-B: prove no user/session substitution at adapter boundary with two-user adversarial fixtures.
- G-C: prove fail closed on JWT expired, signed-out-but-not-yet-expired JWT, Auth timeout/partition, account disable and generation changes in nonproduction Auth.
- G-D: separately decide acceptable time-of-check/time-of-use window and cross-system ordering. Without that proof, **production integration BLOCKED**.
- G-E: reviewed SIWE, independently signed consent, durable challenge and recovery before wallet activation.

## Official external references (for design review)
- https://supabase.com/docs/guides/auth/jwts
- https://supabase.com/docs/reference/javascript/auth-getclaims
- https://supabase.com/docs/reference/javascript/auth-getuser
- https://supabase.com/docs/guides/auth/sessions
- https://supabase.com/docs/guides/auth/signout
- https://supabase.com/docs/guides/auth/server-side/advanced-guide

No Supabase project credentials, database privileges, migrations, service-role exposure, deployment or real wallet binding are used here.

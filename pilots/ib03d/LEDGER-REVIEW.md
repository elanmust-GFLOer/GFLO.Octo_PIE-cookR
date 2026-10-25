# IB-03D.2 — Transactional Nonce & Consent Ledger
**DISPOSABLE POSTGRES 16 ONLY. NO SUPABASE / PRODUCTION MIGRATION.**

What is tested:
1. Atomic one-time consume of an already issued and already cryptographically verified SIWE challenge (8 parallel database clients; exactly one succeeds).
2. Expired nonce fail-closed, replay denied.
3. Explicit `pie:xp:read` consent and generation checks; never implicit XP write permission.
4. Session, wallet-binding and consent locking for per-request authorization decisions; concurrent revocation serializes on row-level lock.
5. Immediate subsequent reads reject prior consent generation after revocation.
6. Binding suspension invalidates sessions and consent and increments generations.

**LIMITATIONS / RELEASE BLOCK**
- `consume_challenge` is an internal trusted function, not a public API. SQL cannot verify the EIP-191/4361 cryptographic proof; the caller MUST first verify exact challenge binding. Caller credentials & DB roles must prevent browser/RLS roles invoking it. Schema revokes PUBLIC, but superuser/test owner still has full authority: production access model remains NOT VERIFIED.
- This lab does not issue real sessions. Nonce consumption and session issuance are not integrated in one trusted transaction and will require an IB-03D.3 authorization service gate.
- SQL lock ordering: session → binding → consent; revocation consent-only locks consent, suspension locks binding → consent → session. This can deadlock under contention. Production lock-order normalization is REQUIRED before further integration.
- A successful authorization decision before revocation linearizes earlier; this does NOT guarantee cancellation of already serialized/read responses or global distribution fencing.
- No table migration, wallet, contract, RPC, production credentials, or external write.

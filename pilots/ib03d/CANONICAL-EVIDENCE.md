# GFLO IB-03D.4 — Canonical Identity Evidence Closure
**Verdict: LAB EVIDENCE CLOSED / PRODUCTION RELEASE BLOCK.**

## Grounded evidence
The three historical GitHub Actions runs were re-read via the GitHub connector before this handoff:
- D1: https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/40202508910 — 15/15 local tests, real EIP-191 EOA recovery, ERC-1271 mock; head `2b3e6bc25c3219481015cdd19076a345fa9f1829`.
- D2: https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/40203025745 — PostgreSQL 16 nonce concurrency and consent checks; head `51fb89aed883de3892fa5553c29a993ecf14f94e`.
- D3: https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/40205286423 — PostgreSQL 16 session issuance and revocation fence; head `fd00e60392a7cab2b6d550cf94c2fae7595cb437`.

Each run is a distinct historical revision, not an integrated full-stack cryptographic-session test. The D4 CI checks **Git blob identities and manifest consistency**, not live GitHub run conclusions; those conclusions were checked separately at handoff and may be rechecked through linked run URLs.

## Trusted admission handoff (MUST be implemented; NOT verified here)
1. Server issues a cryptographically unpredictable, DB-backed nonce bound to chain, wallet, exact SIWE message context, domain, URI and expiration.
2. Trusted server independently verifies the full EIP-4361 message, EIP-191 EOA or finalized-chain ERC-1271 signature, request origin, nonce/session rules. Browser assertion is not trusted.
3. Server passes an unforgeable exact proof identity to a trusted, least-privileged transaction that atomically consumes the nonce, verifies wallet/binding/consent generations and creates a bounded session.
4. PostgreSQL grants/RLS restrict session issuance and nonce consumption to trusted backend, preventing ordinary clients from fabricating proof digests or bypassing cryptography.
5. For every read, recheck versioned session/binding/consent using normalized lock order. Introduce authoritative response-disclosure fence for in-flight requests: D3 only linearizes database authorization decisions; it does not prove that responses cannot leak after revocation.
6. On authorization/provider failure: no XP, no legacy fallback, no production VERIFIED status. Keep `CRYPTO_VERIFIED_ONLY`, `MOCK_VERIFIED`, and durable session authority distinct.

## Reviewable blockers
See `evidence-manifest.json` for explicit blocklist. In particular, ERC-1271 verifier is mocked, D1 constrained parser not fully ABNF-tested, D1->D3 link is not cryptographically bound end-to-end, production PostgreSQL roles/tenant isolation not verified, and distributed revocation/disclosure race remains unproven.

## Change policy
PR #20 remains DRAFT. No merge, deployment, live wallet operations, Supabase migration, or Lovable write is permitted by this evidence closure. Any later merge needs separate code review and approved release gate.

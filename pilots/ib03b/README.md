# GFLO IB-03B — isolated OctoPass read-only bridge
STATUS: **synthetic pilot only; production integration BLOCKED**.

This branch is based on cookR main `05ecb3bbcc9696e0847e7daa3da2a0aeafbe5cbb`, independent of V04 draft PR #19.
Linked V04 lab commit: `1ea68bc5b796901e5f652b6580c0584236ba2c5f`; that candidate is not merged or deployed.
Source Lovable Octogflo Sovereign commit: `157b15c0315644a16d22df17b9453bfc1c5b8deb`; `src/domain/octopass-adapters.ts` has future interfaces only.

This adapter intentionally provides no network/RPC, wallet key, SIWE proof, database, sign operation, token/XP write or live authorization. It accepts dependency-injected synthetic identity and chain readers. `MOCK_VERIFIED` is never a production privilege or authorization signal.

Security checks: authenticated session; active wallet binding and generation; explicit unrevoked consent `pie:xp:read` with expiry/generation; chain ID; finalized nonstale block hash; core/registry/policy runtime pins; ABI hash; active registry policy/owner/core trust; policy and registry pauses; uint64 canonical XP; post-I/O consent/binding/session refresh. Missing/error/changed state returns denial, not zero XP or legacy fallback.

**Open release blockers:** actual SIWE server-side challenge/nonce/recovery evidence; atomic revocation fencing under distributed replicas; trusted blockhash-pinned RPC implementation with EVM Keccak and SHA-256 ABI; deployed registry/policy addresses and on-chain codehash; consumer EXPIRED=4 event parsing, real user consent, issuer factual-work validation, independent app security review. Post-read rechecking reduces obvious races but is NOT atomic cross-system revocation proof.

No Lovable write. No deploy. No wallet signing. No production tokens/XP changes.

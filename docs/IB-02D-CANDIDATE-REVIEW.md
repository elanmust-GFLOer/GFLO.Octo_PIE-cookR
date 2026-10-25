# GFLO IB-02D — V04 candidate for isolated review

Status: **DRAFT / NON-PRODUCTION / RELEASE BLOCK** (2026-10-25).

## Provenance
- Source commit: `8e46c99e575b508b7cb98d74972d96f5de44e5dc`, tree `eb713ef05c84d920a74f45d3293adf516c41cd95`
- Baseline Git blob: `bed6450d08b572181b718cb5cfa19d9c65e90ee5`
- Baseline SHA-256: `d38215cfab66af182ca633432ed16686ebaf4fa47af0d8d9402638e08734b76c`
- New candidate SHA-256 reported by earlier local handoff: `9b7c488de0b2fb8e4467df488d9da0353afc788d4da195eccb556929a3bc19eb` — **must independently re-verify on GitHub**.
- Historical unrecovered candidate SHA-256: `e67807aace938fce881c0ca1cac3549c52e7d58f8d4154eeccd2c2984d8dd8b7`, NOT the same file.

## Scope
`contracts/XPPolicyV04.sol` is a new remediation candidate. Adds four-day finalization window after existing three-day challenge, EXPIRED=4, permissionless single-grant expiry, one-time pending quota release and policy-pause fail-closed canonical XP read. Pending governance revoke releases quota; VALID revoke preserves historical issuance counters. Existing replay markers remain consumed.

The seven-day lifecycle is a **policy proposal, NOT approved**. EVM does not automatically execute expiration; a user or keeper must call it.

## Verification
Source/mock local handoff: 21/21 PASS (2 source + 19 synthetic reader tests), **not Solidity/EVM evidence**.
This PR adds 3 additional source-only guards. They cannot be counted as compiler/EVM PASS.
The historical 26 V04 remediation EVM test code and 14 regression suite were **not included in this GitHub upload**. Previous 26 cases were NOT EXECUTED. Existing 14-case CI may run separately.
Required: pinned npm integrity, full Solidity compile/ABI/storage layout, new EVM tests for expiry/quota/rollover/replay/pause and old signed EVM regressions; source issuer truth and ID_Entity/OctoPass bridge remain separate BLOCKED/NOT VERIFIED gates.

## Security
- Do not merge, deploy or promote to canonical production XP.
- No contracts or wallets have been deployed or signed.
- No user-controlled Builder status is valid factual-work evidence.
- Expiry cannot reset event/evidence/nonce replay use.
- Verify all consumers recognize EXPIRED=4 and GrantExpired; do not silently cast unknown enum.
- This is not a proxy upgrade approval.

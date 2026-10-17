# AR01-03 V04 Signed EVM Regression — CI evidence

Date: 2026-10-17
Run: https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39070306827
Job: `117506353557`, conclusion: **success**
Test: `scripts/ar01-v04-signed-evm.mjs`
Contract: `contracts/XPPolicyV04SourceBound.sol`
Solidity compiler: `0.8.34+commit.80d5c536.Emscripten.clang`

## Verified job log: 9/9 PASS

1. Safe 2/3 controls V04 and Registry/Gate reads canonical XP.
2. Default-deny: attestor+verifier without source approval rejected.
3. Unauthorized issuer signature rejected; Safe source configuration works.
4. Exact source approval allows PENDING, tampered event rejected.
5. Pending XP does not unlock Tier 1 or increase canonical XP.
6. Source-approved claim finalizes only after challenge period.
7. Finalized grant enables signed Tier 1 burn and effective tier.
8. Safe revocation removes effective tier but leaves achieved tier.
9. Replay after revocation rejected; paused Registry fails closed.

## Security boundaries

The fixture demonstrates the source-approval trust boundary for these inputs. It does not prove real-world event truth, issuer independence, key compromise resistance, production deployment, or exhaustive invariants. Separate negative EVM tests for issuer rotation, expiry, revoked issuer, tampered chain/policy domain, and bypass routes remain open.

The V03 6C HIGH finding remains an applicable legacy baseline, not a vulnerability automatically eliminated from any deployed V03 policy. V04 is a candidate and needs independent audit and production governance review.

Evidence status: **V04 signed local EVM regression PASS (9/9)**. Production readiness: **NOT ESTABLISHED**.

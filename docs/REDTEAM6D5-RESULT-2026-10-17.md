# RED TEAM 6D.5 — signed EVM source-bound attestor result

Date: 2026-10-17
Scope: Termux-executed, local synthetic-key EthereumJS fixture; **no production deployment/audit**.
Reported compiler: `solc 0.8.34+commit.80d5c536.Emscripten.clang`
Runner: `scripts/rt6d5-sourcebound-evm.mjs`
Status: **9/9 scenarios completed; RT6C HIGH BYPASS OPEN**.

## Observed user-run output

- RT6D5-01 Safe 2/3, XPPolicyV03, only source-bound attestor allowed — PASS
- RT6D5-02 unapproved fabricated proof rejected — PASS
- RT6D5-03 forged source issuer authorization rejected — PASS
- RT6D5-04 exact proof digest ERC-1271 authorization succeeds; source-event replay blocked — PASS
- RT6D5-05 authorized verifier creates PENDING, duplicate proof rejected — PASS
- RT6D5-06 approved source expiry, pause and revocation fail closed — PASS
- RT6D5-07 finalized claim permits legitimate Tier 1 burn — PASS
- RT6D5-08 **HIGH FINDING**: Safe authorized an alternate EOA attestor, bypassed the source-bound attestor and submitted fictitious XP as PENDING — reproduced.
- RT6D5-09 Safe revocation and paused Registry remove future effective-Tier privilege — PASS.

## Interpretation

Source-bound ERC-1271 checks demonstrably gate XP when the SourceBoundAttestor is the **only** permitted attestor. Existing XPPolicyV03 governance can, however, add another authorized attestor, whose correct signature permits source-unverified claims. This bypass is the significant threat reproduction and **not evidence of closure**.

The issuer EIP-712 signature establishes only that an approved key authorized a digest. It does not establish the truth or independence of underlying OctoPush Builder work. Compromised issuers, malicious reviewers or Safe governance can still compromise source authenticity. The 3-day challenge period limits finalization timing, not factual validity. Revocation of XP cannot undo prior token burning.

## Next acceptance gate

1. Propose XPPolicyV04 with a **rule-pinned source-bound attestor** and explicit governance change controls (e.g. constrained/timelocked changes). Direct alternate-attestor submission must fail despite verifier authorization and Safe owner power under ordinary operations. Governance emergency recovery and credible trust boundaries must be stated.
2. Test safe-controlled configuration drift, new rule creation, key rotation, malicious/fabricated issuer attestations and off-chain evidence-source verification.
3. Run local signed EVM tests and independent review; no existing PIE production deployments or OctoPush Supabase data altered.

## Known gaps

This local run is user-reported; independent third-party audit, testnet, live database-to-signer workflow, verified source event provenance and genuine task completion were not demonstrated. Earlier 5A fixtures are reused and overlap with existing test guarantees.

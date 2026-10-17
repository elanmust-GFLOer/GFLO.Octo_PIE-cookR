# GFLO Security & Development Progress Report v0.1
Date: 2026-10-17
Basis: owner-provided Termux logs, verified repository files, and 6D.4 GitHub Actions PostgreSQL 16 run. This report concerns **pilot proofs in isolated fixtures**, NOT deployment, audit or production integration.

## Executive summary
GFLO's PIE evolution now distinguishes **staking economics** from **canonical verified XP**, separates historical achieved Tier from current Effective Tier, and layers proof source claims, signature verification, revocable XP and restricted privilege consumption. The key architectural achievement is *measured failure modes* rather than a declaration that source authenticity is solved.

## Evidence ledger

| Gate | Observed evidence | Interpretation |
| --- | --- | --- |
| RT6A | 6/6 Termux source assertions | Legacy GasFeeLoop stake XP is architecturally incompatible with PIE integer and signature path; **not** an EVM proof |
| RT6B | 4/4 signed local EVM scenarios | Legacy staking functions while legacy `addXP` against new PIE fails, no tested state change; unauthorized legacy writer rejected |
| RT6C | 8/8 signed local EVM scenes (largely 5A regression reuse) | **HIGH demonstrated**: authorized attestor/verifier can turn fictitious source activity into finalized XP, Tier 1, then Safe can revoke and Effective Tier falls |
| RT6D / 6D.2 | 10/10 then 15/15 locally executed Node source-proof / SQLite assertions (as previously reported) | Cryptographic source-event validation and durable replay pilot; not a live OctoPush service |
| RT6D.3 | Lovable source inspection and offline Postgres schema proposal | Browser-editable project/task status **cannot** prove completed contribution; proposed independent `builder.reviewed.v1` event, not deployed |
| RT6D.4 | 8/8 Termux static and actual GitHub Actions PostgreSQL 16 **success**, run 39031485104; SQL and separate-connection concurrency steps success | Demonstrates the candidate PG migration's examined RLS/privilege/atomicity behavior in disposable DB; *not production Supabase* |
| RT6D.5 | 5/5 static + 9/9 signed EVM owner-run | ERC-1271 source-bound attestor enforces allowed source digest and replay/expiry; **HIGH** Safe governance could still authorize alternate EOA attestor |
| RT6D.6 | 9/9 signed EVM owner-run | XPPolicyV04 immutable single pinned ERC-1271 source-bound attestor blocks the **tested** Safe alternate-attestor bypass; this is a new pilot policy, not a patch deployed to V03 |
| RT6D.7 | 10/10 signed EVM owner-run (9 reused scenes + one new attack) | **HIGH reproduced again**: Safe 2/3 can authorize colluding issuer, allowing fictitious event to pass V04 and finalize XP. Disabling issuer does NOT reverse already canonical XP; explicit grant revoke does |

Test counts are overlapping scenario executions, **not additive independent security guarantees**. Never report a composite 75+ audits or claim full coverage.

## What measurably improved

1. **XP isolation:** the formerly stake-multiplied GasFeeLoop economic output no longer has a functioning direct writer into fresh PIE pilot; ADR-0001 formally rejects stake boosts for canonical XP. Legacy GasFeeLoop code is still legacy and **has not been upgraded**.
2. **Eligibility semantics:** immutable achieved Tier no longer implies current privilege; EffectiveTierGate uses dynamic, revocable canonical XP. Pilot tests show revoked grant reduces effective Tier while burn history remains.
3. **Attestation robustness:** actual signed EVM tests verify key permissions, time limits, event/evidence/nonce replay rejection, Pending→Valid challenge and Safe revoke.
4. **Source-bound credential layer:** source issuer signatures, one-time keys, proof digest binding and Ethereum ERC-1271 cryptographic checks have dedicated attack scenarios.
5. **Narrower governance bypass surface:** V04's immutable pin blocks the known V03 `setAttestor` exploit; demonstrated by Safe 2-of-3 signed adversarial test, with no loosened security check.
6. **Database integrity evidence:** SQLite restart and unique replay pilot, then real PostgreSQL 16 CI with SQL security tests and concurrent connections now exist. Not equivalent to an operating source-to-chain bridge.
7. **Verification discipline:** regressions deliberately expose attacks as open findings; separate code branches/draft PRs, pinned status reports and repeatable synthetic local tests.

## Remaining HIGH trust boundary (not resolved)
The protected on-chain gate does not observe off-chain reality. Governance can approve a colluding `GFLOSourceBoundAttestorV01` issuer, which can cryptographically authorize an invented Builder completion. RT6D.7 showed this succeeds even under V04. Revoking issuer permission alone does not invalidate finalized XP. Retroactive XP grant revoke changes future Effective Tier but cannot reverse irreversible prior actions. External work and independent review remain unproven.

## Other limits / planned rather than implemented
- No live OctoPush Builder review authority or auditable task provenance tied to the on-chain issuer signer.
- No deployed Supabase migration, live PostgreSQL outbox↔EVM receipt exactly-once workflow, hardened key custody/rotation, timelock + issuer independent multi-approval, conflict-of-interest controls or challenge/appeal service.
- No production deployment, public testnet transactions, gas benchmarks, externally reviewed audit, real-user/attacker Sybil resistance, formal verification or operational incident response proven.
- PIE V04 prototype uses a globally pinned attestor; per-rule pinning is a future design choice. Legacy `ruleAttestors` getter remains and should be addressed before stable API.
- Source legitimacy is a broader business and governance problem than syntactic cryptographic signature validity. No code alone can prove off-chain work was real.

## Recommended next implementation priorities (RT6D.8)
1. Specify independently authenticated and externally reviewable OctoPush `builder.reviewed.v1` source event, including reviewer independence, evidence digest, owner-wallet binding, appeal, and issuer accountability.
2. Propose delayed Safe issuer-allowlist rotations / secondary independent approval and source event ledger proofs, plus incident freeze/rescind and backfill repair paths. Test collusion of issuer, reviewer and governance; do not assume a timelock alone prevents malicious actors.
3. Connect disposable Postgres outbox to a restricted source-issuer signer with signed EIP-712 proof provenance and canonical receipt reconciliation; test crash/restart, reorg, duplicate and unauthorized signing.
4. Re-run negative signed EVM tests before any merge/testnet decision, and obtain independent security review for any on-chain contract changes.

## Release status
RT6A/B/C/D.4/D.5/D.6/D.7 **completed only within specified testing scopes**. RT6D.7 is a successful HIGH attack reproduction, not a safety pass. **No permission to deploy, issue canonical user rewards, merge draft PRs automatically, or claim security audit.**

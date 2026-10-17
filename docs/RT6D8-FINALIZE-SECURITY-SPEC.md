# RT6D.8 — Finalization source-revocation gate

Status: SPECIFIED / NOT IMPLEMENTED / NOT TESTED
Base branch: feature/rt6d7-issuer-rotation-attack
Target: contracts/XPPolicyV04.sol

## Confirmed issue
XPPolicyV04.submit() validates a pinned ERC-1271 attestor via SignatureChecker.isValidSignatureNow(attestor, digest, signature). XPPolicyV04.finalize() only checks global pause, PENDING and deadline before marking VALID and increasing validEarnedXP. The current Grant does not store the proof digest or signature.

## Security invariant
For any PENDING claim whose source approval is explicitly revoked under the approved lifecycle policy, finalize MUST revert and MUST NOT increase validEarnedXP.

## Design gate — do not implement before inspecting the attestor
Identify the actual SourceBoundAttestor source path, ABI and issuer disable/revoke semantics. Choose and document ONE mechanism:
A. Persist digest and signature at submit, re-check ERC-1271 at finalize; assess signature expiry behavior and storage/gas.
B. Persist digest at submit and call a pinned read-only approval-status interface that explicitly distinguishes revoked, issuer-disabled, paused, expired, and valid. Ensure digest binding to the original proof and fail closed on call failure.

A bare check of approvals[digest].revoked is insufficient if issuer disable or global pause is supposed to retroactively invalidate PENDING grants.

## Acceptance matrix
| Case | Expected |
|---|---|
| valid approval; challenge elapsed | VALID; XP credited once |
| approval explicitly revoked during PENDING | revert; no XP |
| issuer disabled during PENDING | behavior documented; default fail closed |
| attestor/source paused during PENDING | behavior documented; default fail closed |
| approval expired during PENDING | explicit policy decision; regression |
| XPPolicy Safe revoke during PENDING | cannot finalize |
| finalize before deadline | revert |
| alternate attestor or EOA | cannot bypass immutable pin |
| failed external validation / revert | fail closed; no XP |
| repeat finalize | revert; no duplicate XP |
| existing RT6D.5–D.7 regressions | all still pass |

## Reproducibility gate
Run tests from clean checkout with pinned commit SHA, Solidity compiler, dependency lockfile and CI job URL. Record bytecode/artifact hashes. No PASS or deployment claim from local pasted output.

## Release
Require review of changed contract and test diff; never merge automatically. No production deployment or XP grants in this task.

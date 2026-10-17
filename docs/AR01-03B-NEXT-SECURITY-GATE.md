# AR01-03 — V04 11/11 evidence and next security gate

## Verified evidence
- GitHub Actions run: https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39071005036
- Job: `117508422791`, conclusion `success`
- Compiler: `0.8.34+commit.80d5c536.Emscripten.clang`
- Test script: `scripts/ar01-v04-signed-evm.mjs`
- Log: all 11 scenarios individually checked and reported PASS, including issuer rotation and paused/expired source approval.

## Critical next questions from direct V04 source review
1. **Pending grant after issuer revocation**: `finalize(claimId)` checks global `paused`, grant status and time, but does **not** check `ruleSources[grant.ruleId].active` or issuer epoch. Therefore an already-PENDING claim may be finalized after source deactivation/rotation. This may be deliberate snapshot semantics or an unsafe fail-open trust boundary; decide explicitly and test. If emergency issuer revocation should invalidate pending claims, implement epoch/source binding on Grant or governance bulk revocation and test.
2. **Role independence is address-only**: `_verifySource` requires issuer != attestor and issuer != msg.sender, but three distinct addresses are not proof of three independent controllers. Safe/EOA ownership, multisig overlap and compromised issuer are still open.
3. **Source truth is off-chain**: signatures attest authorization, not truth of underlying OctoPush activity.
4. **Domain replay**: EIP-712 implementation includes chain and verifying contract domain; add signed negative tests across two deployed policy instances and changed chainId.
5. **Expiry vs finalization**: source proof expiry is checked at `submit`, not at `finalize`. Document intended validity snapshot and test.
6. **Replay nullifier scope**: `usedEvents` and `usedEvidence` are global to the policy; confirm cross-source uniqueness policy to prevent accidental denial of service from reused identifiers.

## Next acceptance gate: AR01-03B
- B01: submit approved PENDING; disable source; advance time; assert explicit chosen policy on finalize.
- B02: submit approved PENDING; rotate issuer; advance time; assert chosen policy on finalize.
- B03: reject issuer=attestor and issuer=verifier role collisions.
- B04: cross-contract and cross-chain typed signature rejection.
- B05: mutate each bound proof field and verify revert with XP unchanged.
- B06: ensure no direct bypass of `submit` to write `validEarnedXP`; test role changes and policy registry pause.

**Status:** 11/11 signed local EVM baseline PASS. AR01-03B design and new signed EVM executions OPEN. No production readiness assertion.

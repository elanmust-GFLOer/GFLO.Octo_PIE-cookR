# AR01-02 — Trusted XP Registry Boundary Review

Date: 2026-10-17
Status: STATIC SOURCE REVIEW. NO NEW EVM TESTS RUN.

## Source pinned

`gflo-pie`, branch `feature/pie-core-v0.2`, `contracts/TrustedXPSourceRegistryV02.sol`, blob SHA `d5d62c48db396aa39d6f1d481d6f27f36422cfe2`.

## Verified from source

- `paused` starts `true`.
- `proposePolicy` and `activatePolicy` require `onlyGovernance`.
- `activatePolicy` cannot replace a nonzero `activeSource.policy`.
- Both proposal and activation validate deployed code existence, expected runtime codehash, `pie()` core binding and `owner()` policy owner.
- `totalXP` rechecks those conditions and reverts if paused or inactive.
- `proposeGovernance` and `acceptGovernance` use a two-step handover.

## Security boundaries and limitations

1. Two transactions for policy activation are **not** two independent approvals: the same governance authority can propose and activate.
2. Runtime codehash + owner/core matching do not prove policy correctness or source evidence authenticity.
3. `totalXP` is a read gate only; a downstream consumer that calls the policy directly bypasses this registry's pause and shape checks.
4. Policy owner changes cause registry reads to fail closed; operational recovery is not specified by this contract.
5. Policy activation is one-time. Migration to a replacement policy requires a new registry/deployment design, not an undocumented override.
6. No verified deployment address, bytecode provenance, or live consumer call graph is established by this review.
7. Search of default branches did not locate `XPPolicyV04.sol`; absence in search is not evidence of absence on all branches. Direct lookup on `feature/pie-core-v0.2` also returned 404 for `contracts/XPPolicyV04.sol`. The V04 implementation remains UNVERIFIED.

## Required EVM test matrix

| ID | Scenario | Expected |
| --- | --- | --- |
| REG-01 | Read before activation | revert `RegistryInactive` |
| REG-02 | Unauthorized propose | revert `NotGovernance` |
| REG-03 | Wrong codehash/core/owner | revert, no active source |
| REG-04 | Governance activate valid source | remains paused |
| REG-05 | Explicit unpause and read | matches pinned policy `totalXP` |
| REG-06 | Pause after activation | reads revert |
| REG-07 | Policy owner mismatch after activation | reads revert |
| REG-08 | Second policy activation | revert `PolicyAlreadyActivated` |
| REG-09 | Governance transfer | only pending governance can accept |
| REG-10 | Downstream effective-tier integration | all privileged reads route through registry, not direct policy |

## AR01 next gate

Resolve the deployed/current V04 source path and full commit SHA, then enumerate *all* consumer calls to `totalXP`, `getXP`, `validEarnedXP`, `effectiveTier` and `achievedTier`. Do not promote this static review to a passed test result.

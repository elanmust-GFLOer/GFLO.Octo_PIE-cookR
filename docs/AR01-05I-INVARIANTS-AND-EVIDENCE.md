# AR01-05I — V05 invariant specification and evidence plan

Status: **candidate; CI not yet verified**. Scope: local EthereumJS signed EVM, Solidity 0.8.34, synthetic Safe 2/3 signers. This is not a formal verification or external audit.

## Invariants

- **INV-01 (recovery authorization):** only Safe owner may invoke `releaseRevokedPendingQuota`. Unauthorized calls revert without state mutation.
- **INV-02 (exactly once):** only a grant revoked while PENDING can release quota; a second release reverts. A VALID-then-REVOKED grant never qualifies.
- **INV-03 (original buckets):** a successful recovery decrements `claimsPerRule` once and the day/week buckets reserved at submit; current day/week buckets remain untouched if distinct.
- **INV-04 (permanent replay):** `usedEvents`, `usedEvidence`, and `usedProofNonces` remain consumed after revocation and recovery. The original signed proof cannot be resubmitted.
- **INV-05 (no XP mint by recovery):** `validEarnedXP` and Registry `totalXP` cannot increase during recovery or rejected transactions.
- **INV-06 (no token mint/burn by recovery):** token `totalSupply` is invariant under quota recovery and failed transactions.
- **INV-07 (failed-call atomicity):** failed recovery, invalid claim, and unauthorized governance operations preserve quota, XP, nullifiers, token supply, and tier.
- **INV-08 (source fail-closed):** rotation/deactivation invalidates pending claim finalization, including after reactivation at a new epoch.

## Property-based fixture

The first AR01-05I property test generates a deterministic seeded sequence of 32 unauthorized or invalid recovery attempts across four operation classes (unknown claim, already released claim, VALID-then-REVOKED claim, unauthorized caller), plus replay attempts. Every attempted transaction must revert and leave an explicit state snapshot unchanged. Seed is fixed for reproducible CI; this is **bounded randomized negative testing**, not exhaustive state-machine fuzzing.

## Threats and limitations

- A successful Safe call is privileged by design; a compromised Safe is outside this local authorization model.
- Independent source keys/control groups do not establish organizational independence or real-world event truth.
- The existing quota model consumes replay keys globally and may induce denial of service across sources; analyze separately.
- Historical day/week bucket bookkeeping requires tests for multiple recipients and overlapping windows.
- Dependency versions and upstream branch refs are not fully pinned in the workflow. Pin SHAs and lockfiles before audit evidence is considered reproducible.
- Future work: stateful invariant handler with many valid claim lifecycles, multi-recipient fuzzing, source collisions, differential models, mutation testing, and gas/DoS profiling.

## Evidence

Baseline: [AR01-05H 22/22 CI](https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39080750148/job/117537009002).

AR01-05I evidence must record: commit SHA, full job URL, compiler version, fixture seed, test count, upstream PIE/GasFeeLoop SHAs, dependencies and all observed failures. **Do not mark PASS until job logs are inspected.**

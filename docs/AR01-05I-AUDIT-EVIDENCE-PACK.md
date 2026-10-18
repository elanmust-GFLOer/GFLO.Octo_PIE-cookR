# AR01-05I — Audit Evidence Pack (signed local EVM)

**Status:** CI VERIFIED for the specified bounded regression only. **Not a security audit, formal verification, or deployment approval.**

## Reproduction identifiers

| Artifact | Verified value |
|---|---|
| Audit/integration repository | `elanmust-GFLOer/GFLO.Octo_PIE-cookR` |
| Branch | `audit/ar01-contract-inventory-20261017` |
| Tested commit | `af5ef9bcba5d6b5bbb180f9d4851ef96f5cf302f` |
| PIE upstream checked-out SHA | `dbd02d3f1ffd31abff3bda9caaa9852ee7cecf5c` |
| Legacy GasFeeLoop SHA | `16f5e5aaa52d8022d33cee46cdcbba4e5e49fa7c` |
| CI run | [39081075869](https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39081075869) |
| CI job and logs | [117537949889](https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39081075869/job/117537949889) |
| Job result | `completed / success` |
| Solidity compiler | `0.8.34+commit.80d5c536.Emscripten.clang` |
| Signed EVM regression | **23/23 PASS** |
| Bounded property run | **32 rejected attempts**, seed **99618114** (`0x05f00d42`) |
| Workflow | `.github/workflows/ar01-v05-signed-evm.yml` |
| Test | `scripts/ar01-v05-signed-evm.mjs` |
| Contract under test | `contracts/XPPolicyV05MultiSource.sol` |
| Invariant specification | `docs/AR01-05I-INVARIANTS-AND-EVIDENCE.md` |

## Verified properties (within fixture scope)

1. Safe 2/3 governs source configuration, emergency pause and recovery.
2. Independent 2-of-2 source signatures, domain separation and source epoch changes are exercised.
3. Registry V02 reads codehash-pinned V05 canonical XP; TierGate and Ignition Tier 1 burn integrate.
4. Revocation removes effective tier eligibility without reversing achieved tier or prior token burn.
5. Recovery releases only revoked-while-PENDING quota once, using original day/week buckets, with permanent replay keys.
6. The AR01-05I seeded property test executes 32 invalid recovery/replay attempts and asserts no state change to claim quota, reserved buckets, XP, canonical XP, replay nullifiers, token supply and effective tier.

## Reproduction and caveats

The workflow checks out upstream repositories by mutable branch names, and installs npm dependencies with semver major selectors and without a lockfile. **The checked-out SHA values above are captured from this CI run, but the workflow does not pin them.** A future run on the same workflow may test different upstream code or dependencies. For audit-grade repeatability: pin upstream SHAs, use a lockfile, pin GitHub Actions by immutable SHA, capture compiler/package integrity and upload a machine-readable results artifact.

The bounded property test repeats invalid operations against one fixture state. It is **not** multi-actor stateful fuzzing of arbitrary valid/invalid operation sequences. The issuer/control-group independence model is address-based and cannot prove real-world operational independence. Real-world evidence authenticity, colluding source issuers, economic incentives, external audits and mainnet safety remain out of scope.

## Next acceptance gate

AR01-05J: multi-recipient, multi-window stateful model testing and provenance/collusion threat model. Preserve the signed EVM baseline as a regression guard. Capture CI artifact with SHA-256 digest and dependency lockfile before declaring audit readiness.

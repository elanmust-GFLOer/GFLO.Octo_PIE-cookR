# AR01-01 — Contract inventory and canonical XP gate

Status: STATIC SOURCE REVIEW ONLY. No new EVM execution or deployment is evidenced by this document.
Recorded: 2026-10-17. Branch: `audit/ar01-contract-inventory-20261017`.

## Pinned source observations

| Contract | Source ref | Blob SHA | XP writer / reader | Pilot decision |
| --- | --- | --- | --- | --- |
| Legacy PIECore (root) | `gflo-pie/main/PIECore.sol` | `ab4abc60412d1339e765012e80e05a8bed9fb396` | `addXP` guarded by `onlyAuthorized`; `identities.xp` | EXCLUDE pending explicit compatibility proof |
| Legacy PIECore (contracts/) | `gflo-pie/main/contracts/PIECore.sol` | `5e65caa9f633fab251dbb16c3dda3dc864d03e24` | public `gainXP(amount)` credits caller's own XP; `addXP` also exists | BLOCK as trusted canonical XP source |
| PIECoreIgnitionV01 | `gflo-pie/feature/pie-core-v0.2/contracts/PIECoreIgnitionV01.sol` | `c2442cda19e133417e38ff8b01e27c4ab73b3c2d` | `createIdentity` seeds 25 XP; no `addXP` exposed | CANDIDATE; needs version-pinned execution evidence |
| XPPolicyV03 | `gflo-pie/feature/pie-core-v0.2/contracts/XPPolicyV03.sol` | `32f44e22e982993bae13adad158abf652b5f1282` | `validEarnedXP` incremented only at `finalize`; `totalXP = core.xp + validEarnedXP` | CANDIDATE; verify consumers and revocation semantics |

Blob SHA identifies file contents, not a full repository commit. Obtain full commit SHAs before reproducible test runs.

## Decision gate

1. Never authorize `contracts/PIECore.sol` legacy `gainXP` as canonical XP. Its public method can increase the caller's XP after path selection without evidence authorization.
2. No GasFeeLoop stake-based XP multipliers or app credits may feed canonical XP (see `ADR-0001-GAS-FEE-LOOP-XP-SEPARATION.md`).
3. Treat `PIECoreIgnitionV01 + XPPolicyV03` as an observed *candidate* pair, not as the confirmed current V04 production pair.
4. For any candidate canonical source, record exact repository commit SHA, compiler/dependencies, deployment chain ID/address/code hash, contract ownership, writer roles, source registry and every tier consumer.
5. Before promotion require negative tests for unauthorized credit, duplicate event/evidence/nonce, expiry, paused/revoked sources, early finalize, repeat finalize, post-finalization revoke, and cross-domain replay.
6. Verify that effective-tier consumers use the intended canonical XP view and not legacy `getXP` or raw staking credits.

## AR01-02 invariant candidate (V03 only)

For an existing identity, `totalXP(wallet) = PIECoreIgnitionV01.getIdentity(wallet).xp + XPPolicyV03.validEarnedXP(wallet)`. PENDING grants do not increase `validEarnedXP`. VALID grants do. Revoking a VALID grant subtracts its amount. This is a static reading of the pinned V03 source, not an executed proof or a claim about V04.

## Evidence required to close AR01

- Full current deployment graph and ABI selectors pinned to commits and bytecode hashes.
- Full V04 policy/registry/ignition/core source review, including migration/upgrade policy.
- Test command, toolchain versions, lockfile, full logs, exit code, chain ID, and state assertions.
- Consumer audit: effective tier, governance, review access, burns, app adapters.
- Independent review of signature provenance and Sybil/issuer trust boundaries.

## Current disposition

AR01-01: PARTIAL — four source files inventoried; full dependency and deployment inventory missing.
AR01-02: PARTIAL — V03 source-of-truth formula established; V04 and all consumers unverified.
Runtime validation: NOT RUN for this work package.

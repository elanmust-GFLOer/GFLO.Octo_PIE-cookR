# RT6D.8 — security and reproducibility review

Status: **EVM regression PASS (14/14 on commit 5131b6c); release NOT APPROVED**.
Evidence: https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39050696702

## Verified
- XPPolicyV04.submit stores a digest bound to the EIP-712 proof.
- XPPolicyV04.finalize checks the immutable pinned attestor's code hash and current ERC-1271 signature status before crediting validEarnedXP.
- Signed EthereumJS tests: 14/14 PASS, including revoked digest, disabled issuer, source pause, expired approval; CI ran Solidity 0.8.34.
- PIE fixture checkout now pinned to dbd02d3f1ffd31abff3bda9caaa9852ee7cecf5c and selected source blobs independently checked.

## Review findings and decisions
1. **HIGH / remaining off-chain trust**: a legitimately approved issuer can attest invented events. This is not a smart-contract bug and is NOT closed by RT6D.8. Pilot requires explicit issuer governance, evidence retention, fraud review, revocation and participant caps.
2. **MEDIUM / expiry policy**: finalization rejects an approval that expired during the challenge window. Operational policy must ensure source approval validity exceeds 72h plus processing margin; pending claims may become permanently non-finalizable unless reissued under a fresh digest.
3. **MEDIUM / ABI change**: public `grants(bytes32)` getter now exposes an extra `proofDigest` tuple member; consumers relying on tuple positions must be updated. No proxy upgrade/storage-layout compatibility is asserted: V04 is treated as a fresh deployment candidate.
4. **MEDIUM / finalization gas**: ERC-1271 now requires an external call in finalize. Benchmark against prior V04 in a deterministic EVM environment, record transaction gas and check under target network gas constraints.
5. **MEDIUM / reproducibility gap**: EVM workflow still installs semver ranges without a committed package-lock and npm ci. Pin exact dependency graph and action SHAs before calling the pipeline fully reproducible.
6. **LOW / dormant interface**: ruleAttestors mapping is unused. Document/deprecate rather than re-enable alternate signers.
7. **MEDIUM / quota accounting**: quota is reserved on submit; a PENDING grant invalidated before finalize does not automatically release quotas. Decide whether this is intentional anti-spam behavior or requires an explicit, governance-controlled cancellation path.
8. **MEDIUM / external failure handling**: the SignatureChecker validation fails closed on invalid ERC-1271 result, but future attestor upgrades and failure modes require regression coverage.

## Merge gate
- [x] 14/14 signed EVM regression on GitHub Actions
- [x] Static source invariant CI
- [x] Pin PIE fixture commit and verify selected source blob hashes
- [ ] Commit dependency lockfile, use npm ci, pin GitHub action SHAs
- [ ] Capture deterministic ABI delta and gas measurements
- [ ] Review invalid-PENDING quota handling and operational expiry policy
- [ ] Independent reviewer sign-off
- [ ] Pilot Trust Policy approved
- [ ] Mainnet/testnet deployment review (separate decision)

No audit, no deployment, no authorization to issue real-world XP follows from this document.

## Measured EVM CI evidence (2026-10-17)
- Signed EVM run: https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39051552638 — **14/14 PASS**.
- The job generated a lockfile candidate, successfully installed 37 packages with `npm ci`, and uploaded `rt6d8-package-lock-candidate` artifact (ID 12107852689). The lockfile is **not yet committed**, so this is a reproducibility milestone, not a completed release gate.
- ABI getter `grants(bytes32)` now returns eight values, ordered: recipient, ruleId, amount, finalizesAt, verifier, attestor, proofDigest, status. Consumers relying on prior seven-value ABI must regenerate bindings.
- Successful `submit()` transaction gas samples: 324920, 290768, 307892, 290780, 307868, 290792. Successful `finalize()` samples: 73520, 56432. These are scenario-specific EthereumJS Cancun gas values, **not** a comparative before/after benchmark or a mainnet gas forecast.
- Failed `finalize()` gas samples: 43712, 43695, 41452, 43749. All corresponding invalid-PENDING cases passed.
- Action SHA pinning, committed lockfile and independent security review remain outstanding.

## Follow-up verification work
- All three RT6D.8 workflows now pin `actions/checkout` to `11bd71901bbe5b1630ceea73d27597364c9af683` and `actions/setup-node` to `49933ea5288caeca8642d1e84afbd3f7d6820020` (immutable action commits; verify upstream provenance in release review).
- Added immutable baseline source snapshot at `tests/baselines/XPPolicyV04.rt6d7.sol` from Git blob `6d4b323e39a37990578f3d85c6f3f3b963106f7c`.
- New deterministic comparison compiles both original and patched V04 with identical solc/optimizer/Cancun settings; reports ABI, bytecode sizes and Solidity storage layouts. This is **not** a before/after transaction-gas benchmark, and does not establish upgradeability safety.
- The baseline comparison workflow is pending verification. Do not close the benchmark gate before its CI evidence is reviewed.

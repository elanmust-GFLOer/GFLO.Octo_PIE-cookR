# AR01-03 — Source Authenticity Hardening: implementation gate

Status: DESIGN / NOT IMPLEMENTED. Baseline: signed EVM 6C CI 8/8 PASS, run https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39068879916. The baseline proves an open HIGH trust-boundary failure, not a fix.

## Confirmed source baseline
- `gflo-pie` branch `feature/pie-core-v0.2`: `contracts/XPPolicyV03.sol` (blob `32f44e22e982993bae13adad158abf652b5f1282`) accepts EIP-712 signed claims from authorized attestor and verifier; signed source assertion is not factual evidence.
- `contracts/TrustedXPSourceRegistryV02.sol` (blob `d5d62c48db396aa39d6f1d481d6f27f36422cfe2`) authenticates a governance-approved policy for reads; it does not independently authenticate upstream activity.
- `contracts/XPPolicyV04.sol` was NOT FOUND on this branch at inspection time. Do not treat an unlocated V04 as verified or absent everywhere.

## Non-negotiable invariant
For any source-bound rule, an authorized attestor/verifier pair alone MUST NOT be able to turn arbitrary fabricated evidence into canonical XP. An independently governed source authority must approve the exact source event/digest and recipient/rule/nonce/expiry before PENDING submission. Any bypass route must revert. Even this proves authorized issuance, not the underlying real-world event; issuer compromise/collusion remains a residual risk.

## Proposed minimal design (not yet implemented)
1. Register source-specific issuer authority under Safe 2/3 governance; separate source issuer from attestor and verifier role administration. Require source binding per rule, explicit issuer status, pause, expiration and rotation.
2. Bind approval to chainId, policy contract, sourceId, recipient, ruleId, eventId, evidenceDigest, nonce and validity window; use domain-separated typed signatures or a source-approval digest with explicit domain and version.
3. Verify source approval *inside the policy's claim acceptance path*, not only in an optional off-chain adapter; reject absent/expired/revoked/mismatched approval.
4. Make event ID and nonce replay prevention persistent on-chain; verify cross-rule/cross-source replay scopes and rotation semantics.
5. Preserve PENDING/challenge/finalize/revoke, registry fail-closed, effective-tier behavior; explicitly define legacy rule migration and default deny for rules lacking source binding.
6. Pin Solidity, OpenZeppelin, EthereumJS and source commits; avoid silently changing V03 deployed semantics. Prefer a versioned V04 candidate plus deliberate registry activation rather than in-place assumption.

## Signed EVM acceptance tests (new tests, not merely replaying 6C)
- AR01-03-01: attestor+verifier fabricated claim with no source approval REVERTS, XP unchanged.
- AR01-03-02: unauthorized source issuer signature REVERTS.
- AR01-03-03: valid source approval bound to exact fields permits PENDING, not canonical XP.
- AR01-03-04: tamper recipient/rule/event/evidence/nonce/chain/policy REVERTS.
- AR01-03-05: source issuer pause, expiry, revocation, rotation fail closed; old signatures invalidated as designed.
- AR01-03-06: Safe 2/3 governance changes source authority; outsider and 1-of-3 cannot.
- AR01-03-07: finalized valid claim raises canonical XP; revocation removes effective-tier eligibility.
- AR01-03-08: replay and alternative direct submit paths REVERT; registry pause remains fail closed.

## Required proof
Actual signed EVM receipts, before/after XP state, emitted events, expected revert receipts, run URL, source SHAs and exact compiler/dependency versions. A green CI run without an inspected test log is not sufficient for acceptance.

## Open architectural risk
Independent source issuer can still lie or be compromised. Production deployment additionally requires observed authoritative OctoPush event schema, durable source event provenance, issuer custody/rotation, operational monitoring, and adversarial issuer compromise model.

# AR01-05A — GFLO V05 Multi-Source Evidence Threat Model & Contract Specification
Status: DESIGN CANDIDATE — not implemented, audited, or deployed.
Baseline: V04 18/18 signed local EVM regression, run 39073452372. Test 18 reproduces fabricated event accepted with valid compromised issuer and authorized attestor.

## Security objective
An attacker controlling exactly one configured source issuer must not produce canonical XP without an independently controlled second source approval. This is an authorization/quorum property, NOT proof that a real-world event occurred.

## Assets and trust boundaries
Assets: canonical validEarnedXP, PENDING grants, event/evidence nullifiers, per-rule and per-period quotas, Safe governance, verifier/attestor/source signing keys.
Boundaries: off-chain event capture -> source attestations -> verifier submit -> on-chain challenge -> finalization -> Registry -> TierGate/Ignition.
Adversaries: compromised single issuer, compromised attestor/verifier, coordinated signers, malicious Safe majority, forged/offline evidence, replay across chain/contract, issuer rotation during pending, source-collision, griefing by quota exhaustion.
Assumption: at least two issuer organizations/control groups are independently administered and do not collude. On-chain group IDs are governance assertions, not proof of independence.

## Minimal 2-of-2 pilot
- Two distinct source IDs, two distinct issuer addresses, two distinct governance-assigned controlGroup IDs, all active and allowlisted for the rule.
- Both issuers sign the EXACT same EIP-712 evidence claim (recipient, ruleId, eventId, evidenceDigest, nonce, issuedAt, validUntil), with each signature also binding sourceId and current epoch.
- Attestor is distinct from both issuers and the submitting verifier; verifier has rule-appropriate role.
- No arbitrary duplicate source can occupy two quorum slots; sorting by sourceId canonicalizes approval order.
- sourceId and controlGroup must be unique within a rule's active 2/2 quorum. Governance must enforce real operational independence off-chain.
- Proof validity, identity existence, amount bounds (25..1000), daily cap 1500, weekly cap 3000, maxClaims, replay protection, pause, challenge period (3 days) preserved from V04.
- On submit: verify all signatures and quota/replay preconditions BEFORE persisting state; store both source epochs, source IDs and issuer identities (or equivalent immutable commitment) per PENDING grant.
- On finalize: fail closed if either source is inactive, rotated, revoked, replaced, or quorum composition changed; reject early finalization. Revoke VALID grants with Safe governance and decrement earned XP.
- Use EIP-712 name/version specific to V05; chainId and verifyingContract are domain bound.
- Never assume a signature validates external event truth. Evidence digest needs an off-chain canonical format and independently retrievable record. Do not store personal data on-chain.

## Contract API candidate
constructor(address pieCore,address safeOwner)
registerRule(bytes32 ruleId,uint16 amount,uint32 maxClaims) onlyOwner
setVerifierRole(address verifier,uint8 role) onlyOwner
setAttestor(bytes32 ruleId,address attestor,bool allowed) onlyOwner
configureSource(bytes32 ruleId,bytes32 sourceId,address issuer,bytes32 controlGroup,bool active) onlyOwner
submit(Proof proof,address attestor,bytes attestorSignature,SourceApproval[2] approvals) returns(bytes32 claimId)
finalize(bytes32 claimId)
revoke(bytes32 claimId,bytes32 reason) onlyOwner
validEarnedXP(address recipient) view returns(uint64)
setPaused(bool) onlyOwner

SourceApproval: {sourceId,epoch,signature}; SourceConfig: {issuer,controlGroup,epoch,active}; grant stores both epochs and quorum source IDs.
Governance source rotation increments epoch even if issuer address unchanged. Rule configuration should be immutable while PENDING or explicitly invalidate PENDING via rule epoch.

## Security acceptance tests (signed EVM)
A. Valid 2/2 approvals -> PENDING, no XP; challenge elapses -> VALID, canonical XP rises.
B. One compromised issuer + valid attestor + verifier -> REVERT, zero XP, unchanged quota/nullifiers.
C. Same issuer twice, same source twice, same controlGroup twice -> REVERT.
D. Second source wrong claim/evidence, wrong epoch, expired signature -> REVERT.
E. Source A or B revoked/rotated during PENDING -> finalize REVERT even if reactivated under new epoch.
F. EIP-712 cross-chain and cross-contract replay -> REVERT.
G. Revoke VALID -> earned XP falls; EffectiveTierGate fails closed.
H. Governance unauthorized source changes -> REVERT; Safe 2/3 authorization positive control.
I. Quota/nullifier invariants on all failed submissions; deterministic positive control after failures.

## Explicit residual risks and decisions
- Two independent signatures may still attest the same fiction: correlated source failure/collusion remains.
- Off-chain evidence authenticity, independent collection, dispute/appeal policy, key custody, monitoring and issuer incident response remain external requirements.
- Source key compromise before finalization may require emergency pause and on-chain revocation; previously finalized XP requires governance revoke.
- V04 global event/evidence nullifiers may cause cross-source denial of service; specify event namespace and replay key semantics before V05 implementation.
- Quota reservations from REVOKED PENDING grants are not automatically released in V04; choose explicit policy before V05.
- 2/2 improves safety under single issuer compromise but sacrifices availability if either source fails. 2/3 is future work.
- Registry policy activation requires separate integration and ABI/codehash verification; do not silently replace V04.

## Gate
AR01-05A design review -> V05 candidate implementation -> compiler gate -> signed EVM red-team gate -> Registry/TierGate integration -> external audit. No production readiness claim before those gates.

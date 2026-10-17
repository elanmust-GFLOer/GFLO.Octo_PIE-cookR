# RED TEAM 6D.7 — Issuer rotation / collusion attack

Status: **EVM runner prepared, NOT YET EXECUTED**. The 11-check runner reuses RT6D.6's nine checks (9/9 owner-run previously), then performs two NEW signed-EVM scenarios.

## New tests
- RT6D7-10: Safe 2-of-3 disables original source issuer and enables a replacement attacker-controlled source issuer through the existing SourceBoundAttestorV01 governance function.
- RT6D7-11: Replacement issuer signs EIP-712 SourceAuthorization for *fictitious* Builder work, registers the approval, and an authorized verifier submits through XPPolicyV04's pinned ERC-1271 attestor. Expected observed outcome is **PENDING**, recorded as a **HIGH trust failure**, not a successful fraud defense.

## Expectations and caveats
- RT6D.6's alternate-attestor bypass was blocked *within V04*; 6D.7 deliberately attacks **issuer governance**, a separate trust root.
- A signed issuer authorization only establishes that an authorized issuer key signed a digest. It does not authenticate work, reviewers, or real-world task completion.
- A paused TrustedXPSourceRegistryV02 does not necessarily prevent a direct XPPolicyV04.submit() PENDING claim; registry pause prevents canonical reads via consumers, not all XPPolicy writes. The replay fixture finishes RT6D6-09 with registry paused.
- 11/11 is a target, not a test result; 9 tests are reused from RT6D.6, 2 new attack stages. No live Supabase, contracts, Safe or funds touched.
- This test's fabricated source event is purposefully invented, and demonstrates **colluding governance plus issuer can subvert provenance**. Correct handling is a recorded threat finding and change-control redesign, not pretending the current design prevents it.

## Next mitigation design (not implemented)
Separate source issuer administration from the PIE Safe, delay and independently approve issuer rotation, pin or epoch-bound issuer policy to verified reviewed events, use independent reviewer evidence and dispute audit trail, and adversarially test governance compromise including issuer deactivation/reenablement. Any authority capable of replacing all validating keys remains a trust root. Consider immutable trust anchor and slow governed migration to a new policy instead of pretending unrestricted governance is trustless.

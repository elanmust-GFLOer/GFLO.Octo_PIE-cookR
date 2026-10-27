# IB-03K — Compromised Verifier DB Role & Signed Proof Enforcement
**LAB PASS CANDIDATE / PRODUCTION BLOCK.**

Attack model: adversary has full login credentials of `gflo_verifier_lab`, allowing malicious `ib03j.register_receipt` calls. Adversary does not possess Ed25519 private key, independent `gflo_enforcer_lab` credentials or PostgreSQL owner role.

Independent enforcement process queries signed receipt and public-key trust registry using a separate enforcer-only read function. It verifies exact, domain-separated Ed25519 content before using enforcer-exclusive `ib03j.redeem_receipt`. Verifier, admission and browser roles lack that redemption privilege. Deliberately let attacker register invalid signatures; only enforcer may redeem, and it refuses false signatures. Key revocation and replay are tested.

**Security limitations and production gates:** SQL still cannot verify Ed25519. The enforcer DB role can call `ib03j.redeem_receipt` directly without checking a signature: compromising enforcer process/credentials bypasses this cryptographic fence. The lab does not prove enforcer deployment is isolated or its credentials are unavailable to verifier. Database owner is a trust root. This test does not include cryptographically verified live SIWE/EOA message at intake. Origin, key custody, RLS, mTLS/KMS, audit, session token issuance and distributed revocation remain unverified. In-memory synthetic private key is used only in CI; no real wallets, production DB or deployment.

Next stronger boundary: atomic Ed25519 verification INSIDE a DB-controlled transaction using audited extension, or cryptographically bound verification ticket minted by an independent service with strictly limited DB roles and non-reusable attestations. A compromised enforcer must not have an unchecked direct issuance capability for a production-ready claim.

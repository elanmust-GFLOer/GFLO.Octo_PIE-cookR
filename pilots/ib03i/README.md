# GFLO IB-03I — Key Custody & Verifier Isolation Gate
Status: **ASYMMETRIC CRYPTO LAB / PRODUCTION BLOCK**.

Ed25519 pilot proves that the admission boundary can verify an attestation from a public key alone, while its private key remains in an isolated, in-memory signer mock. Payload pins challenge, wallet, subject, chain, nonce/message digest, session ID, binding/consent generation, expiry and audience. Tests cover mutation, expired token, key rotation, revocation and signer inability to use a revoked key.

**Critical blocker**: The IB-03H production-pattern PostgreSQL function still verifies a HMAC held in PostgreSQL. This IB-03I source is a separately tested cryptographic pattern; it is **not connected to the PostgreSQL session issuance transaction**, and therefore cannot be described as a working asymmetric DB gate. Never treat its lab PASS as proof the HMAC is removed.

For a real handoff:
- Select independently audited KMS/HSM signing/verification with non-exportable private key and attested service identity, not this in-memory key pair.
- Pin public-key trust registry, key rotation epochs and signatures to immutable records and prevent cached revoked keys remaining authoritative.
- Verify the Ed25519 signature and nonce consumption in one non-bypassable admission boundary, or use an audited external verification service plus transactional proof binding that a DB role cannot forge.
- Include nonce/session storage, replay, parallel issuance, verifier compromise, key compromise, rotation races and operational response-disclosure gates.
- No production wallets, Supabase, Lovable, deployments or PR merges.

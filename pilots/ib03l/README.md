# IB-03L — Enforcement Compromise & Atomic Proof Verification Gate

**LAB-only fixture. Production release BLOCK.** CI creates a disposable PostgreSQL 16 instance and uses an ephemeral HMAC-SHA256 key. The application enforcer role cannot read the key or call the previous direct session redemption route. The database checks a scoped tag before D3 atomically consumes nonce and issues a session.

**Critical scope limitation:** This is NOT Ed25519 verification inside PostgreSQL. The trust root is the HMAC issuer and database owner. The synthetic CI signer is not proven to be a verified SIWE service or a KMS/HSM. A compromised issuer or DB owner can authorize forged claims. HMAC tags are compared as hexadecimal text; constant-time verification is not proven. The lab does not cover real EIP-4361, production RBAC, replica-level revocation, session cookie security, or a genuine OctoPass deployment.

This does not authorize deployment, migration, merge, Lovable write, or production wallets.

# GFLO IB-03J — Asymmetric Attestation-to-Session Transaction Gate
**LAB EVIDENCE ONLY. Production BLOCK.**

IB-03I Ed25519 signature semantics are connected to PostgreSQL 16 D3 session issuance in an isolated CI test: Node verifier verifies signature using a public key read from restricted DB key registry. After verification it alone can register a challenge-bound, session-bound receipt, and only an independent admission role can redeem it atomically through the D3 session function. Replay and session substitution are rejected. Old HMAC direct issuance ingress and unsigned IB-03G/IB-03F functions have privileges revoked in this CI fixture.

**CRITICAL NON-BYPASSABILITY LIMITATION**: PostgreSQL does **not** verify Ed25519 itself. The verifier SQL role can register a fabricated receipt without performing crypto verification if compromised or misimplemented. The DB's `signature` field is documentary evidence, not a cryptographic constraint. Therefore this is verifier-role trusted composition, NOT DB-native cryptographic verification. Not safe for production without audited isolated verifier/KMS and independent signed-proof enforcement.

Further blockers: no full live EIP-4361+EOA end-to-end path in this exact test, no on-chain ERC-1271 or trusted RPC, no production RBAC, KMS/HSM, session cookie, SIWE nonce issuance, RLS/multitenancy, independent audit or distributed revocation fencing. Key generation occurs in ephemeral CI memory; production private keys and actual Supabase never touched.

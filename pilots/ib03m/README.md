# GFLO IB-03M — SIWE-to-Attestation Trust Chain Integration
**LAB EVIDENCE ONLY — PRODUCTION BLOCK.**
One isolated CI executes actual EIP-191 EOA signature recovery through the constrained D1 SIWE parser, a server-only HMAC signing adapter, and the IB-03L DB-native HMAC guard calling D3 atomic session issuance. Tests reject forged EOA signatures before MAC signing, chain/subject mutation, nonce replay and revoked consent.

Critical limits:
- The HMAC signer lives in the same synthetic CI process as the verifier and takes a local ephemeral secret. Isolation from untrusted application code, KMS, HSM and mTLS are NOT proven.
- The adapter reads challenge SQL values, but injects URI, binding and consent versions from lab policy rather than authoritative database fields. Production immutable challenge snapshot must contain all SIWE/context/scopes and versions. Thus an end-to-end context-binding production claim is NOT justified.
- Full EIP-4361 ABNF conformance not established; ERC-1271 on-chain verification not exercised.
- A malicious/compromised signer, database owner, or authenticating host can forge attestations. No real session cookie or production DB grant analysis.
- Distributed revocation/disclosure atomicity, finality, strict SIWE host origin enforcement and peer audit remain blockers.
- No remote deployment, production migration, live wallets, Lovable write or merge.

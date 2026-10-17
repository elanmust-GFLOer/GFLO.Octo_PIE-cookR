# RED TEAM 6D.5 — Source-bound ERC-1271 attestor (experimental)

Status: development branch prototype, **NOT EVM-verified, NOT deployment-ready**.

## Architecture
XPPolicyV03 already calls OpenZeppelin SignatureChecker, including ERC-1271 wallet contracts. Register GFLOSourceBoundAttestorV01 as the *only* permitted XPPolicyV03 rule attestor; an approved off-chain source-issuer ECDSA key separately signs a domain-separated EIP-712 SourceAuthorization(proofDigest, sourceEventKey, validUntil). Any relayer may register this signed authorization. XPPolicyV03.submit uses the ERC-1271 attestor address, and an **empty** 1271 signature. Its validity is checked on-chain against the exact XPPolicy.proofDigest. A sourceEventKey cannot be registered twice. No arbitrary EIP-712 signing API is exposed.

Critical: implementation is a defense-in-depth **proposal**. No code here proves independent completion of OctoPush work. A compromised source issuer can approve fiction. Governance retains the ability to add another XPPolicyV03 attestor, so **the RT6C HIGH issue is NOT closed** until on-chain source pinning, timelocked governance and alternative-attestor bypass are tested and independently reviewed. Governance can also change issuer permissions/pausing. A source reviewer signing key MUST be in a separate trust domain from governance, verifier and attestor service.

## Required end-to-end tests (pending, must use signed EthereumJS transactions)

1. Unregistered fabricated XP digest rejected by XPPolicyV03.
2. Random attacker source signature rejected by registerApproval.
3. Correct issuer-authorized digest accepted by ERC-1271, still subject to XPPolicy verifier role, rule, anti-replay and PENDING.
4. Tampered proof digest, event key, expiry or EIP-712 chain/contract domain rejected.
5. Duplicate sourceEventKey rejected even for different XP proof digest.
6. Deadline expiry, pause, issuer revocation and explicit approval revocation each fail closed.
7. A governance-authorized alternate attestor can still bypass adapter (HIGH architectural finding).
8. Untruthful but source-issuer-signed work can still pass (HIGH upstream truth risk).
9. Run mutations, Safe 2/3 authorized configuration and audit before testnet.

## Safety assumptions and rollout

The earlier 6D.4 PostgreSQL gate supplies an outbox only; no source EIP-712 signer implementation was connected or tested. `SOURCE_AUTH_TYPEHASH` authorization is *not* identical to the Ed25519 Source Proof Adapter signature, and a carefully isolated audited bridge/service is needed to map trustworthy reviewed outbox records to issuer authorizations.

Do not put source issuer private keys in code, GitHub secrets available to untrusted pull requests, Supabase browser clients, or a generic sign-anything API. A direct `XPPolicyV03.submit` path still exists via governance-authorized keys. No production migration, real token movement or OctoPush deployment is authorized.

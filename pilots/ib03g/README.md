# GFLO IB-03G — Role Split / Non-bypassable LAB Admission
Scope: PostgreSQL 16 disposable CI; **NOT A PRODUCTION NON-BYPASSABILITY PROOF**.

The **IB-03F direct issuance function is explicitly REVOKED** from gflo_admission_lab. A new verifier-only SQL registration function records challenge-bound, short-lived, single-use proof evidence. An admission-only redemption function requires that record and invokes the atomic D3 session transaction. Browser cannot access either role. Synthetic EOA keys are used in the CI verifier process; the actual EIP-191 signature is verified before the verifier-only function is called.

Threat-model limitations:
1. The verifier SQL role can call register_verification without doing EIP-191; compromise of verifier is not contained by DB-level cryptographic signature checks. A cryptographic attestation/key isolation gate is needed before any production claim.
2. SQL SECURITY DEFINER functions are owned by the disposable test superuser; real DB grants, function ownership, RLS and search-path hardening require separate independent review.
3. A compromised DB owner can write arbitrary proof/session data. Cross-service authorization cannot resist a malicious trust root.
4. The old D3 function exists and is callable by database owner. Application roles lack access; production privileged backend inventory remains unverified.
5. The verification-to-registration hop has not been proved unforgeable if the verifier role is compromised; no true HSM signatures, mTLS identity or enclave attestations.
6. The SIWE parser is not full EIP-4361 ABNF; real EVM ERC-1271 verification not yet executed.
7. Session tokens/cookies and distributed revocation fencing are not production-ready.

Do not merge, deploy, migrate Supabase or modify Lovable. Lab completion means only that an untrusted admission account cannot bypass verifier-only registration under these specific PG grants.

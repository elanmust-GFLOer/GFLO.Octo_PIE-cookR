# IB-03D.3 — Transactional Session Issuance and Revocation Fence
LAB scope — independent disposable PostgreSQL 16 only.

- Trusted backend must establish cryptographic EIP-4361 / EIP-191 or ERC-1271 proof BEFORE executing issue_verified_session; database does not verify any signature.
- A successful issuance atomically consumes the challenge and creates session, under row locks: binding -> consent -> challenge. Duplicate or stale challenges cannot result in multiple sessions.
- authorize_read locks binding -> consent -> session; suspension uses same binding -> consent -> session order to avoid the D.2 deadlock case.
- Concurrent consent revocation takes consent lock; successful earlier authorized transaction linearizes before revocation. No response delivery guaranteed atomic with revocation: response-disclosure fencing remains production blocker.
- SQL functions use SECURITY INVOKER. Production RBAC, tenant isolation, SIWE challenge-origin binding and service-only privileges are NOT verified; do not copy directly to shared Supabase.
- No migrations or production writes. Draft PR only.

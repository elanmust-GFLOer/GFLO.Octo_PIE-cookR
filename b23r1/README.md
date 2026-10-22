# B2.3-R1 — Codex BLOCK remediation, isolation-first

Base: PR #9 head `16282d6cfc0bf21d061696db43a5abdf1adac5e5`.
Status: **ISOLATED HARDENING, NOT AUTHENTICATED WALLET BINDING**.

## R1.0: close dangerous routes before extending features
- Revoke `b23_runtime`'s `SELECT` on simulated sessions; revoke `EXECUTE` on `b23_suspend`.
- Require denied calls for `b23_runtime` and PUBLIC, including after `USAGE` on schema is granted.
- Legacy function is still present for historical tests but must not be application reachable.
- No client-supplied user_id/session_id is authoritative. No new app-accessible suspender until a trusted adapter and revocation authority exist.
- Any session-lock simulator results are lab-only; actual Supabase session authority is **BLOCKED**.

## R1.1: fail closed before idempotent return
- For an already suspended binding, verify controller status is suspended and no pending challenge exists; reject inconsistent state, never fake success. Existing epoch consistency is not validated; remediation requires an explicit lifecycle/epoch design.
- A separate audited repair workflow is required for pre-existing inconsistent data.

## R1.2: challenge issue gate (closed to application roles)
- Controller row `FOR UPDATE` first, then check lifecycle state and epoch.
- Insert can occur only from the privileged lab/test owner; no `b23_runtime` direct INSERT nor function `EXECUTE`.
- Suspend and issuance must use the same controller lock for a valid serial order. Provide independent-connection race tests before claiming verified.

## Acceptance and outstanding risks
- Add a baseline-plus-transition CI; separate databases, real runtime grants, audit fault injection and race coverage.
- Auditor owner can still write directly: **AUD-01 BLOCKED**. Isolate operational and owner credentials, create narrow vetted trusted entrypoints with transactional audit and external DBA traceability.
- Independent SIWE + separately signed consent, activation/recovery and real Supabase revocation are **NOT IMPLEMENTED**.
- No production migration, on-chain action, XP, Tier, token or governance privilege.
- No release/merge permitted solely on R1 lab CI green.

## Codex finding map
P1 user/session -> lock down runtime SELECT/EXECUTE.
P1 simulated sessions -> production BLOCK remains.
P1 owner audit-bypass -> production BLOCK remains.
P2 definer role tests -> explicit privilege tests needed.
P2 revoke race -> two-session tests needed.
P2 b22 workflow path -> CI trigger includes b22.
P2 already_suspended -> reject inconsistent state.
P2 issuance/suspension -> shared controller lock and race test.

# B2.3-R1 PostgreSQL laboratory verification

Executed 2026-10-22. [Actions run 39791049224](https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39791049224), job 119866851305, PostgreSQL 16.15, conclusion: success.

Three independently visible SQL NOTICE assertions from the actual job logs: (1) runtime denied sensitive functions and session enumeration, (2) challenge issuer rejects suspended controller, (3) inconsistent pre-suspended row rejects misleading idempotent success.

**Scope only:** tests are sequential laboratory assertions under an isolated disposable DB. They do NOT run all B2.2 baseline tests, true runtime adapter end-to-end auth, actual concurrent issue/suspend races, mandatory owner-resistant audit, production Supabase revocation, signed SIWE, consent or recovery. The lab issuer is closed to runtime; it is not an authenticated challenge API. A green job does not resolve eight prior Codex PR #9 review findings.

**Verdict:** local restrictive subset PASS; security release BLOCK. Keep PR draft and unmerged.

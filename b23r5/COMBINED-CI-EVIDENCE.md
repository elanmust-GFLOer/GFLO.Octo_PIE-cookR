# B2.3-R5 — combined security evidence (2026-10-22)

## Executed
- Commit containing code/test changes: `6eb14dc1bdfbae3b8f6c845cc055743b6c5bcf90`
- GitHub Actions https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39810598862
- Job `119935475475`, completed **success** on disposable PostgreSQL 16
- Two separate databases: `b2test_r4_baseline` and `b2test_r4_transition`
- Exact manifest/assertion count: B2.2 6/6; R2 7/7; R3 6/6; R4 3/3; R5 additions 6/6. Total **28/28 Python PASS**, plus B2.2, B2.3, R1, R5 SQL checks.
- R5 new proof scenarios: deterministic DELETE-first session revocation; mutation rollback followed by DELETE; concurrent identical request -> one audit/epoch/request; conflicting payload race denial; wrong binding/stale epoch refusal; exact named audit-insert fault -> pending challenge, controller, binding, audit and request all rollback.
- This R5 combined CI runs the new R5 quarantine overlay **after** pre-existing R3/R4 laboratory tests. This ordering is intentionally needed so prior baselines remain reproducible but it is not a production privilege implementation.
- Previous R5 first combined run `39810423785` FAILED due to mismatched disposable DB guard; fixed at commit above. Historical failure retained in Actions.
- Separate R5 role matrix evidence: https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39809148352

## What this does NOT establish
- No real Supabase Auth token validation, current session liveness guarantee or cross-service revocation/commit serialization. External Auth design documented at `b23r5/AUTHORITY-CONTRACT.md` only.
- The R3 laboratory suspender still accepts caller-supplied user/session IDs. The R5 overlay denies application and lab-role EXECUTE; the test uses privileged postgres for legacy races, **not a deployable API**.
- No full approved issuer-first -> audited activation -> suspension lifecycle: pilot issuer is `unbound`-only and activation missing.
- No externally tamper-evident administrator audit or superuser protection. B2.2 historical audit-bypass reproducer remains.
- No SIWE, separate signed consent, strong recovery, PIE permission, production deployment, main merge or migration.
- Workflow uses unpinned `postgres:16`, `checkout@v4` and `psycopg[binary]>=3.2,<4`; no downloadable artifact/immutable dependency bill. These are still P2 review blockers for reproducibility.
- Tests demonstrate lock waits via `pg_blocking_pids` before release; the newly introduced tests still need independent red-team review for fault cleanup and race false positives.

## Gate
Isolated DB R5 partial completion: **PASS on executed scoped tests**.
Full authorization-safe wallet binding / production integration: **BLOCK**.
Keep PR #14 draft and unmerged.

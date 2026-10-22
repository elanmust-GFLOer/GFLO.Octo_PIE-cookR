# B2.3-R5 evidence — external Auth design & extended role quarantine
Date 2026-10-22

**Source commit:** `64600485581c628c57bcd5770789ef919bc96f3d`
**GitHub CI:** https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39809148352
**Job:** `119930337744`, completed SUCCESS, disposable PostgreSQL 16.

Confirmed from job log:
- R5 original four-role RPC/DML/session/member denial notice PASS.
- Schema USAGE yet EXECUTE denied notice PASS.
- Expanded 4-role x 7-table INSERT/UPDATE/DELETE/TRUNCATE and membership privilege matrix notice PASS.
- Fake known-victim identifier tuple denied via function EXECUTE ACL notice PASS.

**Limitations:** All tests inspect a lab schema and role boundary; passing a forged context to a blocked function proves RPC ACL denial, not actual identity binding. The implementation does not integrate Supabase getUser/getClaims, session expiration/revocation, signed SIWE, separate consent, recovery, deterministic missing R4 races, a complete build/test manifest, or admin audit. It does not replace the R4 22/22 baseline execution with a fresh combined R5 regression. Supabase production integration and all wallet activation remain BLOCKED.

See `b23r5/AUTHORITY-CONTRACT.md` for an external identity-provider verification design with explicit non-atomic cross-system revocation limitations. No production changes, merge or deployment.

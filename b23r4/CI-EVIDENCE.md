# B2.3-R4 — Combined Security Gate evidence and limits
Date: 2026-10-22

**Disposition:** isolated PG16 combined regression PASS; GFLO OctoPass Backend-2 production/security acceptance **BLOCKED**.

## Exact executed evidence
- GitHub Actions: https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39804196724
- Job: `119912903947` conclusion SUCCESS.
- Run checkout SHA reported `a7b0fcb0d141f45e7d2ff28a4f193764c9aa37df` (PR merge commit). Confirm it has the expected PR head as a parent before treating head as exact tested revision.
- Branch PR #13 head before this evidence-only commit: `111187be4b10ee0a3b047cec0f02b165717a945d`.
- Two fresh disposable databases: `b2test_r4_baseline`, `b2test_r4_transition`.
- Actual Python test groups: B2.2 6/6, R2 7/7, R3 6/6, deterministic R4 3/3 = **22/22**; B2.2, B2.3, R1 SQL checks also executed successfully.
- R4 observed `pg_blocking_pids` against expected blocker PID before transaction release in 3 isolated scenarios: revoke-first UPDATE vs R3 suspension, mutation-first R3 suspension vs revoke UPDATE, controller transition vs laboratory challenge issuance.

## Limitations
1. Not a real Supabase Auth integration. `b23_auth_sim.sessions` is a simulator, and session/user IDs are parameters instead of a trusted verified principal.
2. B2.2 historical owner direct-UPDATE without audit test still passes by reproducing the flaw; do NOT count it as proof of mandatory audit.
3. No deterministic DELETE-based revoke scenario or full issue-first/suspend state-machine path in R4; R1 challenge issuer only permits unbound.
4. The R3 definer and lab caller are not acceptable production authentication surfaces; database-owner/superuser bypass remains.
5. No SIWE verification, separately signed consent, recovery, replica/failover or PIE XP integration.
6. CI uses mutable image tag `postgres:16`, checkout `@v4` and unpinned pip constraint; exact build artifacts/crypto provenance not yet provided.
7. This document commit occurs after the verified run; rerun the PR merge test if head changes materially.

## Codex re-review
Request an independent security review on PR #13 against original eight PR #9 findings plus new R4 changes. No release/merge until remediation evidence is reviewed and authoritative Auth/revocation design is separately approved.

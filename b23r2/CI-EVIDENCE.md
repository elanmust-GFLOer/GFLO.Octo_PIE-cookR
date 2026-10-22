# B2.3-R2 PostgreSQL independent-connection experiments

2026-10-22 | Draft PR #11 | Commit `5e45252829c9791630b2f5131ff02f60cfc35677`

CI: https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39800953806

PostgreSQL 16 isolated runner returned **7/7 unittest PASS**. Individual log checks: issue lock state transition, missing session, mutation-first revoke, mutation rollback, revoke-first DELETE, revoke-first UPDATE, suspended issue reject.

**Narrow evidence / limits:** The tests use independent psycopg connections and overlapping transactions. They do **not** assert actual waiter/blocker lock state via pg_locks, and the release event can occur before the second statement is blocked. Therefore they do not conclusively prove both overlapping lock orders. This is an exploratory lab PASS, not completion of the Codex-required race acceptance gate. Current R1 issuer only allows `unbound`, while suspend needs a binding that is `active`; its test simulates a controller lifecycle transition, not a full issue/suspend business lifecycle. Direct owner INSERT to challenges and owner audit bypass remain open; no production security claim.

Next: add deterministic lock-wait observation (pg_stat_activity/pg_blocking_pids), enforce ordering, both UPDATE and DELETE revocation, explicit audited failure rollback, auth generation, and full separate-database B2.2 + B2.3 combined suite. Supabase authority remains BLOCKED.

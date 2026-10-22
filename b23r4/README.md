# B2.3-R4 — Combined Security Gate

Runs B2.2's original SQL + six Python tests on fresh disposable DB A and the B2.3, R1, R2, R3 transition with additional deterministic lock-observation tests on separate fresh disposable DB B.

Scope: laboratory Postgres 16 with *simulated* session authority. Never call this an actual Supabase Auth integration, authenticated wallet binding, full state-machine audit or production readiness.

Historical B2.2 owner-audit bypass test remains deliberately intact and PASS means that vulnerability was successfully reproduced, **not** that auditing is secured.

Deterministic lock probes assert `pg_blocking_pids` before the releasing transaction commits. Test success is narrower than proving all possible interleavings, recovery, real Auth revocation or non-DB cache consistency.

Keep PR draft, no merge/deploy. Codex re-review should assess actual CI logs, prior eight PR #9 findings and this PR's new limitations.

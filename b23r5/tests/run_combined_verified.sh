#!/usr/bin/env bash
set -euo pipefail
[[ "${PGHOST:-}" == "127.0.0.1" && "${B22_DISPOSABLE_ACK:-}" == YES && "${B23_DISPOSABLE_ACK:-}" == YES ]] || exit 2
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PGOPTIONS="-c gflo.b2_disposable_ok=YES"
export PGDATABASE=b2test_r4_baseline
psql -X -v ON_ERROR_STOP=1 -f "$root/b22/sql/001_backend2_schema_DRAFT.sql"
psql -X -v ON_ERROR_STOP=1 -f "$root/b22/tests/01_schema_invariants.sql"
python3 "$root/b23r5/tests/04_verified_suite.py" "$root/b22/tests/02_pg_races.py" 6
export PGDATABASE=b2test_r4_transition
psql -X -v ON_ERROR_STOP=1 -f "$root/b22/sql/001_backend2_schema_DRAFT.sql"
psql -X -v ON_ERROR_STOP=1 -f "$root/b23/sql/002_b23_auth_audit.sql"
psql -X -v ON_ERROR_STOP=1 -f "$root/b23/tests/01_auth_audit.sql"
psql -X -v ON_ERROR_STOP=1 -f "$root/b23/tests/02_role_denial.sql"
psql -X -v ON_ERROR_STOP=1 -f "$root/b23r1/sql/003_restrict_and_gate.sql"
psql -X -v ON_ERROR_STOP=1 -f "$root/b23r1/tests/01_r1_restrictions.sql"
python3 "$root/b23r5/tests/04_verified_suite.py" "$root/b23r2/tests/01_races.py" 7
psql -X -v ON_ERROR_STOP=1 -f "$root/b23r3/sql/004_role_audit_lab.sql"
python3 "$root/b23r5/tests/04_verified_suite.py" "$root/b23r3/tests/01_role_audit.py" 6
python3 "$root/b23r5/tests/04_verified_suite.py" "$root/b23r4/tests/01_deterministic_locks.py" 3
python3 "$root/b23r5/tests/04_verified_suite.py" "$root/b23r5/tests/03_deterministic_completion.py" 6
psql -X -v ON_ERROR_STOP=1 -f "$root/b23r5/sql/005_operational_quarantine.sql"
psql -X -v ON_ERROR_STOP=1 -f "$root/b23r5/tests/01_role_quarantine.sql"
psql -X -v ON_ERROR_STOP=1 -f "$root/b23r5/tests/02_operational_matrix.sql"
echo 'R5 combined 28 tests + SQL groups passed, but production Auth is BLOCKED'

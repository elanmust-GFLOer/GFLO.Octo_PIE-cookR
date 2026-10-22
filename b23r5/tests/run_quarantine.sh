#!/usr/bin/env bash
set -euo pipefail
[[ "${PGDATABASE:-}" == b2test_* && "${PGHOST:-}" == 127.0.0.1 && "${B23_DISPOSABLE_ACK:-}" == YES ]] || exit 2
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PGOPTIONS="-c gflo.b2_disposable_ok=YES"
psql -X -v ON_ERROR_STOP=1 -f "$root/b22/sql/001_backend2_schema_DRAFT.sql"
psql -X -v ON_ERROR_STOP=1 -f "$root/b23/sql/002_b23_auth_audit.sql"
psql -X -v ON_ERROR_STOP=1 -f "$root/b23r1/sql/003_restrict_and_gate.sql"
psql -X -v ON_ERROR_STOP=1 -f "$root/b23r3/sql/004_role_audit_lab.sql"
psql -X -v ON_ERROR_STOP=1 -f "$root/b23r5/sql/005_operational_quarantine.sql"
psql -X -v ON_ERROR_STOP=1 -f "$root/b23r5/tests/01_role_quarantine.sql"

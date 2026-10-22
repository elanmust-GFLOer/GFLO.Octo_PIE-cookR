#!/usr/bin/env bash
set -euo pipefail
[[ "${PGDATABASE:-}" == b2test_* && "${B23_DISPOSABLE_ACK:-}" == YES ]] || { echo 'B2.3: disposable acknowledgement missing' >&2; exit 2; }
[[ "${PGHOST:-}" == 127.0.0.1 || "${PGHOST:-}" == localhost ]] || { echo 'B2.3: local host required' >&2; exit 2; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PGOPTIONS="${PGOPTIONS:-} -c gflo.b2_disposable_ok=YES"
psql -X -v ON_ERROR_STOP=1 -f "$ROOT/b22/sql/001_backend2_schema_DRAFT.sql"
psql -X -v ON_ERROR_STOP=1 -f "$ROOT/b23/sql/002_b23_auth_audit.sql"
psql -X -v ON_ERROR_STOP=1 -f "$ROOT/b23/tests/01_auth_audit.sql"
psql -X -v ON_ERROR_STOP=1 -f "$ROOT/b23/tests/02_role_denial.sql"
echo 'B2.3 local simulation subgate completed, production session authority NOT PROVEN'

#!/usr/bin/env bash
# Use ONLY a disposable PostgreSQL instance; refuses non-test db names.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
command -v psql >/dev/null || { echo 'psql unavailable; no PostgreSQL claims' >&2; exit 2; }
: "${PGDATABASE:?Set PGDATABASE to a disposable rt6d4_* database}"
[[ "$PGDATABASE" == rt6d4_* ]] || { echo 'Refusing non-rt6d4_* database' >&2; exit 2; }
[[ "${RT6D4_DISPOSABLE_DB_ACK:-}" == YES ]] || { echo 'Set RT6D4_DISPOSABLE_DB_ACK=YES for isolated database only' >&2; exit 2; }
psql -X -v ON_ERROR_STOP=1 -f tests/00_disposable_roles.sql
psql -X -v ON_ERROR_STOP=1 -f sql/001_gflo_bridge_RT6D4_CANDIDATE.sql
psql -X -v ON_ERROR_STOP=1 -f tests/01_postgres_security.sql
echo 'RT6D4 PostgreSQL 8 groups PASS (disposable DB only)'

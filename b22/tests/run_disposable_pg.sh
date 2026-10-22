#!/usr/bin/env bash
set -euo pipefail
: "${PGDATABASE:?Set PGDATABASE to b2test_*}"
if [[ "${PGDATABASE}" != b2test_* || "${B22_DISPOSABLE_ACK:-}" != YES ]]; then
  echo "Refusing non-disposable database" >&2; exit 2
fi
case "${PGHOST:-}" in localhost|127.0.0.1|/var/run/postgresql) ;; *) echo "Refusing remote PGHOST" >&2; exit 2 ;; esac
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
COUNT="$(psql -X -A -t -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname='private' AND c.relkind IN ('r','p')")"
[[ "$COUNT" == 0 ]] || { echo "Refusing populated private schema" >&2; exit 2; }
PGOPTIONS="${PGOPTIONS:-} -c gflo.b2_disposable_ok=YES" psql -X -v ON_ERROR_STOP=1 -f "$ROOT/sql/001_backend2_schema_DRAFT.sql"
psql -X -v ON_ERROR_STOP=1 -f "$ROOT/tests/01_schema_invariants.sql"
python3 "$ROOT/tests/02_pg_races.py"
echo "B2.2 DB exercises completed; production acceptance remains BLOCKED."

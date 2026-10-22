#!/usr/bin/env bash
set -euo pipefail
[[ "${PGHOST:-}" == 127.0.0.1 && "${PGPORT:-}" == 5432 && "${B22_DISPOSABLE_ACK:-}" == YES && "${B23_DISPOSABLE_ACK:-}" == YES ]] || exit 2
[[ "${R6A_DISPOSABLE_ACK:-}" == YES ]] || exit 2
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p evidence
# Fresh service/container only. Never DROP or reuse a preexisting database.
psql -d postgres -X -v ON_ERROR_STOP=1 -c 'CREATE DATABASE b2test_r4_baseline;'
psql -d postgres -X -v ON_ERROR_STOP=1 -c 'CREATE DATABASE b2test_r4_transition;'
psql -d postgres -X -At -v ON_ERROR_STOP=1 -c "SELECT oid,datname FROM pg_database WHERE datname IN ('b2test_r4_baseline','b2test_r4_transition') ORDER BY datname" | tee evidence/database-identities.log
bash b23r5/tests/run_combined_verified.sh 2>&1 | tee evidence/postgres-tests.log
# No domain/database credential is passed to the gateway/HTTP test process.
unset PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE PGOPTIONS
for suite in test_gateway test_http test_manifest test_deadlines; do
  python3 b23r6a/run_verified.py "b23r6a/tests/${suite}.py" 2>&1 | tee "evidence/${suite}.log"
done
python3 b23r6a/run_verified.py pilot0b/tests/test_manifest.py 2>&1 | tee evidence/pilot0b-manifest.log
python3 b23r6a/frozen_pilot.py 2>&1 | tee evidence/pilot0a-rerun.log
python3 - <<'PY'
import json
from pathlib import Path
root=Path("evidence")
manifest=json.loads(Path("b23r6a/test-manifest.json").read_text())
total=0
for source,expected in manifest.items():
    ledger=json.loads((root/(source.replace("/","_")+".json")).read_text())
    assert sorted(e["test"] for e in ledger["executed"])==sorted(expected)
    assert all(e["status"]=="PASS" for e in ledger["executed"])
    total+=len(expected)
frozen=json.loads((root/"pilot0a-rerun.json").read_text())
assert frozen['status']=='PASS' and frozen['executed']==59 and all(t['status']=='PASS' for t in frozen['tests'])
print(f"COMBINED EXACT MANIFEST PASS {total}/{total} + FROZEN PILOT 0A 59/59; zero skipped; SQL gates completed")
(root/"acceptance.json").write_text(json.dumps({"status":"PASS","python_tests":total,"preserved_r6a":86,"closure_new":total-86,"frozen_pilot0a":59,"total":total+59,"skipped":0,"sql":"PASS","production":"BLOCK"},indent=2)+"\n")
PY

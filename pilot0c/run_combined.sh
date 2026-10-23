#!/usr/bin/env bash
set -euo pipefail
[[ "${PGHOST:-}" == 127.0.0.1 && "${PGPORT:-}" == 5432 && "${R6A_DISPOSABLE_ACK:-}" == YES ]] || exit 2
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# Unchanged 207-case runner and all SQL guards, two separate fresh databases.
bash b23r6a/run_combined.sh
unset PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE PGOPTIONS
node pilot0c/tests.cjs | tee evidence/pilot0c-tests.log
python3 - <<'PY'
import json
from pathlib import Path
out=Path('evidence');old=json.loads((out/'acceptance.json').read_text());new=json.loads((out/'pilot0c-ledger.json').read_text())
expected=json.loads(Path('pilot0c/test-manifest.json').read_text())
assert old['status']=='PASS' and old['total']==207 and old['skipped']==0 and old['sql']=='PASS'
assert new['status']=='PASS' and sorted(t['test'] for t in new['executed'])==expected
assert all(t['status']=='PASS' for t in new['executed']) and len(expected)==96 and new['skipped']==0
result={'status':'PASS','inherited':207,'pilot0c':96,'total':303,'sql':'PASS','skipped':0,'production':'BLOCK'}
(out/'pilot0c-acceptance.json').write_text(json.dumps(result,indent=2)+'\n')
print('PILOT_0C COMBINED EXACT MANIFEST PASS 303/303 + SQL; production BLOCK')
PY

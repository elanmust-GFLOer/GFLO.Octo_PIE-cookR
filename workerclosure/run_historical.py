"""Execute original historical gate once and retain its ledger even on failure."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASE = '12e2df4c32ef51d08c799ec63a565c90221e8bcd'


def main():
    sys.path.insert(0, str(ROOT))
    from b23r6a.frozen_pilot import verify_snapshot
    snapshot = verify_snapshot()
    out = ROOT / 'evidence'
    out.mkdir(exist_ok=True)
    result = None
    code = 2
    with tempfile.TemporaryDirectory(prefix='workerclosure-history-') as directory:
        parent = Path(directory)
        old, pilot = parent / 'gflo-r6a', parent / 'pilot0a'
        subprocess.run(['git', 'worktree', 'add', '--detach', str(old), BASE], cwd=ROOT, check=True)
        try:
            shutil.copytree(snapshot, pilot)
            # The archive contains its original PASS ledger. A new run must
            # never inherit that old result if it aborts before writing a ledger.
            (pilot / 'evidence/test-ledger.json').unlink()
            env = {k: v for k, v in os.environ.items() if not k.startswith('PG') and k != 'PYTHONPATH'}
            with (out / 'workerclosure-historical.log').open('w') as log:
                try:
                    code = subprocess.run([sys.executable, 'run_verified.py'], cwd=pilot, env=env,
                                          stdout=log, stderr=subprocess.STDOUT, timeout=180).returncode
                finally:
                    ledger = pilot / 'evidence/test-ledger.json'
                    if ledger.exists():
                        raw = ledger.read_bytes()
                        (out / 'workerclosure-historical-raw-ledger.json').write_bytes(raw)
                        result = json.loads(raw)
                        result['raw_ledger_sha256'] = hashlib.sha256(raw).hexdigest()
            subprocess.run(['git', 'diff', '--exit-code', 'HEAD', '--'], cwd=old, check=True, capture_output=True)
            if result is not None:
                result.update({'historical_source': BASE, 'runner_exit': code,
                    'worker_sha256': hashlib.sha256((old / 'b23r6a/workers.py').read_bytes()).hexdigest(),
                    'policy': 'ORIGINAL_GATE_UNCHANGED; no waiver; no propagation of current fix'})
                (out / 'workerclosure-historical-ledger.json').write_text(json.dumps(result, indent=2) + '\n')
        finally:
            subprocess.run(['git', 'worktree', 'remove', '--force', str(old)], cwd=ROOT, check=True)
    verify_snapshot()
    print('HISTORICAL_ORIGINAL', result['status'] if result else 'NOT_EXECUTED', 'exit', code)
    if result:
        print('HISTORICAL_NONPASS', json.dumps([{'test': r['name'], 'status': r['status']} for r in result['tests'] if r['status'] != 'PASS']))
    raise SystemExit(0 if result and result['status'] == 'PASS' and code == 0 else 1)


if __name__ == '__main__':
    main()

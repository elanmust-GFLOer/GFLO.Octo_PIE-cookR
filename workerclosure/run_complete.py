"""Execute every suite independently; a red historical suite remains red."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evidence'


def main():
    OUT.mkdir(exist_ok=True)
    assert os.environ.get('PGHOST') == '127.0.0.1' and os.environ.get('PGPORT') == '5432'
    assert all(os.environ.get(k) == 'YES' for k in ('B22_DISPOSABLE_ACK', 'B23_DISPOSABLE_ACK', 'R6A_DISPOSABLE_ACK'))
    commands = []
    def run(name, command, env=None):
        try:
            with (OUT / ('workerclosure-' + name + '.log')).open('w') as log:
                code = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=240).returncode
        except subprocess.TimeoutExpired:
            code = 124
        commands.append({'suite': name, 'exit': code})
        print('SUITE_EXIT', name, code, flush=True)
        return code

    setup = run('database-create', ['psql', '-d', 'postgres', '-X', '-v', 'ON_ERROR_STOP=1', '-c',
        'CREATE DATABASE b2test_r4_baseline;', '-c', 'CREATE DATABASE b2test_r4_transition;'])
    if setup == 0:
        run('database-identities', ['psql', '-d', 'postgres', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c',
            "SELECT oid,datname FROM pg_database WHERE datname IN ('b2test_r4_baseline','b2test_r4_transition') ORDER BY datname"])
    sql = run('postgres', ['bash', 'b23r5/tests/run_combined_verified.sh']) if setup == 0 else None
    env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
    env['PYTHONPATH'] = str(ROOT)
    manifest = json.loads((ROOT / 'b23r6a/test-manifest.json').read_text())
    for source in manifest:
        if source.startswith(('b23r6a/', 'pilot0b/')):
            run(source.replace('/', '_'), [sys.executable, 'b23r6a/run_verified.py', source], env)
    run('historical', [sys.executable, 'workerclosure/run_historical.py'], env)
    run('crypto', ['node', 'pilot0c/tests.cjs'], env)
    run('units', ['node', 'pilot0d1/unit-tests.cjs'], env)
    run('lifecycle', [sys.executable, 'workerclosure/test_lifecycle.py'], env)
    run('causal', [sys.executable, 'pilot0d1/reaping-cause.py'], env)
    rows = []
    def read_ledger(path, expected, suite, field='test', key='executed'):
        file = OUT / path
        data = json.loads(file.read_text()) if file.exists() else {}
        actual = data.get(key, [])
        indexed = {r[field]: r['status'] for r in actual}
        if actual and (len(indexed) != len(actual) or set(indexed) != set(expected)):
            raise RuntimeError('EXACT_TEST_LEDGER_MISMATCH:' + suite)
        for test in expected:
            rows.append({'suite': suite, 'test': test, 'status': indexed.get(test, 'NOT_EXECUTED')})
    for source, expected in manifest.items():
        read_ledger(source.replace('/', '_') + '.json', expected, source)
    read_ledger('workerclosure-historical-ledger.json', json.loads((ROOT / 'pilot0a-frozen/test-manifest.json').read_text()), 'frozen0a', 'name', 'tests')
    read_ledger('pilot0c-ledger.json', json.loads((ROOT / 'pilot0c/test-manifest.json').read_text()), 'pilot0c')
    # The inherited unit runner uses the same exact-name ledger structure.
    read_ledger('pilot0d1-unit-ledger.json', json.loads((ROOT / 'pilot0d1/unit-manifest.json').read_text()), 'pilot0d1-units')
    read_ledger('workerclosure-ledger.json', json.loads((ROOT / 'workerclosure/test-manifest.json').read_text()), 'workerclosure')
    causal = OUT / 'pilot0d1r-reaping-cause.json'
    probe = json.loads(causal.read_text()) if causal.exists() else {}
    rows.append({'suite': 'causal', 'test': 'reaping.peer_waitpid_cache_window_reproduces_false_unreaped', 'status': probe.get('status', 'NOT_EXECUTED')})
    assert len(rows) == 340
    counts = {s: sum(r['status'] == s for r in rows) for s in ('PASS', 'FAIL', 'ERROR', 'STARTED', 'SKIPPED', 'NOT_EXECUTED')}
    current = [r for r in rows if r['suite'] != 'frozen0a']
    current_ok = all(r['status'] == 'PASS' for r in current) and sql == 0
    all_ok = current_ok and all(r['status'] == 'PASS' for r in rows) and all(c['exit'] == 0 for c in commands)
    result = {'cohort': os.environ.get('WORKER_COHORT'), 'head': os.environ.get('GITHUB_SHA'),
        'status': 'PASS' if all_ok else 'FAIL', 'current_code': 'PASS' if current_ok else 'FAIL',
        'sql': 'PASS' if sql == 0 else 'FAIL', 'historical_policy': 'UNMODIFIED_STRICT_GATE_NO_WAIVER',
        'counts': counts, 'executed': rows, 'commands': commands, 'production': 'BLOCK', 'pilot0d2': 'HOLD'}
    (OUT / 'workerclosure-complete-ledger.json').write_text(json.dumps(result, indent=2) + '\n')
    print('WORKER_CLOSURE_COMPLETE', json.dumps({k: v for k, v in result.items() if k not in ('executed', 'commands')}))
    print('WORKER_CLOSURE_NONPASS', json.dumps([r for r in rows if r['status'] != 'PASS']))
    raise SystemExit(0 if all_ok else 1)


if __name__ == '__main__':
    main()

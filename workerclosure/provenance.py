"""Narrow correction allowlist relative to the exact causal-reproducer commit."""
import ast
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = 'cbc4cbdaa3c6cb80aa797e3f91b3dc0000a680a8'
HISTORY = '12e2df4c32ef51d08c799ec63a565c90221e8bcd'


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()


def main():
    sys.path.insert(0, str(ROOT))
    for row in git('ls-tree', '-r', BASE).splitlines():
        info, path = row.split('\t')
        mode, kind, sha = info.split()
        if path != 'b23r6a/workers.py':
            assert kind == 'blob' and git('hash-object', path) == sha, 'inherited source changed: ' + path
    for row in git('diff', '--name-status', BASE, 'HEAD').splitlines():
        status, path = row.split('\t')
        assert ((status == 'M' and path == 'b23r6a/workers.py') or
                (status == 'A' and (path.startswith('workerclosure/') or path in
                 {'b23r6a/process_lifecycle.py', '.github/workflows/workerclosure.yml'}))), row
    from b23r6a.frozen_pilot import verify_snapshot
    verify_snapshot()
    from b23r6a.process_lifecycle import OwnedSpawnContext
    OwnedSpawnContext()
    from pilot0d1 import provenance as inherited
    inherited.ALLOWED = inherited.ALLOWED | {'b23r6a/workers.py'}
    inherited.verify_source()
    source = ast.parse((ROOT / 'workerclosure/test_lifecycle.py').read_text())
    actual = sorted(c.name + '.' + m.name for c in source.body if isinstance(c, ast.ClassDef)
                    for m in c.body if isinstance(m, ast.FunctionDef) and m.name.startswith('test_'))
    assert actual == json.loads((ROOT / 'workerclosure/test-manifest.json').read_text())
    assert len(actual) == len(set(actual)) == 17
    versions = {n: importlib.metadata.version(n) for n in ('PyJWT', 'psycopg', 'psycopg-binary', 'typing-extensions')}
    assert versions == {'PyJWT': '2.15.1', 'psycopg': '3.3.6', 'psycopg-binary': '3.3.6', 'typing-extensions': '4.15.0'}
    assert git('rev-parse', 'HEAD') == os.environ['GITHUB_SHA']
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, 'HEAD'], cwd=ROOT, check=True)
    import multiprocessing.process
    import multiprocessing.popen_fork
    import multiprocessing.popen_spawn_posix
    runtime_files = [Path(m.__file__) for m in (multiprocessing.process, multiprocessing.popen_fork, multiprocessing.popen_spawn_posix)]
    result = {'base': BASE, 'head': git('rev-parse', 'HEAD'), 'tree': git('rev-parse', 'HEAD^{tree}'),
        'parents': git('show', '-s', '--format=%P', 'HEAD').split(), 'python': sys.version,
        'run': os.environ['GITHUB_RUN_ID'], 'cohort': os.environ.get('WORKER_COHORT', 'browser'),
        'dependencies': versions, 'runtime_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in runtime_files},
        'historical_worker_blob': git('rev-parse', HISTORY + ':b23r6a/workers.py'),
        'current_worker_blob': git('hash-object', 'b23r6a/workers.py'),
        'file_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in git('ls-files').splitlines()}}
    out = ROOT / 'evidence'; out.mkdir(exist_ok=True)
    (out / 'workerclosure-provenance.json').write_text(json.dumps(result, indent=2) + '\n')
    print('WORKER_CLOSURE_PROVENANCE', json.dumps({k: v for k, v in result.items() if k != 'file_sha256'}))


if __name__ == '__main__':
    main()

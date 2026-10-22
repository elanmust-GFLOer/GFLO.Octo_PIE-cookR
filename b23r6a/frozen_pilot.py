"""Rerun preserved Pilot 0A against its exact historical R6A, never new code.

All temporary files/worktrees are disposable. The source and archived evidence
under pilot0a-frozen remain byte-for-byte unchanged, including known findings.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
BASE="12e2df4c32ef51d08c799ec63a565c90221e8bcd"

def verify_snapshot():
    snapshot=ROOT/"pilot0a-frozen"
    inventory=json.loads((ROOT/"pilot0b/pilot0a-inventory.json").read_text())
    actual={p.relative_to(snapshot).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in snapshot.rglob("*") if p.is_file()}
    assert actual==inventory,"frozen Pilot 0A file inventory changed"
    pinned=json.loads((snapshot/"file-manifest.json").read_text())
    assert all(actual.get(p)==h for p,h in pinned.items()),"original source fingerprints changed"
    assert len(json.loads((snapshot/"test-manifest.json").read_text()))==59
    return snapshot

def main():
    snapshot=verify_snapshot()
    with tempfile.TemporaryDirectory(prefix="gflo-frozen-0a-") as directory:
        parent=Path(directory);old=parent/"gflo-r6a"
        subprocess.run(["git","worktree","add","--detach",str(old),BASE],cwd=ROOT,check=True)
        try:
            pilot=parent/"gflo-id-entity-pilot-0a"
            shutil.copytree(snapshot,pilot)
            environment={k:v for k,v in os.environ.items() if not k.startswith("PG")}
            environment.pop("PYTHONPATH",None)
            subprocess.run([sys.executable,"run_verified.py"],cwd=pilot,env=environment,check=True,timeout=180)
            result=json.loads((pilot/"evidence/test-ledger.json").read_text())
            assert result["status"]=="PASS" and result["executed"]==59
            out=ROOT/"evidence";out.mkdir(exist_ok=True)
            result['historical_source']=BASE
            result['interpretation']='Original diagnostics reproduce historical flaws; not claims about new code.'
            (out/"pilot0a-rerun.json").write_text(json.dumps(result,indent=2)+"\n")
        finally:
            subprocess.run(["git","worktree","remove","--force",str(old)],cwd=ROOT,check=True)
    verify_snapshot()

if __name__=="__main__":main()

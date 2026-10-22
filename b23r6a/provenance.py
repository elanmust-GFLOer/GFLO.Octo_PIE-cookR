"""Fail-closed checkout, immutable references and exact manifest provenance."""
import ast
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
BASE="2362ce622daf896248265a03efca00d6ef72a9a7"
def git(*args):
    return subprocess.check_output(["git",*args],cwd=ROOT,text=True).strip()
def main():
    event=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    checkout=git("rev-parse","HEAD")
    tree=git("rev-parse","HEAD^{tree}")
    if os.environ["GITHUB_EVENT_NAME"]=="pull_request":
        pr=event["pull_request"]
        assert pr["base"]["sha"]==BASE, "R5 base changed"
        head=pr["head"]["sha"]
        assert git("show","-s","--format=%P",checkout).split()==[BASE,head], "unexpected merge parents"
        assert tree==git("rev-parse",head+"^{tree}"), "merge tree differs from R6A head"
    else:
        head=os.environ["GITHUB_SHA"]
        assert checkout==head
    subprocess.run(["git","merge-base","--is-ancestor",BASE,head],cwd=ROOT,check=True)
    manifest=json.loads((ROOT/"b23r6a/test-manifest.json").read_text())
    for path,expected in manifest.items():
        source=ast.parse((ROOT/path).read_text())
        actual=sorted(c.name+"."+m.name for c in source.body if isinstance(c,ast.ClassDef)
                      for m in c.body if isinstance(m,ast.FunctionDef) and m.name.startswith("test_"))
        assert actual==sorted(expected), "manifest substitution: "+path
        if not path.startswith("b23r6a/"):
            original=ast.parse(git("show",BASE+":"+path))
            pinned=sorted(c.name+"."+m.name for c in original.body if isinstance(c,ast.ClassDef)
                          for m in c.body if isinstance(m,ast.FunctionDef) and m.name.startswith("test_"))
            assert pinned==sorted(expected), "R5 baseline test identities changed"
    # R5 quarantine definitions are byte-for-byte unchanged.
    assert git("rev-parse",BASE+":b23r5/sql/005_operational_quarantine.sql")==git("hash-object","b23r5/sql/005_operational_quarantine.sql")
    for workflow in (ROOT/".github/workflows").glob("*.yml"):
        text=workflow.read_text()
        assert all(re.fullmatch(r"[0-9a-f]{40}",ref) for ref in re.findall(r"uses: [^@\s]+@([^\s]+)",text)), "mutable Action reference"
        assert all(re.fullmatch(r"postgres:16@sha256:[0-9a-f]{64}",image) for image in re.findall(r"image: ([^\s]+)",text)), "mutable PostgreSQL reference"
        assert all("--require-hashes --only-binary=:all: -r b23r6a/requirements.lock" in line for line in text.splitlines() if "pip install" in line), "unlocked dependency installation"
    tracked=git("ls-files").splitlines()
    hashes={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in tracked}
    import importlib.metadata as md
    deps={p:md.version(p) for p in ("PyJWT","psycopg","psycopg-binary","typing-extensions")}
    assert deps=={"PyJWT":"2.15.1","psycopg":"3.3.6","psycopg-binary":"3.3.6","typing-extensions":"4.15.0"}
    assert sys.version_info[:2]==(3,12)
    result={"base":BASE,"head":head,"checkout":checkout,"tree":tree,
            "parents":git("show","-s","--format=%P",checkout).split(),
            "run_id":os.environ["GITHUB_RUN_ID"],"run_attempt":os.environ["GITHUB_RUN_ATTEMPT"],
            "python":sys.version,"dependencies":deps,"file_sha256":hashes,"manifest":manifest,
            "postgres_image":"postgres:16@sha256:9e2cf6287f25c3151f4c9421ccce2b17f3e60061c111a29165e0d2cdd9ff0a97"}
    out=ROOT/"evidence";out.mkdir(exist_ok=True)
    (out/"provenance.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k not in ("file_sha256","manifest")},indent=2))
if __name__=="__main__": main()

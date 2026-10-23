"""Only additive Pilot 0C changes; exact inherited 207 identities and source blobs."""
import hashlib,json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASE='e9e1c2f3ae599046ac7c16788a6b6aa1cea1534b'
def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT,text=True).strip()
def verify_source():
    for row in git('ls-tree','-r',BASE).splitlines():
        info,path=row.split('\t');mode,kind,sha=info.split()
        assert kind=='blob' and git('hash-object',path)==sha,'inherited blob changed: '+path
    old=json.loads((ROOT/'b23r6a/test-manifest.json').read_text())
    frozen=json.loads((ROOT/'pilot0a-frozen/test-manifest.json').read_text())
    assert sum(map(len,old.values()))==148 and len(frozen)==59
    expected=json.loads((ROOT/'pilot0c/test-manifest.json').read_text())
    actual=sorted(re.findall(r"^test\('([^']+)'",(ROOT/'pilot0c/tests.cjs').read_text(),re.M))
    assert actual==expected and len(actual)==len(set(actual))==96,'Pilot 0C manifest mismatch'
    dep=json.loads((ROOT/'pilot0c/dependency-manifest.json').read_text())
    raw=(ROOT/dep['local_path']).read_bytes()
    assert len(raw)==dep['size'] and hashlib.sha256(raw).hexdigest()==dep['sha256']
    assert git('hash-object',dep['local_path'])==dep['git_blob'],'upstream bundle mismatch'
    assert dep['upstream_commit']=='9fd9d41d017a5e3b329aca47c79786e69cd40b99'
    assert dep['production_approved'] is False
    # Network/database/chain mutation APIs are not imported by the proof service.
    for name,allowed in [('proof.cjs',{'node:crypto','node:perf_hooks','./crypto.cjs'}),
                         ('crypto.cjs',{'node:fs','node:path','node:crypto','./dependency-manifest.json','./vendor/ethers.umd.min.cjs'})]:
        imports=set(re.findall(r"require\('([^']+)'\)",(ROOT/'pilot0c'/name).read_text()))
        assert imports<=allowed,(name,imports)
    for wf in (ROOT/'.github/workflows').glob('*.yml'):
        content=wf.read_text()
        assert all(re.fullmatch('[0-9a-f]{40}',v) for v in re.findall(r'uses: [^@\s]+@([^\s]+)',content))
        assert all(re.fullmatch('postgres:16@sha256:[0-9a-f]{64}',v) for v in re.findall(r'image: ([^\s]+)',content))
    return dep,expected
def main():
    dep,expected=verify_source()
    checkout=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}')
    event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    if os.environ['GITHUB_EVENT_NAME']=='pull_request':
        pr=event['pull_request'];assert pr['base']['sha']==BASE,'base moved'
        head=pr['head']['sha'];assert git('show','-s','--format=%P',checkout).split()==[BASE,head]
        assert tree==git('rev-parse',head+'^{tree}')
    else:head=os.environ['GITHUB_SHA'];assert checkout==head
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],cwd=ROOT,check=True)
    changed=git('diff','--name-status',BASE,head).splitlines()
    assert all(row.startswith('A\tpilot0c/') or row=='A\t.github/workflows/pilot0c.yml' for row in changed),'non-additive change'
    import importlib.metadata as md
    deps={name:md.version(name) for name in ('PyJWT','psycopg','psycopg-binary','typing-extensions')}
    assert deps=={'PyJWT':'2.15.1','psycopg':'3.3.6','psycopg-binary':'3.3.6','typing-extensions':'4.15.0'}
    assert sys.version_info[:2]==(3,12)
    assert subprocess.check_output(['node','--version'],text=True).strip()=='v22.14.0'
    result={'base':BASE,'head':head,'checkout':checkout,'tree':tree,'parents':git('show','-s','--format=%P',checkout).split(),
            'run_id':os.environ['GITHUB_RUN_ID'],'run_attempt':os.environ['GITHUB_RUN_ATTEMPT'],
            'node':subprocess.check_output(['node','--version'],text=True).strip(),'python':sys.version,
            'dependency':dep,'python_dependencies':deps,'pilot0c_expected':expected,'preserved_tests':207,
            'file_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in git('ls-files').splitlines()}}
    out=ROOT/'evidence';out.mkdir(exist_ok=True);(out/'pilot0c-provenance.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('file_sha256','pilot0c_expected')},indent=2))
if __name__=='__main__':main()

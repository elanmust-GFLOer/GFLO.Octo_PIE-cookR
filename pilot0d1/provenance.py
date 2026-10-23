"""Inherited 303 test identities/SQL unchanged; two explicit core extension files."""
import hashlib,json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
BASE='44d077f4f0d8a0a978fb18ad18190ee361cc9608'
ALLOWED={'pilot0c/proof.cjs','pilot0c/proof.d.cts'}
IMAGE='mcr.microsoft.com/playwright:v1.56.1-noble@sha256:f1e7e01021efd65dd1a2c56064be399f3e4de00fd021ac561325f2bfbb2b837a'
def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT,text=True).strip()
def verify_source():
    for row in git('ls-tree','-r',BASE).splitlines():
        data,name=row.split('\t');mode,kind,sha=data.split()
        if name not in ALLOWED:assert kind=='blob' and git('hash-object',name)==sha,'inherited blob changed: '+name
    assert sum(map(len,json.loads((ROOT/'b23r6a/test-manifest.json').read_text()).values()))+len(json.loads((ROOT/'pilot0a-frozen/test-manifest.json').read_text()))+len(json.loads((ROOT/'pilot0c/test-manifest.json').read_text()))==303
    for file,manifest in [('unit-tests.cjs','unit-manifest.json'),('browser-tests.cjs','browser-manifest.json')]:
        actual=sorted(re.findall(r"^test\('([^']+)'",(ROOT/'pilot0d1'/file).read_text(),re.M))
        assert actual==json.loads((ROOT/'pilot0d1'/manifest).read_text()) and len(actual)==len(set(actual))
    dep=json.loads((ROOT/'pilot0c/dependency-manifest.json').read_text())
    assert hashlib.sha256((ROOT/dep['local_path']).read_bytes()).hexdigest()==dep['sha256']
    browser=json.loads((ROOT/'pilot0d1/dependencies.json').read_text())
    assert browser['browser_image']==IMAGE and browser['playwright_revision']=='1194'
    for file in (ROOT/'.github/workflows').glob('*.yml'):
        text=file.read_text();assert all(re.fullmatch('[0-9a-f]{40}',x) for x in re.findall(r'uses: [^@\s]+@([^\s]+)',text))
    client='\n'.join(p.read_text() for p in (ROOT/'pilot0d1/frontend').glob('*.mjs'))
    for forbidden in ('localStorage','sessionStorage','window.ethereum','innerHTML','eval(','node:','require('):
        assert forbidden not in client,'client boundary violation: '+forbidden
    # Check import paths, not consent-version data (the inherited version is pilot0c/1).
    expected={'app.mjs':['./wallet.mjs','./policy.mjs'],'wallet.mjs':[],'policy.mjs':[]}
    for path in (ROOT/'pilot0d1/frontend').glob('*.mjs'):
        source=path.read_text()
        imports=re.findall(r"^import\s+.+?\s+from\s+['\"]([^'\"]+)['\"]",source,re.M)
        assert path.name in expected and imports==expected[path.name],'unexpected client imports: '+path.name
        assert not re.search(r"(?:from\s*|import\s*\()\s*['\"][^'\"]*pilot0c/",source),'server verifier import in client'
    server=(ROOT/'pilot0d1/server.cjs').read_text();assert "require('./fixtures.cjs')" not in server
    assert "'127.0.0.1'" in server and '43817' in server
def main():
    verify_source();event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text());checkout=git('rev-parse','HEAD');tree=git('rev-parse','HEAD^{tree}')
    if os.environ['GITHUB_EVENT_NAME']=='pull_request':
        pr=event['pull_request'];assert pr['base']['sha']==BASE;head=pr['head']['sha'];assert git('show','-s','--format=%P',checkout).split()==[BASE,head];assert tree==git('rev-parse',head+'^{tree}')
    else:head=os.environ['GITHUB_SHA'];assert head==checkout
    for row in git('diff','--name-status',BASE,head).splitlines():
        status,name=row.split('\t');assert (status=='M' and name in ALLOWED) or (status=='A' and (name.startswith('pilot0d1/') or name=='.github/workflows/pilot0d1.yml'))
    result={'base':BASE,'head':head,'checkout':checkout,'tree':tree,'parents':git('show','-s','--format=%P',checkout).split(),'run_id':os.environ['GITHUB_RUN_ID'],'job':os.environ['GITHUB_JOB'],'python':sys.version,'browser_image':IMAGE,'inherited_tests':303,'file_sha256':{f:hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in git('ls-files').splitlines()}}
    out=ROOT/'evidence';out.mkdir(exist_ok=True);(out/('pilot0d1-provenance-'+os.environ['GITHUB_JOB']+'.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='file_sha256'},indent=2))
if __name__=='__main__':main()

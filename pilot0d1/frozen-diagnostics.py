"""Bounded disposable diagnostics; never a substitute for the original gate."""
import functools
import hashlib
import importlib.metadata
import json
import platform
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
BASE='12e2df4c32ef51d08c799ec63a565c90221e8bcd'

def probe():
    import run_verified
    import test_pilot
    from harness import Harness
    from bootstrap import WorkerSupervisor
    for name,wanted in json.loads(Path('file-manifest.json').read_text()).items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==wanted
    original_run=WorkerSupervisor.run
    original_read=Harness.read
    rows=[]
    lock=threading.Lock()
    trials=[]
    current=0
    @functools.wraps(original_run)
    def observed_run(self,adapter,method,args,deadline,stage_limit=.4):
        begin=time.monotonic();state='RETURNED'
        try:return original_run(self,adapter,method,args,deadline,stage_limit)
        except BaseException as error:
            state=type(error).__name__;raise
        finally:
            end=time.monotonic()
            with lock:rows.append({'trial':current,'stage':type(adapter).__name__+'.'+method,'outcome':state,'elapsed_ms':round((end-begin)*1000,3),'remaining_before_ms':round((deadline-begin)*1000,3),'remaining_after_ms':round((deadline-end)*1000,3)})
    @functools.wraps(original_read)
    def observed_read(self,*args,**kwargs):
        original_deliver=kwargs.get('deliver')
        released=0
        def delivery(value):
            nonlocal released
            released+=1
            return original_deliver(value)
        if original_deliver is not None:kwargs['deliver']=delivery
        begin=time.monotonic()
        decision=original_read(self,*args,**kwargs)
        with lock:rows.append({'trial':current,'decision':decision.outcome,'reason':decision.reason,'released':released,'elapsed_ms':round((time.monotonic()-begin)*1000,3)})
        return decision
    WorkerSupervisor.run=observed_run
    Harness.read=observed_read
    try:
        for current in range(1,4):
            case=test_pilot.IdentitySecurity('test_concurrent_same_consent_is_single_use')
            result=unittest.TestResult()
            case.run(result)
            trials.append({'trial':current,'test':case.id(),'successful':result.wasSuccessful(),'executed':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped)})
    finally:
        WorkerSupervisor.run=original_run
        Harness.read=original_read
    for name,wanted in json.loads(Path('file-manifest.json').read_text()).items():
        assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==wanted
    payload={'classification':'DIAGNOSTIC_ONLY_NOT_ACCEPTANCE_SUBSTITUTE','source':BASE,'python':sys.version,'PyJWT':importlib.metadata.version('PyJWT'),'platform':platform.platform(),'trials':trials,'observations':rows,'scope':'offline synthetic; no network; original case/assertions/deadlines unchanged'}
    Path(sys.argv[2]).write_text(json.dumps(payload,indent=2)+'\n')
    print(json.dumps({'trials':trials,'decisions':[r for r in rows if 'decision' in r]}))
    if any(not trial['successful'] or trial['executed']!=1 or trial['skipped'] for trial in trials):
        raise SystemExit('DIAGNOSTIC_ORIGINAL_ASSERTION_FAILED')

def main():
    if os.environ.get('GFLO_DISPOSABLE_LOCALHOST')!='YES':
        raise SystemExit('DISPOSABLE_ACK_REQUIRED')
    from b23r6a.frozen_pilot import verify_snapshot
    snapshot=verify_snapshot()
    output=ROOT/'evidence'/'pilot0d1-frozen-diagnostics.json'
    output.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='gflo-frozen-diagnostic-') as directory:
        parent=Path(directory);old=parent/'gflo-r6a';pilot=parent/'gflo-id-entity-pilot-0a'
        subprocess.run(['git','worktree','add','--detach',str(old),BASE],cwd=ROOT,check=True,capture_output=True)
        try:
            shutil.copytree(snapshot,pilot)
            shutil.copy2(__file__,pilot/'probe.py')
            environment={key:value for key,value in os.environ.items() if not key.startswith('PG')}
            environment.pop('PYTHONPATH',None)
            subprocess.run([sys.executable,'probe.py','--probe',str(output)],cwd=pilot,env=environment,check=True,timeout=30)
        finally:subprocess.run(['git','worktree','remove','--force',str(old)],cwd=ROOT,check=True,capture_output=True)
    verify_snapshot()

if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--probe':probe()
    else:
        sys.path.insert(0,str(ROOT));main()

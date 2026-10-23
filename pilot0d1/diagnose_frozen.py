"""Observe unmodified historical tests in a disposable copy; never relax their limits."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import multiprocessing.process
import multiprocessing.popen_fork
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
ANCHOR = '12e2df4c32ef51d08c799ec63a565c90221e8bcd'
NAME = 'test_pilot.IdentitySecurity.test_concurrent_same_consent_is_single_use'

def main():
    from b23r6a.frozen_pilot import verify_snapshot
    snapshot = verify_snapshot()
    out = ROOT / 'evidence'
    out.mkdir(exist_ok=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix='gflo-0d1r-') as directory:
        parent = Path(directory)
        old = parent / 'gflo-r6a'
        subprocess.run(['git','worktree','add','--detach',str(old),ANCHOR],cwd=ROOT,check=True)
        try:
            pilot = parent / 'pilot0a'
            shutil.copytree(snapshot,pilot)
            sys.path.insert(0,str(pilot))
            import test_pilot
            from harness import Harness
            from bootstrap import WorkerSupervisor
            original_run, original_read = WorkerSupervisor.run, Harness.read
            process_methods={name:getattr(multiprocessing.process.BaseProcess,name) for name in ('join','is_alive','terminate','kill')}
            original_waitpid=os.waitpid
            original_poll=multiprocessing.popen_fork.Popen.poll
            events = []
            event_lock = threading.Lock()
            origin = time.monotonic()
            labels={}
            def label(pid):
                with event_lock:
                    return labels.setdefault(pid,'child-'+str(len(labels)+1))
            def record(row):
                with event_lock: events.append(row)
            def process_observer(name,original):
                def observed(self,*args,**kwargs):
                    start=time.monotonic();value=None;error=None
                    try:
                        value=original(self,*args,**kwargs)
                        return value
                    except BaseException as exc:
                        error=type(exc).__name__
                        raise
                    finally:
                        popen=self._popen
                        record({'event':'process','method':name,'thread':threading.current_thread().name,
                            'child':label(getattr(popen,'pid',None)),
                            'start_ms':round((start-origin)*1000,3),'duration_ms':round((time.monotonic()-start)*1000,3),
                            'returncode_cached':getattr(popen,'returncode',None),
                            'alive':value if name=='is_alive' else None,'error':error})
                return observed
            def observed_waitpid(pid,flags):
                try:
                    result=original_waitpid(pid,flags)
                except OSError as error:
                    record({'event':'waitpid','child':label(pid),'thread':threading.current_thread().name,'errno':error.errno})
                    raise
                if result[0]:
                    record({'event':'waitpid','child':label(pid),'thread':threading.current_thread().name,'reaped':True,'exit_code':os.waitstatus_to_exitcode(result[1])})
                return result
            # Diagnostic counterfactual only. This never changes the historical file or acceptance runner.
            poll_locks={}
            def serialized_poll(self,*args,**kwargs):
                with event_lock:
                    lock=poll_locks.setdefault(self,threading.RLock())
                with lock:return original_poll(self,*args,**kwargs)
            def measured_run(self,adapter,method,args,deadline,stage_limit=.4):
                start = time.monotonic()
                status = 'RETURNED'
                try:
                    return original_run(self,adapter,method,args,deadline,stage_limit)
                except BaseException as exc:
                    status = type(exc).__name__
                    import traceback
                    record({'event':'exception','thread':threading.current_thread().name,
                        'type':status,'known_code':str(exc) if str(exc) in ('adapter process could not be reaped','adapter failed') else 'REDACTED',
                        'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno} for f in traceback.extract_tb(exc.__traceback__)],
                        'supervisor_failed':self.failed,'active_count':len(self.active)})
                    raise
                finally:
                    record({'event':'worker','thread':threading.current_thread().name,
                        'adapter':type(adapter).__name__,'method':method,'status':status,
                        'start_ms':round((start-origin)*1000,3),
                        'duration_ms':round((time.monotonic()-start)*1000,3),
                        'remaining_at_start_ms':round((deadline-start)*1000,3),
                        'stage_limit_ms':stage_limit*1000,'active_after':len(self.active)})
            def measured_read(self,*args,**kwargs):
                start=time.monotonic();count=0;deliver=kwargs.get('deliver')
                def delivery(body):
                    nonlocal count
                    count+=1
                    return deliver(body)
                if deliver is not None: kwargs['deliver']=delivery
                decision=original_read(self,*args,**kwargs)
                record({'event':'read','thread':threading.current_thread().name,
                    'outcome':decision.outcome,'reason':decision.reason,'release_count':count,
                    'duration_ms':round((time.monotonic()-start)*1000,3),
                    'deadline_ms':self.deadline*1000,'active_after':len(self.workers.active)})
                return decision
            for mode in ('plain','observed','serialized_poll_control'):
                for iteration in range(8):
                    events.clear()
                    suite=unittest.defaultTestLoader.loadTestsFromName(NAME)
                    with contextlib.ExitStack() as stack:
                        if mode in ('observed','serialized_poll_control'):
                            stack.enter_context(patch.object(WorkerSupervisor,'run',measured_run))
                            stack.enter_context(patch.object(Harness,'read',measured_read))
                            for name,original in process_methods.items():
                                stack.enter_context(patch.object(multiprocessing.process.BaseProcess,name,process_observer(name,original)))
                            stack.enter_context(patch.object(os,'waitpid',observed_waitpid))
                        if mode=='serialized_poll_control':
                            stack.enter_context(patch.object(multiprocessing.popen_fork.Popen,'poll',serialized_poll))
                        capture=io.StringIO()
                        result=unittest.TextTestRunner(stream=capture,verbosity=0).run(suite)
                    row={'mode':mode,'iteration':iteration,'test':NAME,
                        'status':'PASS' if result.wasSuccessful() else 'FAIL',
                        'run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
                        'skipped':len(result.skipped),'events':list(events)}
                    rows.append(row)
                    print('FROZEN_DIAGNOSTIC',mode,iteration,row['status'],json.dumps(row['events']))
            # Sequential control uses another original named test; no assertions are synthesized as replacements.
            for iteration in range(4):
                events.clear()
                with patch.object(WorkerSupervisor,'run',measured_run),patch.object(Harness,'read',measured_read):
                    result=unittest.TextTestRunner(stream=io.StringIO()).run(unittest.defaultTestLoader.loadTestsFromName('test_pilot.IdentitySecurity.test_replayed_consent_with_new_request_id_is_rejected'))
                rows.append({'mode':'sequential_control','iteration':iteration,'status':'PASS' if result.wasSuccessful() else 'FAIL','events':list(events)})
            print('HISTORICAL_LIMITS',json.dumps({'worker_stage_default':.4,'harness_deadline':2.0,'frozen_files_changed':False}))
        finally:
            subprocess.run(['git','worktree','remove','--force',str(old)],cwd=ROOT,check=True)
    verify_snapshot()
    payload={'anchor':ANCHOR,'python':sys.version,'cpu_count':os.cpu_count(),'rows':rows,
        'frozen_unchanged':True,'diagnostic_only':True,'production':'BLOCK','pilot0d2':'HOLD',
        'redaction':'No token, key, MAC, signature, principal, wallet, consent or payload values recorded.'}
    (out/'pilot0d1r-frozen-diagnostic.json').write_text(json.dumps(payload,indent=2)+'\n')
    print('FROZEN_DIAGNOSTIC_SUMMARY',json.dumps({'pass':sum(r['status']=='PASS' for r in rows),'fail':sum(r['status']=='FAIL' for r in rows),'observations':len(rows)}))

if __name__=='__main__':
    sys.path.insert(0,str(ROOT))
    main()

"""Deterministic causal probe of the stdlib race; no frozen source/assertion/limit edits."""
import errno
import json
import multiprocessing
import os
from pathlib import Path
import sys
import threading
import time
from unittest.mock import patch

def quiet_child():
    pass

def main():
    process=multiprocessing.get_context('spawn').Process(target=quiet_child)
    process.start()
    reaped=threading.Event();owner_done=threading.Event();rows=[];errors=[]
    original_waitpid=os.waitpid
    def observed_waitpid(pid,flags):
        try:result=original_waitpid(pid,flags)
        except OSError as error:
            rows.append({'thread':threading.current_thread().name,'event':'waitpid_error','errno':error.errno})
            raise
        if threading.current_thread().name=='peer_cleanup' and pid==process.pid and result[0]==pid:
            rows.append({'thread':'peer_cleanup','event':'os_reaped_before_cache_assignment','exit_code':os.waitstatus_to_exitcode(result[1])})
            reaped.set()
            # Controlled scheduler interleaving, with fixed bound. No worker deadline is changed.
            if not owner_done.wait(2):errors.append('OWNER_BARRIER_TIMEOUT')
        return result
    def peer():
        try:process._popen.poll(0)
        except BaseException as error:errors.append(type(error).__name__)
    thread=threading.Thread(target=peer,name='peer_cleanup')
    false_alive=None;cached=None
    try:
        with patch.object(os,'waitpid',observed_waitpid):
            thread.start()
            if not reaped.wait(2):raise RuntimeError('REAP_BARRIER_TIMEOUT')
            # The original supervisor's cleanup sequence, unchanged .1-second joins.
            if process.is_alive():process.terminate()
            process.join(.1)
            if process.is_alive():
                process.kill();process.join(.1)
            false_alive=process.is_alive();cached=process._popen.returncode
            rows.append({'thread':'owner','event':'supervisor_final_liveness','is_alive':false_alive,'returncode_cached':cached})
            owner_done.set();thread.join(2)
        if thread.is_alive() or errors:raise RuntimeError('PROBE_THREAD_FAILURE')
        actual_alive=process.is_alive();exit_code=process.exitcode
        assert false_alive is True and cached is None
        assert actual_alive is False and exit_code==0
        assert any(r.get('errno')==errno.ECHILD for r in rows)
        rows.append({'event':'after_peer_cache_assignment','is_alive':actual_alive,'exit_code':exit_code})
        output=Path(__file__).resolve().parents[1]/'evidence';output.mkdir(exist_ok=True)
        payload={'status':'PASS','test':'reaping.peer_waitpid_cache_window_reproduces_false_unreaped',
            'classification':'CAUSAL_FAULT_INJECTION_NOT_ACCEPTANCE','python':sys.version,
            'rows':rows,'original_cleanup_join_seconds':.1,'frozen_edits':False,
            'production':'BLOCK','pilot0d2':'HOLD'}
        (output/'pilot0d1r-reaping-cause.json').write_text(json.dumps(payload,indent=2)+'\n')
        print('REAPING_CAUSAL_PROBE',json.dumps(payload))
    finally:
        owner_done.set();thread.join(2)
        if process.is_alive():process.kill()
        process.join(.1);process.close()

if __name__=='__main__':main()

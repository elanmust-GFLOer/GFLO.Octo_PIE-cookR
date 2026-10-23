"""Killable adapter processes. A timeout is not merely an HTTP timeout.

Only trusted, read-only offline adapters are accepted. No process gets a domain
credential. Completion/timeout reaps the process before its capacity is reused.
"""
import multiprocessing
import os
import pickle
import time
from .contracts import Rejected, Unavailable, ExpiredDeadline
from .process_lifecycle import OwnedSpawnContext

def _invoke(pipe, adapter, method, args):
    try:
        result = getattr(adapter, method)(*args)
        message=("ok",result)
    except Rejected as exc:
        message=("rejected", exc.reason)
    except Unavailable:
        message=("unavailable", None)
    except BaseException:
        message=("error", None)
    try:
        raw=pickle.dumps(message)
        if len(raw)>2048: raw=pickle.dumps(("error",None))
        # Header+payload fits PIPE_BUF: no partial frame can bypass poll's deadline.
        pipe.send_bytes(raw)
    finally:
        pipe.close()

class WorkerSupervisor:
    def __init__(self):
        self.context = OwnedSpawnContext()
        self.active = set()
        self.failed = False
        import threading
        self.lock = threading.Lock()

    def run(self, adapter, method, args, deadline, stage_limit=.4):
        if adapter is None or self.failed:
            raise Unavailable()
        stage_end=min(deadline,time.monotonic()+stage_limit)
        budget = stage_end-time.monotonic()
        if budget <= 0:
            raise ExpiredDeadline()
        receiver, sender = self.context.Pipe(duplex=False)
        if os.fpathconf(sender.fileno(),"PC_PIPE_BUF")<2052:
            receiver.close();sender.close()
            raise Unavailable()
        process = self.context.Process(target=_invoke, args=(sender, adapter, method, args), daemon=True)
        started = False
        try:
            process.start()
            started = True
            with self.lock:
                self.active.add(process.pid)
            sender.close()
            remaining = stage_end-time.monotonic()
            if remaining <= 0 or not receiver.poll(remaining):
                raise ExpiredDeadline()
            status, value = pickle.loads(receiver.recv_bytes(2048))
            if status == "rejected":
                raise Rejected(value)
            if status == "unavailable":
                raise Unavailable()
            if status != "ok":
                raise RuntimeError("adapter failed")
        finally:
            try:
                if started:
                    try:
                        # Both this owner and stdlib global cleanup use the
                        # child's atomic, nonblocking waitpid/cache operation.
                        if process.is_alive():
                            process.terminate()
                        process.join(.1)
                        if process.is_alive():
                            process.kill()
                            process.join(.1)
                        if process.is_alive():
                            raise RuntimeError("adapter process could not be reaped")
                        pid = process.pid
                        process.close()
                        # Close failure retains accounting and poisons admission.
                        with self.lock:
                            self.active.discard(pid)
                    except BaseException:
                        with self.lock:
                            self.failed = True
                        raise
            finally:
                sender.close()
                receiver.close()
        # Startup, decoding AND cleanup are charged; no stale result escapes.
        if time.monotonic()>=stage_end:raise ExpiredDeadline()
        return value

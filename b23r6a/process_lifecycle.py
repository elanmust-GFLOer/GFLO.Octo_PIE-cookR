"""Linux CPython 3.12 spawn lifecycle ownership for isolated read-only workers.

Every stdlib owner and global multiprocessing._cleanup caller reaches the same
per-child Popen.poll lock. No process-wide lock and no stdlib monkeypatch exist.
The private Popen seam is intentionally limited to the recorded/tested runtime.
"""
import multiprocessing.context
from multiprocessing.popen_spawn_posix import Popen as SpawnPopen
import os
import sys
import threading
import time


class OwnedSpawnPopen(SpawnPopen):
    def __init__(self, process_obj):
        self._state_lock = threading.RLock()
        super().__init__(process_obj)

    def poll(self, flag=os.WNOHANG):
        # waitpid + cached exitcode publication form one indivisible operation.
        # Always nonblocking: Popen.wait already waits on the exit sentinel.
        # A lifecycle observer must never hold this lock waiting for a live child.
        with self._state_lock:
            return super().poll(os.WNOHANG)

    def wait(self, timeout=None):
        # A readable exit sentinel can precede a waitable OS status. Re-poll
        # until the original join budget expires; neither block in waitpid(0)
        # nor mistake that short interval for confirmed liveness/cleanup.
        end = None if timeout is None else time.monotonic() + max(0, timeout)
        while True:
            code = self.poll()
            if code is not None:
                return code
            remaining = None if end is None else end - time.monotonic()
            if remaining is not None and remaining <= 0:
                return None
            time.sleep(.001 if remaining is None else min(.001, remaining))

    def _send_signal(self, sig):
        # Prevent a competing cleanup from reaping between the cached-state check
        # and signal delivery. Reaped PIDs must never become signal targets.
        with self._state_lock:
            return super()._send_signal(sig)

    def close(self):
        with self._state_lock:
            return super().close()


class OwnedSpawnProcess(multiprocessing.context.SpawnProcess):
    @staticmethod
    def _Popen(process_obj):
        child = OwnedSpawnPopen.__new__(OwnedSpawnPopen)
        try:
            child.__init__(process_obj)
        except BaseException:
            # If launch failed after creating a child, BaseProcess.start would
            # otherwise lose the only handle before assigning its _popen field.
            # Publish it only on failure, after serialization has finished.
            if getattr(child, 'pid', None) is not None:
                process_obj._popen = child
                process_obj._sentinel = getattr(child, 'sentinel', None)
            raise
        return child


class OwnedSpawnContext(multiprocessing.context.SpawnContext):
    Process = OwnedSpawnProcess

    def __init__(self):
        if (sys.platform != 'linux' or sys.implementation.name != 'cpython'
                or sys.version_info[:2] != (3, 12)):
            raise RuntimeError('UNSUPPORTED_WORKER_LIFECYCLE_RUNTIME')

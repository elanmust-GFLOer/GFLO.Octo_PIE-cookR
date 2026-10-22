"""Trusted monotonic authorization budget; never constructed from request inputs."""
from contextlib import contextmanager
import math
import time
from .contracts import ExpiredDeadline

class Budget:
    def __init__(self,seconds=1.0,clock=None):
        if type(seconds) not in (int,float) or not math.isfinite(seconds) or not 0<seconds<=1:
            raise ValueError("authorization budget must be positive and at most one second")
        self.clock=clock or time.monotonic
        self.started=self.clock()
        self.last=self.started
        self.expires=self.started+seconds

    def remaining(self):
        now=self.clock()
        if not math.isfinite(now) or now<self.last or now>=self.expires:
            raise ExpiredDeadline()
        self.last=now
        return self.expires-now

    def check(self):self.remaining()

    @contextmanager
    def hold(self,lock):
        if not lock.acquire(timeout=self.remaining()):raise ExpiredDeadline()
        try:
            self.check()
            yield
        finally:lock.release()

def prepare_delivery(callback,body,budget):
    """Prepare within the trusted boundary, then guard the first external handoff.

    Ordinary callbacks are trusted synchronous in-memory consumers; invocation
    is their initial release. Deadline-aware transports must check again at
    their actual first application write, after serialization/preparation.
    """
    prepare=getattr(callback,"prepare",None)
    if prepare is not None:
        commit=prepare(body,budget)
        if not callable(commit):raise TypeError("invalid prepared delivery")
    else:
        commit=lambda:callback(body)
    budget.check()
    def guarded():
        budget.check()
        commit()
        budget.check()
    return guarded

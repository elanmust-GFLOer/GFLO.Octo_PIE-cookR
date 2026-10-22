"""Separate bounded synthetic observer sink. No domain database connection."""
from collections import deque
import hashlib
import hmac
import secrets
import threading

class EventStore:
    def __init__(self, capacity=4096):
        self._events = deque(maxlen=capacity)
        self._key = secrets.token_bytes(32)
        self._lock = threading.Lock()

    def _pseudo(self, value):
        return hmac.new(self._key, value.encode(), hashlib.sha256).hexdigest()[:24]

    def event(self, decision, operation, identity=None):
        from .contracts import Identity
        if type(identity) is not Identity or type(identity.subject) is not str or type(identity.session_id) is not str:
            identity = None
        # Construct an allowlisted object, never scrub arbitrary request objects.
        return {"environment": "R6A-OFFLINE", "trace_id": decision.trace_id,
                "request_id": decision.request_id, "decision": decision.decision.value,
                "reason_code": decision.reason_code.value,
                "operation": operation if operation in {
                    "system.health.read", "audit.summary.read", "wallet.challenge.issue",
                    "wallet.binding.verify", "wallet.binding.activate", "wallet.binding.suspend",
                    "wallet.binding.recover"} else "unknown",
                "actor_pseudonym": self._pseudo(identity.subject) if identity else None,
                "session_pseudonym": self._pseudo(identity.session_id) if identity else None}

    def commit(self, event):
        # Best-effort terminal/public observations never wait behind protected work.
        if not self._lock.acquire(blocking=False):
            from .contracts import Unavailable
            raise Unavailable()
        try:self._events.append(dict(event))
        finally:self._lock.release()

    def commit_before_deadline(self,event,budget):
        prepared=dict(event)
        with budget.hold(self._lock):
            budget.check()
            self._events.append(prepared)
            budget.check()

    def summary(self):
        with self._lock:
            counts = {k: sum(e["decision"] == k for e in self._events)
                      for k in ("ALLOW", "DENY", "QUARANTINE")}
            return {"environment": "R6A-OFFLINE", "events": len(self._events), "counts": counts}

    def summary_before_deadline(self,budget):
        with budget.hold(self._lock):
            counts={k:sum(e["decision"]==k for e in self._events) for k in ("ALLOW","DENY","QUARANTINE")}
            value={"environment":"R6A-OFFLINE","events":len(self._events),"counts":counts}
            budget.check()
            return value

    def snapshot_for_test(self):
        with self._lock:
            return [dict(e) for e in self._events]

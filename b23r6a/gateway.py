"""Non-executing gateway. Only authorized synthetic reads can return data."""
from collections import OrderedDict
from dataclasses import dataclass
import threading
import time
import uuid
from .contracts import (READS, SENSITIVE, ISSUER, AUDIENCE, PROJECT, Request, Identity,
                        UserObservation, SessionObservation, SessionState, LocalState,
                        Decision, Outcome, Reason, Rejected, Unavailable, ExpiredDeadline)
from .contracts import JwtVerifier,FreshUserObserver,SessionAuthority,OperationPolicy,SecurityEventEmitter
from .events import EventStore
from .workers import WorkerSupervisor

@dataclass(frozen=True)
class Adapters:
    jwt: JwtVerifier | None = None
    user: FreshUserObserver | None = None
    session: SessionAuthority | None = None
    policy: OperationPolicy | None = None
    emitter: SecurityEventEmitter | None = None

class DeliveryFailed(Exception):
    pass

class Gateway:
    def __init__(self, adapters, primary, *, timeout=2.0, capacity=8, events=None):
        self.adapters, self.primary = adapters, primary
        self.timeout = timeout
        self.slots = threading.BoundedSemaphore(capacity)
        self.workers = WorkerSupervisor()
        self.events = events or EventStore()
        self.ledger = OrderedDict()
        self.ledger_lock = threading.Lock()

    def _request_record(self, identity, request):
        key = (identity.project, identity.subject, request.request_id)
        with self.ledger_lock:
            now = time.monotonic()
            while self.ledger and next(iter(self.ledger.values()))[1] <= now:
                self.ledger.popitem(last=False)
            prior = self.ledger.get(key)
            if prior and prior[0] != request.digest:
                raise Rejected(Reason.REQUEST_DIGEST_CONFLICT)
            if prior is None:
                if len(self.ledger) >= 4096:
                    raise Unavailable()
                self.ledger[key] = (request.digest, now + 600)

    def handle(self, value, token=None, *, include_data=False, deliver=None):
        """Trusted delivery callback runs INSIDE the primary fence.

        No protected data is returned from this function. Only the callback can
        consume it, synchronously, while the fence is held. HTTP writes use this
        path; a prior ALLOW object cannot authorize a later data read.
        """
        if deliver:
            transport = deliver
            def deliver(body):
                try:
                    transport(body)
                except Exception:
                    raise DeliveryFailed() from None
        trace = str(uuid.uuid4())
        request = None
        identity = None
        locked = False
        slot = False
        deadline = time.monotonic() + self.timeout
        def decision(outcome, reason):
            return Decision(outcome, reason, trace, request.request_id if request else str(uuid.uuid4()))
        def run(adapter, method, *args):
            return self.workers.run(adapter, method, args, deadline)
        try:
            request = Request.parse(value)
            if request.operation not in READS | SENSITIVE:
                raise Rejected(Reason.OPERATION_UNKNOWN)
            if request.operation == "system.health.read":
                result = decision(Outcome.ALLOW, Reason.PUBLIC_HEALTH)
                try:
                    self.events.commit(self.events.event(result, request.operation))
                except Exception:
                    pass  # Minimal public health is independent of audit availability.
                if deliver:
                    deliver({**result.as_dict(), "data": {"status": "ok"}})
                return result
            if not self.slots.acquire(blocking=False):
                result = decision(Outcome.QUARANTINE, Reason.CAPACITY_EXHAUSTED)
                return self._finish(result, request, None, deliver)
            slot = True
            if type(token) is not str or not token or len(token.encode()) > 8192:
                raise Rejected(Reason.AUTH_MISSING)
            identity = run(self.adapters.jwt, "verify", token)
            self._identity(identity)
            user = run(self.adapters.user, "observe", identity)
            if type(user) is not UserObservation:
                raise ValueError("malformed user evidence")
            if user.subject != identity.subject:
                raise Rejected(Reason.SUBJECT_MISMATCH)
            session = run(self.adapters.session, "observe", identity)
            if type(session) is not SessionObservation or type(session.state) is not SessionState or type(session.generation) is not int:
                raise ValueError("malformed session evidence")
            if (session.subject, session.session_id) != (identity.subject, identity.session_id):
                raise Rejected(Reason.SUBJECT_MISMATCH)
            if session.state == SessionState.REVOKED:
                raise Rejected(Reason.SESSION_REVOKED)
            if session.state != SessionState.ACTIVE:
                result = decision(Outcome.QUARANTINE, Reason.SESSION_UNKNOWN)
                return self._finish(result, request, identity, deliver)
            if session.generation != identity.generation:
                raise Rejected(Reason.GENERATION_STALE)
            policy = run(self.adapters.policy, "authorize", identity, request)
            if type(policy) is not bool:
                raise ValueError("malformed policy evidence")
            if not policy:
                raise Rejected(Reason.POLICY_DENIED)
            self._request_record(identity, request)
            locked = self.primary.acquire(identity.subject, deadline - time.monotonic())
            if not locked:
                raise ExpiredDeadline()
            local = self.primary.snapshot(identity.subject)
            if (type(local) is not LocalState or type(local.generation) is not int
                    or local.generation < 0 or local.binding_status not in {"unbound", "active", "suspended"}):
                raise ValueError("malformed primary evidence")
            if local.generation != identity.generation:
                raise Rejected(Reason.GENERATION_STALE)
            if local.binding_status == "suspended":
                raise Rejected(Reason.BINDING_SUSPENDED)
            target = request.payload.get("binding_ref")
            if target is not None and target != local.binding_ref:
                raise Rejected(Reason.POLICY_DENIED)
            if request.operation in SENSITIVE:
                result = decision(Outcome.QUARANTINE, Reason.MUTATION_CAPABILITY_DISABLED)
                return self._finish(result, request, identity, deliver)
            result = decision(Outcome.ALLOW, Reason.READ_AUTHORIZED)
            event = self.events.event(result, request.operation, identity)
            try:
                if run(self.adapters.emitter, "approve", event) is not True:
                    raise Unavailable()
            except (Unavailable, ExpiredDeadline, RuntimeError):
                result = decision(Outcome.QUARANTINE, Reason.AUDIT_UNAVAILABLE)
                return self._finish(result, request, identity, deliver)
            # Fresh independent session authority and policy at the release
            # point: JWT/user validity alone never establishes session liveness.
            final_session = run(self.adapters.session, "observe", identity)
            if (type(final_session) is not SessionObservation
                    or type(final_session.state) is not SessionState
                    or type(final_session.generation) is not int):
                raise ValueError("malformed final session evidence")
            if type(final_session) is not SessionObservation or final_session != session:
                if type(final_session) is SessionObservation and final_session.state == SessionState.REVOKED:
                    raise Rejected(Reason.SESSION_REVOKED)
                raise Unavailable()
            if run(self.adapters.policy, "authorize", identity, request) is not True:
                raise Rejected(Reason.POLICY_DENIED)
            self._identity(identity)
            if time.monotonic() >= deadline:
                raise ExpiredDeadline()
            if self.primary.snapshot(identity.subject) != local:
                raise Rejected(Reason.GENERATION_STALE)
            data = self.events.summary() if include_data else None
            self.events.commit(event)
            if deliver:
                response = result.as_dict()
                if data is not None:
                    response["data"] = data
                deliver(response)
            return result
        except DeliveryFailed:
            # A failed/partially completed network write is never retried.
            return result
        except Rejected as exc:
            return self._finish(decision(Outcome.DENY, exc.reason), request, identity, deliver)
        except ExpiredDeadline:
            return self._finish(decision(Outcome.QUARANTINE, Reason.AUTHORITY_TIMEOUT), request, identity, deliver)
        except Unavailable:
            return self._finish(decision(Outcome.QUARANTINE, Reason.AUTHORITY_UNAVAILABLE), request, identity, deliver)
        except (ValueError, TypeError, AttributeError):
            return self._finish(decision(Outcome.QUARANTINE, Reason.EVIDENCE_INVALID), request, identity, deliver)
        except Exception:
            return self._finish(decision(Outcome.QUARANTINE, Reason.INTERNAL_ERROR), request, identity, deliver)
        finally:
            if locked:
                self.primary.release(identity.subject)
            if slot:
                self.slots.release()

    @staticmethod
    def _identity(identity):
        if type(identity) is not Identity or (identity.issuer, identity.audience, identity.project) != (ISSUER, AUDIENCE, PROJECT):
            raise ValueError("malformed verified identity")
        if type(identity.expires_at) is not int or identity.expires_at <= time.time():
            raise Rejected(Reason.AUTH_EXPIRED)
        if type(identity.generation) is not int or identity.generation < 0:
            raise ValueError("malformed generation")
        for value in (identity.subject, identity.session_id):
            if type(value) is not str or str(uuid.UUID(value)) != value:
                raise ValueError("malformed principal")

    def _finish(self, result, request, identity, deliver):
        # Terminal non-executing decision; never enqueue or retry anything.
        try:
            self.events.commit(self.events.event(result, request.operation if request else "unknown", identity))
        except Exception:
            result = Decision(Outcome.QUARANTINE, Reason.AUDIT_UNAVAILABLE, result.trace_id, result.request_id)
        if deliver:
            try:
                deliver(result.as_dict())
            except DeliveryFailed:
                pass  # Never retry a partially completed transport write.
        return result

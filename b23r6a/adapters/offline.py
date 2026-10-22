import secrets
import threading
import time
from dataclasses import dataclass, field
import jwt
from ..contracts import (ISSUER, AUDIENCE, PROJECT, Identity, UserObservation,
                         SessionObservation, SessionState, LocalState, Reason, Rejected)

USER_A = "00000000-0000-4000-8000-000000000001"
USER_B = "00000000-0000-4000-8000-000000000002"
SESSION_A = "00000000-0000-4000-8000-000000000011"

@dataclass(frozen=True)
class OfflineJwtVerifier:
    key: bytes

    def verify(self, token):
        try:
            claims = jwt.decode(token, self.key, algorithms=["HS256"], issuer=ISSUER,
                                audience=AUDIENCE, options={"require": ["exp", "sub", "session_id", "iss", "aud", "project", "auth_generation"]})
        except jwt.ExpiredSignatureError:
            raise Rejected(Reason.AUTH_EXPIRED) from None
        except jwt.InvalidIssuerError:
            raise Rejected(Reason.AUTH_ISSUER) from None
        except jwt.InvalidAudienceError:
            raise Rejected(Reason.AUTH_AUDIENCE) from None
        except jwt.PyJWTError:
            raise Rejected(Reason.AUTH_INVALID) from None
        if claims.get("project") != PROJECT:
            raise Rejected(Reason.AUTH_PROJECT)
        import uuid
        try:
            for key in ("sub", "session_id"):
                if type(claims[key]) is not str or str(uuid.UUID(claims[key])) != claims[key]:
                    raise ValueError()
            if type(claims["exp"]) is not int or type(claims["auth_generation"]) is not int or claims["auth_generation"] < 0:
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise Rejected(Reason.AUTH_INVALID) from None
        return Identity(claims["sub"], claims["session_id"], ISSUER, AUDIENCE, PROJECT,
                        claims["exp"], claims["auth_generation"])

@dataclass(frozen=True)
class OfflineUsers:
    users: frozenset = frozenset((USER_A, USER_B))

    def observe(self, identity):
        if identity.subject not in self.users:
            raise Rejected(Reason.AUTH_INVALID)
        return UserObservation(identity.subject)

@dataclass(frozen=True)
class OfflineSessions:
    records: tuple = ((USER_A, SESSION_A, SessionState.ACTIVE, 0),)

    def observe(self, identity):
        for subject, session, state, generation in self.records:
            if subject == identity.subject and session == identity.session_id:
                return SessionObservation(subject, session, state, generation)
        return SessionObservation(identity.subject, identity.session_id, SessionState.UNKNOWN, 0)

@dataclass(frozen=True)
class OfflinePolicy:
    observers: frozenset = frozenset((USER_A,))

    def authorize(self, identity, request):
        target = request.payload.get("target_profile_ref")
        if target is not None and target != identity.subject:
            raise Rejected(Reason.SUBJECT_MISMATCH)
        return request.operation != "audit.summary.read" or identity.subject in self.observers

@dataclass(frozen=True)
class OfflineEmitter:
    def approve(self, event):
        return True

@dataclass(frozen=True)
class FaultAdapter:
    """Fault injection fixture. File side effect used only to prove kill/reaping."""
    delay: float = 0
    fault: str = "unavailable"
    late_write: str | None = None

    def _run(self):
        time.sleep(self.delay)
        if self.late_write:
            from pathlib import Path
            Path(self.late_write).write_text("LATE SIDE EFFECT")
        if self.fault == "unexpected":
            raise RuntimeError("untrusted exception data must not leak")
        from ..contracts import Unavailable
        raise Unavailable()

    def observe(self, *args): return self._run()
    def verify(self, *args): return self._run()
    def authorize(self, *args): return self._run()
    def approve(self, *args): return self._run()

class OfflinePrimary:
    """Primary/fence simulator, not PostgreSQL or distributed correctness proof."""
    def __init__(self):
        self.states = {USER_A: LocalState(), USER_B: LocalState()}
        self._locks = {USER_A: threading.RLock(), USER_B: threading.RLock()}
        self._map_lock = threading.Lock()

    def _lock(self, subject):
        with self._map_lock:
            return self._locks.setdefault(subject, threading.RLock())

    def acquire(self, subject, timeout):
        return self._lock(subject).acquire(timeout=max(0, timeout))

    def release(self, subject):
        self._lock(subject).release()

    def snapshot(self, subject):
        return self.states.get(subject, LocalState(-1))

    def revoke(self, subject):
        with self._lock(subject):
            current = self.snapshot(subject)
            self.states[subject] = LocalState(current.generation + 1, "suspended", current.binding_ref)

def test_token(key, **changes):
    claims = {"sub": USER_A, "session_id": SESSION_A, "iss": ISSUER, "aud": AUDIENCE,
              "project": PROJECT, "auth_generation": 0, "exp": int(time.time()) + 300}
    claims.update(changes)
    return jwt.encode(claims, key, algorithm="HS256")

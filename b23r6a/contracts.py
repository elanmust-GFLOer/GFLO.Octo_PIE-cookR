"""Trusted-process interfaces; these types are never deserialized from HTTP."""
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, Callable
import hashlib
import json
import uuid

ISSUER = "https://auth.r6a.test/auth/v1"
AUDIENCE = "r6a-test-gateway"
PROJECT = "r6a-offline"
READS = frozenset(("system.health.read", "audit.summary.read"))
SENSITIVE = frozenset(("wallet.challenge.issue", "wallet.binding.verify",
                       "wallet.binding.activate", "wallet.binding.suspend", "wallet.binding.recover"))

class Outcome(str, Enum):
    ALLOW = "ALLOW"
    QUARANTINE = "QUARANTINE"
    DENY = "DENY"

class Reason(str, Enum):
    READ_AUTHORIZED = "READ_AUTHORIZED"
    PUBLIC_HEALTH = "PUBLIC_HEALTH"
    INVALID_REQUEST = "INVALID_REQUEST"
    OPERATION_UNKNOWN = "OPERATION_UNKNOWN"
    AUTH_INVALID = "AUTH_INVALID"
    AUTH_EXPIRED = "AUTH_EXPIRED"
    AUTH_ISSUER = "AUTH_ISSUER"
    AUTH_AUDIENCE = "AUTH_AUDIENCE"
    AUTH_PROJECT = "AUTH_PROJECT"
    AUTH_MISSING = "AUTH_MISSING"
    SUBJECT_MISMATCH = "SUBJECT_MISMATCH"
    POLICY_DENIED = "POLICY_DENIED"
    SESSION_REVOKED = "SESSION_REVOKED"
    SESSION_UNKNOWN = "SESSION_UNKNOWN"
    GENERATION_STALE = "GENERATION_STALE"
    BINDING_SUSPENDED = "BINDING_SUSPENDED"
    AUTHORITY_UNAVAILABLE = "AUTHORITY_UNAVAILABLE"
    AUTHORITY_TIMEOUT = "AUTHORITY_TIMEOUT"
    EVIDENCE_INVALID = "EVIDENCE_INVALID"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    MUTATION_CAPABILITY_DISABLED = "MUTATION_CAPABILITY_DISABLED"
    REQUEST_DIGEST_CONFLICT = "REQUEST_DIGEST_CONFLICT"
    CAPACITY_EXHAUSTED = "CAPACITY_EXHAUSTED"

class SessionState(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"

class Rejected(Exception):
    def __init__(self, reason: Reason):
        self.reason = reason

class Unavailable(Exception):
    pass

class ExpiredDeadline(Exception):
    pass

@dataclass(frozen=True)
class Request:
    operation: str
    request_id: str
    payload_json: str
    digest: str

    @classmethod
    def parse(cls, value):
        if type(value) is not dict or set(value) != {"operation", "request_id", "payload"}:
            raise Rejected(Reason.INVALID_REQUEST)
        op, rid, payload = value["operation"], value["request_id"], value["payload"]
        if type(op) is not str or len(op) > 80:
            raise Rejected(Reason.INVALID_REQUEST)
        try:
            if type(rid) is not str or str(uuid.UUID(rid)) != rid:
                raise ValueError()
        except (ValueError, AttributeError):
            raise Rejected(Reason.INVALID_REQUEST) from None
        if type(payload) is not dict or set(payload) - {"target_profile_ref", "chain_id", "binding_ref"}:
            raise Rejected(Reason.INVALID_REQUEST)
        for key, val in payload.items():
            if key == "chain_id":
                if type(val) is not int or not 0 < val < 2**63:
                    raise Rejected(Reason.INVALID_REQUEST)
            elif type(val) is not str or len(val) > 256 or any(ord(c) < 32 for c in val):
                raise Rejected(Reason.INVALID_REQUEST)
        if op in READS and payload:
            raise Rejected(Reason.INVALID_REQUEST)
        canonical = json.dumps({"operation": op, "payload": payload}, sort_keys=True,
                               separators=(",", ":"), allow_nan=False)
        return cls(op, rid, json.dumps(payload, sort_keys=True), hashlib.sha256(canonical.encode()).hexdigest())

    @property
    def payload(self):
        return json.loads(self.payload_json)

@dataclass(frozen=True)
class Identity:
    subject: str
    session_id: str
    issuer: str
    audience: str
    project: str
    expires_at: int
    generation: int

@dataclass(frozen=True)
class UserObservation:
    subject: str

@dataclass(frozen=True)
class SessionObservation:
    subject: str
    session_id: str
    state: SessionState
    generation: int

@dataclass(frozen=True)
class LocalState:
    generation: int = 0
    binding_status: str = "unbound"
    binding_ref: str | None = None

@dataclass(frozen=True)
class Decision:
    decision: Outcome
    reason_code: Reason
    trace_id: str
    request_id: str

    def as_dict(self):
        return {"decision": self.decision.value, "reason_code": self.reason_code.value,
                "trace_id": self.trace_id, "request_id": self.request_id}

class JwtVerifier(Protocol):
    def verify(self, token: str) -> Identity: ...

class FreshUserObserver(Protocol):
    def observe(self, identity: Identity) -> UserObservation: ...

class SessionAuthority(Protocol):
    def observe(self, identity: Identity) -> SessionObservation: ...

class OperationPolicy(Protocol):
    def authorize(self, identity: Identity, request: Request) -> bool: ...

class SecurityEventEmitter(Protocol):
    def approve(self, event: dict) -> bool: ...

class PrimaryGenerationFence(Protocol):
    def acquire(self, subject: str, timeout: float) -> bool: ...
    def snapshot(self, subject: str) -> LocalState: ...
    def release(self, subject: str) -> None: ...

Delivery = Callable[[dict], None]

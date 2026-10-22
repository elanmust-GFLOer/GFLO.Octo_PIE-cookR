"""Pilot 0A data contract. Labels are evidence classes, never permissions."""
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
import uuid
from typing import NewType

ProfileId=NewType("ProfileId",str)
PrincipalId=NewType("PrincipalId",str)
ProtocolId=NewType("ProtocolId",str)
WalletAddress=NewType("WalletAddress",str)

CHAIN = 11155111
LEGACY = "0x9cf55d0b9d61dc28ef3cb10765cf4b861cd0991e"
DEMO_CONTRACT = "0x00000000000000000000000000000000000000d0"
WALLET_A = "0x1111111111111111111111111111111111111111"
WALLET_B = "0x2222222222222222222222222222222222222222"
PROFILE_A = "00000000-0000-4000-8000-000000000101"
PROFILE_B = "00000000-0000-4000-8000-000000000102"

class Classification(str, Enum):
    DEMO_FIXTURE = "DEMO_FIXTURE"
    VERIFIED_WALLET_CONTROL = "VERIFIED_WALLET_CONTROL"
    LEGACY_UNTRUSTED_XP = "LEGACY_UNTRUSTED_XP"
    REVIEWED_PROTOCOL_DATA = "REVIEWED_PROTOCOL_DATA"

class SessionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"

class Stop(Exception):
    def __init__(self, reason, outcome="DENY"):
        self.reason,self.outcome=reason,outcome

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False)

def digest(value): return hashlib.sha256(canonical(value).encode()).hexdigest()

def address(value):
    # Harness wire format is canonical lower-case hex, not an EIP-55 validator.
    if type(value) is not str or not re.fullmatch(r"0x[0-9a-f]{40}",value) or int(value,16)==0:
        raise Stop("ADDRESS_INVALID")
    return value

def uuid_string(value):
    try:
        if type(value) is not str or str(uuid.UUID(value))!=value: raise ValueError()
    except (ValueError,TypeError,AttributeError): raise Stop("IDENTIFIER_INVALID") from None

@dataclass(frozen=True)
class WalletRef:
    chain_id: int
    address: WalletAddress

@dataclass(frozen=True)
class ProtocolRef:
    protocol_id: ProtocolId
    chain_id: int
    contract: str
    account: WalletAddress

@dataclass(frozen=True)
class Relation:
    profile_id: ProfileId
    principal: PrincipalId
    wallet: WalletRef
    protocol: ProtocolRef
    epoch: int = 0
    revocation_generation: int = 0
    status: str = "ACTIVE"
    wallet_assurance: Classification = Classification.DEMO_FIXTURE

@dataclass(frozen=True)
class Provenance:
    classification: Classification
    origin: str
    source_ref: str
    source_digest: str
    confidence: str
    review_ref: str | None = None
    block_number: int | None = None
    block_hash: str | None = None

@dataclass(frozen=True)
class ProtocolRecord:
    reference: ProtocolRef
    reported_xp: int
    reported_tier: int
    provenance: Provenance

@dataclass(frozen=True)
class Consent:
    consent_id: str
    nonce: str
    principal: str
    profile_id: str
    session_id: str
    protocol: ProtocolRef
    scopes: tuple[str,...]
    version: str
    issued_at: int
    expires_at: int
    generation: int
    epoch: int
    revocation_generation: int
    proof_kind: str = "MOCK_TEST_ONLY"
    mock_mac: str = ""

@dataclass(frozen=True)
class ReadRequest:
    request_id: str
    profile_id: str
    chain_id: int
    wallet: str
    contract: str
    protocol_id: str
    consent: Consent | None

@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str
    trace_id: str
    request_id: str

"""Deny-by-default, offline evidence matching. No RPC, Auth or wallet capability."""
from dataclasses import dataclass,asdict
from enum import Enum
import hashlib
import json
import re
from types import MappingProxyType

LEGACY_CHAIN=11155111
LEGACY_ADDRESS="0x9cf55d0b9d61dc28ef3cb10765cf4b861cd0991e"
MAX_AGE=86400
# Deliberately narrow, pinned standard selector vector. Unknown signatures
# remain unverifiable; do not substitute NIST SHA3 for Ethereum Keccak.
SUPPORTED_SELECTORS={"balanceOf(address)":"0x70a08231"}

class SourceClass(str,Enum):
    DEMO_FIXTURE="DEMO_FIXTURE"
    LEGACY_UNTRUSTED_XP="LEGACY_UNTRUSTED_XP"
    REVIEWED_PROTOCOL_DATA="REVIEWED_PROTOCOL_DATA"

class Verification(str,Enum):
    VERIFIED_OFFLINE="VERIFIED_OFFLINE"
    UNKNOWN="UNKNOWN"
    REVOKED="REVOKED"

@dataclass(frozen=True)
class Hash:
    algorithm:str
    value:str

def sha256(value:bytes)->Hash:return Hash("sha256",hashlib.sha256(value).hexdigest())
def abi_bytes(text:str)->bytes:
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError("conflicting ABI keys")
            result[key]=value
        return result
    value=json.loads(text,object_pairs_hook=unique)
    if type(value) is not list:raise ValueError("invalid ABI")
    return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()

@dataclass(frozen=True)
class Implementation:
    address:str
    runtime_hash:Hash

@dataclass(frozen=True)
class Manifest:
    chain_id:int
    contract:str
    deployment_hash:Hash | None
    runtime_hash:Hash | None
    abi_hash:Hash | None
    source_id:str
    source_hash:Hash | None
    proxy_kind:str
    implementation:Implementation | None
    classification:SourceClass
    read_selectors:tuple[str,...]
    evidence_ref:str
    verification:Verification
    issued_at:int
    expires_at:int
    non_production:bool=True

@dataclass(frozen=True)
class SelectorProof:
    selector:str
    abi_signature:str

@dataclass(frozen=True)
class Evidence:
    reference:str
    chain_id:int
    contract:str
    creation_code:bytes
    runtime_code:bytes
    abi_json:str
    verified_source:bytes
    source_id:str
    proxy_kind:str
    implementation_address:str | None
    implementation_runtime:bytes | None
    classification:SourceClass
    selectors:tuple[SelectorProof,...]
    verification:Verification
    reviewer_ref:str
    observed_at:int
    expires_at:int
    permissionless_xp:bool=False

@dataclass(frozen=True)
class ReadSource:
    chain_id:int
    contract:str
    selectors:tuple[str,...]

@dataclass(frozen=True)
class Result:
    status:str
    reason:str
    classification:SourceClass | None=None
    manifest_digest:str | None=None
    production_authorized:bool=False
    canonical_xp_authorized:bool=False
    entitlements:tuple=()

class Registry:
    """Trusted server/test configuration, NEVER reconstructed from caller JSON.

    Entries are independently supplied offline observations. A VERIFIED field
    in a caller's Manifest alone confers no trust. No network resolution.
    """
    def __init__(self,entries=()):
        pairs=[(e.reference,e) for e in entries]
        if len({k for k,_ in pairs})!=len(pairs):raise ValueError("conflicting evidence references")
        self.entries=MappingProxyType(dict(pairs))
    def get(self,reference):return self.entries.get(reference)

class Denied(Exception):pass
def require(condition,reason):
    if not condition:raise Denied(reason)
def is_address(value):return type(value) is str and re.fullmatch(r"0x[0-9a-f]{40}",value) is not None and int(value,16)>0
def text(value):return type(value) is str and 0<len(value)<=256 and not any(ord(c)<32 for c in value)
def valid_hash(value):return type(value) is Hash and value.algorithm=="sha256" and type(value.value) is str and re.fullmatch(r"[0-9a-f]{64}",value.value) is not None
def selectors(value):return type(value) is tuple and 0<len(value)<=32 and len(set(value))==len(value) and all(type(s) is str and re.fullmatch(r"0x[0-9a-f]{8}",s) and s!="0x00000000" for s in value)

def validate(manifest:Manifest | None,request:ReadSource,registry:Registry | None,now:int)->Result:
    classification=None
    if type(request) is ReadSource and (request.chain_id,request.contract)==(LEGACY_CHAIN,LEGACY_ADDRESS):
        classification=SourceClass.LEGACY_UNTRUSTED_XP
    try:
        require(type(manifest) is Manifest,"MANIFEST_MISSING_OR_MALFORMED")
        m=manifest
        require(type(request) is ReadSource,"REQUEST_INVALID")
        require(type(now) is int and now>=0,"CLOCK_INVALID")
        require(type(m.chain_id) is int and m.chain_id>0 and type(request.chain_id) is int,"CHAIN_INVALID")
        require(is_address(m.contract) and is_address(request.contract),"ADDRESS_INVALID")
        require((m.chain_id,m.contract)==(request.chain_id,request.contract),"CHAIN_OR_CONTRACT_MISMATCH")
        require(type(m.classification) is SourceClass,"CLASSIFICATION_INVALID")
        classification=m.classification if classification is None else classification
        require(m.non_production is True,"PRODUCTION_AUTHORITY_PROHIBITED")
        require(all(valid_hash(v) for v in (m.deployment_hash,m.runtime_hash,m.abi_hash,m.source_hash)),"DIGEST_MISSING_OR_UNSUPPORTED")
        require(text(m.source_id) and text(m.evidence_ref),"PROVENANCE_MISSING")
        require(type(m.verification) is Verification and m.verification==Verification.VERIFIED_OFFLINE,"MANIFEST_UNVERIFIED")
        require(type(m.issued_at) is int and type(m.expires_at) is int and m.issued_at<=now<m.expires_at
                and 0<m.expires_at-m.issued_at<=MAX_AGE,"MANIFEST_STALE")
        require(selectors(m.read_selectors) and selectors(request.selectors),"SELECTORS_INVALID")
        require(set(request.selectors)<=set(m.read_selectors),"SELECTOR_NOT_ALLOWED")
        require(type(registry) is Registry,"EVIDENCE_AUTHORITY_UNAVAILABLE")
        e=registry.get(m.evidence_ref)
        require(type(e) is Evidence,"EVIDENCE_MISSING")
        require(type(e.chain_id) is int and is_address(e.contract) and type(e.classification) is SourceClass
                and type(e.permissionless_xp) is bool,"EVIDENCE_MALFORMED")
        require(e.verification is Verification.VERIFIED_OFFLINE and text(e.reviewer_ref),"EVIDENCE_UNVERIFIED")
        require(type(e.observed_at) is int and type(e.expires_at) is int and e.observed_at<=now<e.expires_at
                and now-e.observed_at<=MAX_AGE,"EVIDENCE_STALE")
        require((e.chain_id,e.contract,e.source_id,e.classification)==(m.chain_id,m.contract,m.source_id,m.classification),"EVIDENCE_CONFLICT")
        if (m.chain_id,m.contract)==(LEGACY_CHAIN,LEGACY_ADDRESS) or e.permissionless_xp:
            classification=SourceClass.LEGACY_UNTRUSTED_XP
            require(m.classification is SourceClass.LEGACY_UNTRUSTED_XP,"LEGACY_PROMOTION_DENIED")
        require(type(e.creation_code) is bytes and type(e.runtime_code) is bytes and type(e.verified_source) is bytes
                and all(0<len(v)<=1_048_576 for v in (e.creation_code,e.runtime_code,e.verified_source)),"RAW_EVIDENCE_MISSING")
        require(sha256(e.creation_code)==m.deployment_hash,"DEPLOYMENT_HASH_MISMATCH")
        require(sha256(e.runtime_code)==m.runtime_hash,"RUNTIME_HASH_MISMATCH")
        require(type(e.abi_json) is str and 0<len(e.abi_json)<=262144,"ABI_INVALID")
        require(sha256(abi_bytes(e.abi_json))==m.abi_hash,"ABI_HASH_MISMATCH")
        require(sha256(e.verified_source)==m.source_hash,"SOURCE_HASH_MISMATCH")
        require(m.proxy_kind in ("DIRECT","EIP1967") and e.proxy_kind==m.proxy_kind,"PROXY_IDENTITY_UNVERIFIED")
        if m.proxy_kind=="DIRECT":
            require(m.implementation is None and e.implementation_address is None and e.implementation_runtime is None,"PROXY_IMPLEMENTATION_CONFLICT")
        else:
            require(type(m.implementation) is Implementation and is_address(m.implementation.address)
                    and valid_hash(m.implementation.runtime_hash),"IMPLEMENTATION_MISSING")
            require(m.implementation.address==e.implementation_address,"IMPLEMENTATION_ADDRESS_MISMATCH")
            require(type(e.implementation_runtime) is bytes and len(e.implementation_runtime)>0
                    and sha256(e.implementation_runtime)==m.implementation.runtime_hash,"IMPLEMENTATION_HASH_MISMATCH")
        # Selector-to-signature association is separately attested by registry;
        # ABI mutability and canonical ABI hash are checked locally. No fake
        # Keccak computation or sha3_256-as-Ethereum-selector substitution.
        methods={}
        for f in json.loads(e.abi_json):
            if f.get("type")=="function":
                signature=f['name']+'('+','.join(i['type'] for i in f['inputs'])+')'
                require(signature not in methods,"ABI_CONFLICT")
                methods[signature]=f.get("stateMutability")
        proofs={}
        for proof in e.selectors:
            require(type(proof) is SelectorProof and proof.selector not in proofs,"SELECTOR_EVIDENCE_CONFLICT")
            require(methods.get(proof.abi_signature) in ("view","pure"),"MUTATION_SELECTOR_DENIED")
            require(SUPPORTED_SELECTORS.get(proof.abi_signature)==proof.selector,"SELECTOR_UNVERIFIABLE")
            proofs[proof.selector]=proof.abi_signature
        require(set(m.read_selectors)<=set(proofs),"SELECTOR_EVIDENCE_MISSING")
        raw=json.dumps(asdict(m),sort_keys=True,separators=(",",":"),allow_nan=False).encode()
        return Result("CONSISTENT_OFFLINE_NON_PRODUCTION","OFFLINE_EVIDENCE_MATCH",classification,hashlib.sha256(raw).hexdigest())
    except Denied as exc:return Result("DENY",str(exc),classification)
    except Exception:return Result("DENY","MALFORMED_OR_UNCERTAIN_EVIDENCE",classification)

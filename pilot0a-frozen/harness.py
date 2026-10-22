"""Synthetic ID–Entity read proof. No HTTP, RPC, SQL, wallet signing or mutations."""
from collections import deque
from dataclasses import asdict
import hashlib
import hmac
import secrets
import threading
import time
import uuid
from bootstrap import (Gateway,WorkerSupervisor,Identity,SessionObservation,SessionState,
                       UserObservation,LocalState,Rejected,Unavailable,ExpiredDeadline)
from contracts import *

class AuditSink:
    def __init__(self,capacity=128):
        self.events=deque(maxlen=capacity)
        self.available=True
        self.key=secrets.token_bytes(32)
    def event(self,decision,principal=None,source=None):
        return {"environment":"PILOT_0A_SYNTHETIC","trace_id":decision.trace_id,
                "request_id":decision.request_id,"outcome":decision.outcome,
                "reason":decision.reason,"source_classification":source,
                "actor_pseudonym":hmac.new(self.key,principal.encode(),hashlib.sha256).hexdigest()[:24] if principal else None}
    def commit(self,event):
        if not self.available: raise Unavailable()
        self.events.append(dict(event))

class Harness:
    def __init__(self,adapters,primary,relations,records,consents,consent_key,clock,*,deadline=2.0):
        self.adapters,self.primary,self.clock=adapters,primary,clock
        self.relations={r.profile_id:r for r in relations}
        self.records={r.reference.protocol_id:r for r in records}
        self.consents={c.consent_id:c for c in consents}
        self.consent_key=consent_key
        self.used=set();self.revoked=set();self.requests={}
        self.audit=AuditSink()
        self.workers=WorkerSupervisor()
        self.lock=threading.Lock()
        self.slots=threading.BoundedSemaphore(8)
        self.deadline=deadline

    def _session(self,identity,deadline):
        observation=self.workers.run(self.adapters.session,"observe",(identity,),deadline)
        if (type(observation) is not SessionObservation or type(observation.state) is not SessionState
                or type(observation.generation) is not int):
            raise Stop("SESSION_MALFORMED","QUARANTINE")
        if (observation.subject,observation.session_id)!=(identity.subject,identity.session_id):
            raise Stop("SESSION_SUBJECT_MISMATCH")
        if observation.state==SessionState.REVOKED: raise Stop("SESSION_REVOKED")
        if observation.state!=SessionState.ACTIVE: raise Stop("SESSION_UNKNOWN","QUARANTINE")
        if observation.generation!=identity.generation: raise Stop("GENERATION_STALE")
        return observation

    def _relation(self,identity,request):
        if self.relations is None: raise Unavailable()
        relation=self.relations.get(request.profile_id)
        if relation is None or relation.principal!=identity.subject: raise Stop("PROFILE_NOT_OWNED")
        if relation.status!="ACTIVE": raise Stop("LINK_REVOKED")
        if relation.wallet_assurance!=Classification.DEMO_FIXTURE:
            raise Stop("REAL_WALLET_PROOF_UNIMPLEMENTED","QUARANTINE")
        if type(request.chain_id) is not int or request.chain_id!=CHAIN: raise Stop("CHAIN_MISMATCH")
        if request.chain_id!=relation.wallet.chain_id: raise Stop("CHAIN_MISMATCH")
        if address(request.wallet)!=relation.wallet.address: raise Stop("WALLET_MISMATCH")
        if address(request.contract)!=relation.protocol.contract: raise Stop("CONTRACT_MISMATCH")
        if request.protocol_id!=relation.protocol.protocol_id: raise Stop("PROTOCOL_MISMATCH")
        if (relation.protocol.chain_id,relation.protocol.account)!=(relation.wallet.chain_id,relation.wallet.address):
            raise Stop("RELATION_INCONSISTENT","QUARANTINE")
        return relation

    def _consent(self,identity,request,relation):
        c=request.consent
        if type(c) is not Consent: raise Stop("CONSENT_MISSING")
        uuid_string(c.consent_id);uuid_string(c.nonce)
        if c.consent_id in self.used: raise Stop("CONSENT_REPLAY")
        if c.consent_id in self.revoked: raise Stop("CONSENT_REVOKED")
        if self.consents is None: raise Unavailable()
        if self.consents.get(c.consent_id)!=c: raise Stop("CONSENT_TAMPERED")
        body=asdict(c);body.pop("mock_mac")
        expected=hmac.new(self.consent_key,canonical(body).encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(c.mock_mac,expected): raise Stop("CONSENT_TAMPERED")
        if (c.principal,c.profile_id,c.session_id,c.protocol)!=(identity.subject,relation.profile_id,identity.session_id,relation.protocol):
            raise Stop("CONSENT_ASSOCIATION_MISMATCH")
        if c.scopes!=("identity:read",) or c.version!="0A-MOCK-v1" or c.proof_kind!="MOCK_TEST_ONLY":
            raise Stop("CONSENT_SCOPE_OR_VERSION")
        now=self.clock()
        if type(now) is not int or any(type(v) is not int for v in (c.issued_at,c.expires_at,c.generation,c.epoch,c.revocation_generation)):
            raise Stop("CLOCK_OR_CONSENT_MALFORMED","QUARANTINE")
        if not c.issued_at<=now<c.expires_at or not 0<c.expires_at-c.issued_at<=300: raise Stop("CONSENT_EXPIRED")
        if (c.generation,c.epoch,c.revocation_generation)!=(identity.generation,relation.epoch,relation.revocation_generation):
            raise Stop("CONSENT_FENCE_STALE")
        return c

    def _record(self,relation):
        if self.records is None: raise Unavailable()
        record=self.records.get(relation.protocol.protocol_id)
        if type(record) is not ProtocolRecord or record.reference!=relation.protocol: raise Stop("PROTOCOL_RECORD_MISMATCH")
        p=record.provenance
        if type(p) is not Provenance or type(p.classification) is not Classification:
            raise Stop("PROVENANCE_MALFORMED","QUARANTINE")
        # No approved reviewed-protocol registry or real wallet verifier exists.
        if p.classification==Classification.REVIEWED_PROTOCOL_DATA:
            raise Stop("CANONICAL_PROTOCOL_BLOCKED","QUARANTINE")
        if p.classification not in (Classification.DEMO_FIXTURE,Classification.LEGACY_UNTRUSTED_XP):
            raise Stop("SOURCE_CLASS_INVALID","QUARANTINE")
        if relation.protocol.contract==LEGACY and p.classification!=Classification.LEGACY_UNTRUSTED_XP:
            raise Stop("LEGACY_PROMOTION_DENIED")
        if (p.origin!="SYNTHETIC_FIXTURE" or p.confidence!="SYNTHETIC_ONLY"
                or not p.source_ref.startswith("fixture://") or p.review_ref is not None
                or p.block_number is not None or p.block_hash is not None):
            raise Stop("SYNTHETIC_PROVENANCE_REQUIRED","QUARANTINE")
        expected=digest({"reference":asdict(record.reference),"reported_xp":record.reported_xp,"reported_tier":record.reported_tier})
        if p.source_digest!=expected: raise Stop("SOURCE_DIGEST_MISMATCH")
        if type(record.reported_xp) is not int or not 0<=record.reported_xp<2**256 or type(record.reported_tier) is not int or not 0<=record.reported_tier<=2:
            raise Stop("PROTOCOL_RECORD_MALFORMED")
        return record

    def read(self,request,token,*,deliver=None,operation="read"):
        trace=str(uuid.uuid4());identity=None;held=False;guard=False;slot=False
        rid=request.request_id if type(request) is ReadRequest else str(uuid.uuid4())
        end=time.monotonic()+self.deadline
        def result(outcome,reason): return Decision(outcome,reason,trace,rid)
        try:
            if type(request) is not ReadRequest: raise Stop("REQUEST_INVALID")
            uuid_string(request.request_id);uuid_string(request.profile_id)
            if operation not in ("read","bind"): raise Stop("OPERATION_DENIED")
            if not self.slots.acquire(blocking=False): raise Stop("CAPACITY_EXHAUSTED","QUARANTINE")
            slot=True
            if type(token) is not str or not token or len(token)>8192: raise Stop("AUTH_REQUIRED")
            identity=self.workers.run(self.adapters.jwt,"verify",(token,),end)
            Gateway._identity(identity)
            user=self.workers.run(self.adapters.user,"observe",(identity,),end)
            if type(user) is not UserObservation or user.subject!=identity.subject: raise Stop("USER_MISMATCH")
            self._session(identity,end)
            self._relation(identity,request)
            if self.workers.run(self.adapters.policy,"authorize",(identity,request),end) is not True:
                raise Stop("POLICY_DENIED")
            held=self.primary.acquire(identity.subject,max(0,end-time.monotonic()))
            if not held: raise ExpiredDeadline()
            guard=self.lock.acquire(timeout=max(0,end-time.monotonic()))
            if not guard: raise ExpiredDeadline()
            local=self.primary.snapshot(identity.subject)
            if type(local) is not LocalState or type(local.generation) is not int or local.generation!=identity.generation: raise Stop("GENERATION_STALE")
            if local.binding_status not in ("unbound","active"): raise Stop("LOCAL_SUSPENSION")
            relation=self._relation(identity,request)
            if operation=="bind": raise Stop("MUTATION_QUARANTINED","QUARANTINE")
            consent=self._consent(identity,request,relation)
            record=self._record(relation)
            if not callable(deliver): raise Stop("DELIVERY_REQUIRED","QUARANTINE")
            payload_digest=digest(asdict(request))
            prior=self.requests.get((identity.subject,rid))
            if prior is not None and prior!=payload_digest: raise Stop("REQUEST_DIGEST_CONFLICT")
            if prior is None and len(self.requests)>=256: raise Stop("REQUEST_CAPACITY","QUARANTINE")
            decision=result("ALLOW","SYNTHETIC_READ_AUTHORIZED")
            event=self.audit.event(decision,identity.subject,record.provenance.classification.value)
            if self.workers.run(self.adapters.emitter,"approve",(event,),end) is not True: raise Unavailable()
            self._session(identity,end)
            if self.workers.run(self.adapters.policy,"authorize",(identity,request),end) is not True:
                raise Stop("POLICY_DENIED")
            Gateway._identity(identity)
            if self.primary.snapshot(identity.subject)!=local or self._relation(identity,request)!=relation:
                raise Stop("GENERATION_STALE")
            self._consent(identity,request,relation)
            if time.monotonic()>=end: raise ExpiredDeadline()
            response={"profile_id":relation.profile_id,"wallet":asdict(relation.wallet),
                      "protocol":asdict(record.reference),"provenance":asdict(record.provenance),
                      "wallet_assurance":Classification.DEMO_FIXTURE.value,"wallet_control_verified":False,
                      "unique_human_verified":False,"canonical_xp":None,"entitlements":[],
                      "synthetic_observation":{"reported_xp":record.reported_xp,"reported_tier":record.reported_tier},
                      "consent_version":consent.version,"consent_proof_kind":consent.proof_kind,
                      "epoch":relation.epoch,"generation":local.generation,"revocation_generation":relation.revocation_generation,
                      "trace_id":trace,"request_id":rid,"payload_digest":payload_digest}
            # Bookkeeping only. No protocol/wallet/domain state is mutated.
            self.audit.commit(event)
            self.used.add(consent.consent_id)
            self.requests[(identity.subject,rid)]=payload_digest
            try: deliver(response)
            except Exception: return result("QUARANTINE","DELIVERY_FAILED_NO_RETRY")
            return decision
        except Stop as exc: decision=result(exc.outcome,exc.reason)
        except Rejected as exc: decision=result("DENY",exc.reason.value)
        except ExpiredDeadline: decision=result("QUARANTINE","DEPENDENCY_TIMEOUT")
        except Unavailable: decision=result("QUARANTINE","DEPENDENCY_UNAVAILABLE")
        except Exception: decision=result("QUARANTINE","UNEXPECTED_FAILURE")
        finally:
            if guard:self.lock.release()
            if held:self.primary.release(identity.subject)
            if slot:self.slots.release()
        try:self.audit.commit(self.audit.event(decision,identity.subject if type(identity) is Identity else None))
        except Exception:pass
        return decision

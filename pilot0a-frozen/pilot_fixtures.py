"""Trusted test builder, not an issuance endpoint or real identity authority."""
from dataclasses import asdict,dataclass,replace
import hmac
import hashlib
import secrets
import time
import uuid
from bootstrap import *
from b23r6a.gateway import Adapters
from contracts import *
from harness import Harness

SESSION_B="00000000-0000-4000-8000-000000000012"

@dataclass(frozen=True)
class IdentityPolicy:
    def authorize(self,identity,request):
        return (identity.subject,request.profile_id) in ((USER_A,PROFILE_A),(USER_B,PROFILE_B))

class Clock:
    def __init__(self):self.now=1_000_000
    def __call__(self):return self.now

class Fixture:
    def __init__(self):
        self.clock=Clock();self.jwt_key=secrets.token_bytes(32);self.consent_key=secrets.token_bytes(32)
        self.primary=OfflinePrimary()
        self.adapters=Adapters(OfflineJwtVerifier(self.jwt_key),OfflineUsers(),
            OfflineSessions(((USER_A,SESSION_A,SessionState.ACTIVE,0),(USER_B,SESSION_B,SessionState.ACTIVE,0))),
            IdentityPolicy(),OfflineEmitter())
        self.a=Relation(PROFILE_A,USER_A,WalletRef(CHAIN,WALLET_A),ProtocolRef("fixture:PIE:A",CHAIN,DEMO_CONTRACT,WALLET_A))
        self.b=Relation(PROFILE_B,USER_B,WalletRef(CHAIN,WALLET_B),ProtocolRef("fixture:PIE:B:legacy",CHAIN,LEGACY,WALLET_B))
        self.records=[self.record(self.a,25,Classification.DEMO_FIXTURE),self.record(self.b,1_000_000,Classification.LEGACY_UNTRUSTED_XP)]
        self.ca=self.consent(self.a,SESSION_A);self.cb=self.consent(self.b,SESSION_B)
        self.harness=Harness(self.adapters,self.primary,(self.a,self.b),self.records,(self.ca,self.cb),self.consent_key,self.clock)
        # This immutable tuple is the complete synthetic token-state fixture.
        self.token_state=("SYNTHETIC_TOKEN",0,0,0)

    def record(self,relation,xp,classification):
        data={"reference":asdict(relation.protocol),"reported_xp":xp,"reported_tier":0}
        return ProtocolRecord(relation.protocol,xp,0,Provenance(classification,"SYNTHETIC_FIXTURE",f"fixture://pie/{relation.profile_id}",digest(data),"SYNTHETIC_ONLY"))

    def sign_mock(self,consent):
        data=asdict(consent);data.pop("mock_mac")
        return replace(consent,mock_mac=hmac.new(self.consent_key,canonical(data).encode(),hashlib.sha256).hexdigest())

    def consent(self,relation,session,**changes):
        c=Consent(str(uuid.uuid4()),str(uuid.uuid4()),relation.principal,relation.profile_id,session,
                  relation.protocol,("identity:read",),"0A-MOCK-v1",self.clock.now,self.clock.now+120,0,relation.epoch,relation.revocation_generation)
        return self.sign_mock(replace(c,**changes))

    def request(self,who="A",**changes):
        r,c=(self.a,self.ca) if who=="A" else (self.b,self.cb)
        return replace(ReadRequest(str(uuid.uuid4()),r.profile_id,r.wallet.chain_id,r.wallet.address,r.protocol.contract,r.protocol.protocol_id,c),**changes)

    def token(self,who="A",**changes):
        return test_token(self.jwt_key,sub=USER_A if who=="A" else USER_B,session_id=SESSION_A if who=="A" else SESSION_B,**changes)

    def register_consent(self,consent):
        # Test-only setup; never reachable from a caller request.
        self.harness.consents[consent.consent_id]=consent

    def snapshot(self):
        return canonical({"relations":[asdict(r) for r in self.harness.relations.values()],
                          "records":[asdict(r) for r in self.harness.records.values()],"tokens":self.token_state})

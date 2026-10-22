import ast
from dataclasses import replace,asdict
import inspect
import json
import multiprocessing
from pathlib import Path
import subprocess
import threading
import time
import unittest
import uuid
from unittest.mock import patch
from bootstrap import *
from contracts import *
from harness import AuditSink
from pilot_fixtures import Fixture,SESSION_B
from b23r6a.gateway import Adapters
from b23r6a.adapters.offline import OfflinePolicy

class SharedSession:
    def __init__(self,flag):self.flag=flag
    def observe(self,identity):
        return SessionObservation(identity.subject,identity.session_id,
            (SessionState.ACTIVE,SessionState.REVOKED,SessionState.UNKNOWN)[self.flag.value],0)

class FlipAtAudit:
    def __init__(self,flag,value):self.flag,self.value=flag,value
    def approve(self,event):self.flag.value=self.value;return True

class SharedPolicy:
    def __init__(self,flag):self.flag=flag
    def authorize(self,identity,request):return self.flag.value==0

class DelayedReadOnly:
    def __init__(self,target):self.target=target
    def _run(self,method,*args):time.sleep(.10);return getattr(self.target,method)(*args)
    def verify(self,*args):return self._run("verify",*args)
    def observe(self,*args):return self._run("observe",*args)
    def authorize(self,*args):return self._run("authorize",*args)
    def approve(self,*args):return self._run("approve",*args)

class IdentitySecurity(unittest.TestCase):
    def setUp(self):self.f=Fixture();self.h=self.f.harness
    def call(self,request=None,token=None,**options):
        data=[]
        decision=self.h.read(request or self.f.request(),token if token is not None else self.f.token(),deliver=data.append,**options)
        self.assertFalse(self.h.workers.active)
        if decision.outcome!="ALLOW":self.assertEqual(data,[])
        return decision,data
    def deny(self,request,reason,**options):
        d,data=self.call(request,**options);self.assertEqual(d.outcome,"DENY");self.assertEqual(d.reason,reason)

    def test_own_demo_read_has_no_canonical_authority(self):
        before=self.f.snapshot();d,data=self.call()
        self.assertEqual(d.outcome,"ALLOW");self.assertEqual(data[0]["profile_id"],PROFILE_A)
        self.assertIsNone(data[0]["canonical_xp"]);self.assertEqual(data[0]["entitlements"],[])
        self.assertFalse(data[0]["wallet_control_verified"]);self.assertFalse(data[0]["unique_human_verified"])
        self.assertEqual(data[0]["provenance"]["classification"],Classification.DEMO_FIXTURE)
        self.assertEqual(self.f.snapshot(),before)

    def test_own_legacy_read_never_promotes_arbitrary_xp(self):
        d,data=self.call(self.f.request("B"),self.f.token("B"))
        self.assertEqual(d.outcome,"ALLOW");self.assertEqual(data[0]["synthetic_observation"]["reported_xp"],1_000_000)
        self.assertIsNone(data[0]["canonical_xp"])
        self.assertEqual(data[0]["provenance"]["classification"],Classification.LEGACY_UNTRUSTED_XP)

    def test_user_a_cannot_read_user_b(self):self.deny(self.f.request("B"),"PROFILE_NOT_OWNED")
    def test_user_a_cannot_bind_user_b(self):self.deny(self.f.request("B"),"PROFILE_NOT_OWNED",operation="bind")
    def test_own_binding_request_is_still_quarantined(self):
        before=self.f.snapshot();d,_=self.call(operation="bind")
        self.assertEqual(d.outcome,"QUARANTINE");self.assertEqual(d.reason,"MUTATION_QUARANTINED")
        self.assertEqual(before,self.f.snapshot());self.assertFalse(self.h.used)

    def test_caller_asserted_auth_context_is_rejected(self):
        d,_=self.call(token={"subject":USER_A,"session_id":SESSION_A})
        self.assertEqual(d.reason,"AUTH_REQUIRED");self.assertEqual(d.outcome,"DENY")
    def test_wrong_chain_isolated(self):self.deny(self.f.request(chain_id=1),"CHAIN_MISMATCH")
    def test_wrong_wallet_isolated(self):self.deny(self.f.request(wallet=WALLET_B),"WALLET_MISMATCH")
    def test_wrong_contract_isolated(self):self.deny(self.f.request(contract=LEGACY),"CONTRACT_MISMATCH")
    def test_wrong_protocol_isolated(self):self.deny(self.f.request(protocol_id=self.f.b.protocol.protocol_id),"PROTOCOL_MISMATCH")
    def test_invalid_address_is_rejected(self):self.deny(self.f.request(wallet="0xDEMO"),"ADDRESS_INVALID")
    def test_missing_consent(self):self.deny(self.f.request(consent=None),"CONSENT_MISSING")

    def test_expiration_boundary_is_exclusive(self):
        self.f.clock.now=self.f.ca.expires_at
        self.deny(self.f.request(),"CONSENT_EXPIRED")
    def test_future_consent_is_rejected(self):
        self.f.clock.now=self.f.ca.issued_at-1
        self.deny(self.f.request(),"CONSENT_EXPIRED")
    def test_replayed_consent_with_new_request_id_is_rejected(self):
        self.assertEqual(self.call()[0].outcome,"ALLOW")
        self.deny(self.f.request(),"CONSENT_REPLAY")
    def test_foreign_consent_is_rejected(self):self.deny(self.f.request(consent=self.f.cb),"CONSENT_ASSOCIATION_MISMATCH")
    def test_consent_field_tampering_is_rejected(self):
        self.deny(self.f.request(consent=replace(self.f.ca,profile_id=PROFILE_B)),"CONSENT_TAMPERED")
    def test_unauthorized_scope_with_valid_mock_mac_is_rejected(self):
        c=self.f.sign_mock(replace(self.f.ca,scopes=("mint:xp",)))
        self.f.register_consent(c);self.deny(self.f.request(consent=c),"CONSENT_SCOPE_OR_VERSION")
    def test_consent_revocation_is_rejected(self):
        self.h.revoked.add(self.f.ca.consent_id);self.deny(self.f.request(),"CONSENT_REVOKED")
    def test_stale_epoch_invalidates_old_consent(self):
        self.h.relations[PROFILE_A]=replace(self.f.a,epoch=1)
        self.deny(self.f.request(),"CONSENT_FENCE_STALE")
    def test_stale_revocation_generation_invalidates_old_consent(self):
        self.h.relations[PROFILE_A]=replace(self.f.a,revocation_generation=1)
        self.deny(self.f.request(),"CONSENT_FENCE_STALE")
    def test_stale_auth_generation_is_rejected(self):
        self.f.primary.revoke(USER_A);self.deny(self.f.request(),"GENERATION_STALE")
    def test_local_suspension_blocks_read(self):
        self.f.primary.states[USER_A]=LocalState(0,"suspended")
        self.deny(self.f.request(),"LOCAL_SUSPENSION")
    def test_revoked_session_blocks_read(self):
        self.h.adapters=replace(self.f.adapters,session=OfflineSessions(((USER_A,SESSION_A,SessionState.REVOKED,0),)))
        self.deny(self.f.request(),"SESSION_REVOKED")
    def test_unknown_session_quarantines_read(self):
        self.h.adapters=replace(self.f.adapters,session=OfflineSessions(()))
        d,_=self.call();self.assertEqual(d.outcome,"QUARANTINE");self.assertEqual(d.reason,"SESSION_UNKNOWN")
    def test_each_missing_authority_dependency_fails_closed(self):
        for name in ("jwt","user","session","policy","emitter"):
            with self.subTest(dependency=name):
                self.h.adapters=replace(self.f.adapters,**{name:None})
                d,_=self.call();self.assertEqual(d.outcome,"QUARANTINE");self.assertEqual(d.reason,"DEPENDENCY_UNAVAILABLE")
                self.assertFalse(self.h.used)
    def test_authority_timeout_then_fresh_retry(self):
        self.h.adapters=replace(self.f.adapters,session=FaultAdapter(delay=3))
        d,_=self.call();self.assertEqual(d.reason,"DEPENDENCY_TIMEOUT");self.assertEqual(d.outcome,"QUARANTINE")
        self.assertFalse(self.h.used);self.h.adapters=self.f.adapters
        self.assertEqual(self.call()[0].outcome,"ALLOW")
    def test_audit_outage_blocks_delivery_and_ticket_consumption(self):
        self.h.audit.available=False
        d,_=self.call();self.assertEqual(d.outcome,"QUARANTINE");self.assertEqual(d.reason,"DEPENDENCY_UNAVAILABLE")
        self.assertFalse(self.h.used);self.h.audit.available=True
        self.assertEqual(self.call()[0].outcome,"ALLOW")
    def test_each_allowed_read_has_source_and_trace(self):
        for who in ("A","B"):
            d,data=self.call(self.f.request(who),self.f.token(who))
            self.assertEqual(d.outcome,"ALLOW")
            self.assertEqual(data[0]["trace_id"],d.trace_id)
            event=self.h.audit.events[-1];self.assertEqual(event["trace_id"],d.trace_id)
            self.assertEqual(event["source_classification"],data[0]["provenance"]["classification"])
            self.assertEqual(len(data[0]["provenance"]["source_digest"]),64)
    def test_audit_is_bounded_and_pseudonymized(self):
        self.h.audit=AuditSink(2)
        for _ in range(4):self.call(token="invalid")
        self.assertEqual(len(self.h.audit.events),2)
        text=json.dumps(list(self.h.audit.events))
        for value in (USER_A,USER_B,PROFILE_A,PROFILE_B,SESSION_A,WALLET_A,self.f.token()):self.assertNotIn(value,text)
    def test_xp_tier_and_token_state_are_unchanged(self):
        before=self.f.snapshot();self.call();self.call(self.f.request("B"),self.f.token("B"));self.call(operation="bind")
        self.assertEqual(before,self.f.snapshot())
    def test_legacy_cannot_be_relabelled_demo(self):
        r=self.f.records[1];self.h.records[r.reference.protocol_id]=replace(r,provenance=replace(r.provenance,classification=Classification.DEMO_FIXTURE))
        self.deny(self.f.request("B"),"LEGACY_PROMOTION_DENIED",token=self.f.token("B"))
    def test_reviewed_protocol_label_requires_missing_review_gate(self):
        r=self.f.records[0];self.h.records[r.reference.protocol_id]=replace(r,provenance=replace(r.provenance,classification=Classification.REVIEWED_PROTOCOL_DATA))
        d,_=self.call();self.assertEqual(d.outcome,"QUARANTINE");self.assertEqual(d.reason,"CANONICAL_PROTOCOL_BLOCKED")
    def test_verified_wallet_label_requires_real_proof(self):
        self.h.relations[PROFILE_A]=replace(self.f.a,wallet_assurance=Classification.VERIFIED_WALLET_CONTROL)
        d,_=self.call();self.assertEqual(d.outcome,"QUARANTINE");self.assertEqual(d.reason,"REAL_WALLET_PROOF_UNIMPLEMENTED")
    def test_record_tampering_is_rejected(self):
        r=self.f.records[0];self.h.records[r.reference.protocol_id]=replace(r,reported_xp=999999)
        self.deny(self.f.request(),"SOURCE_DIGEST_MISMATCH")
    def test_synthetic_record_cannot_claim_live_chain_provenance(self):
        r=self.f.records[0];self.h.records[r.reference.protocol_id]=replace(r,provenance=replace(r.provenance,origin="ETHERSCAN_VERIFIED"))
        d,_=self.call();self.assertEqual(d.outcome,"QUARANTINE");self.assertEqual(d.reason,"SYNTHETIC_PROVENANCE_REQUIRED")
    def test_concurrent_same_consent_is_single_use(self):
        outcomes=[];data=[];errors=[];barrier=threading.Barrier(2)
        def read():
            try:
                barrier.wait(2);outcomes.append(self.h.read(self.f.request(),self.f.token(),deliver=data.append))
            except BaseException as e:errors.append(e)
        threads=[threading.Thread(target=read) for _ in range(2)]
        for t in threads:t.start()
        for t in threads:t.join(5)
        self.assertFalse(errors);self.assertTrue(all(not t.is_alive() for t in threads))
        self.assertEqual(sorted(d.outcome for d in outcomes),["ALLOW","DENY"])
        self.assertEqual([d.reason for d in outcomes if d.outcome=="DENY"],["CONSENT_REPLAY"])
        self.assertEqual(len(data),1);self.assertFalse(self.h.workers.active)
    def test_revocation_committed_before_fence_blocks_delivery(self):
        attempted=threading.Event();output=[];outcomes=[];errors=[]
        primary=self.f.primary;original=primary.acquire;primary.acquire(USER_A,1)
        def acquire(subject,timeout):attempted.set();return original(subject,timeout)
        def read():
            try:outcomes.append(self.h.read(self.f.request(),self.f.token(),deliver=output.append))
            except BaseException as e:errors.append(e)
        t=threading.Thread(target=read)
        try:
            with patch.object(primary,"acquire",acquire):
                t.start();self.assertTrue(attempted.wait(2));primary.revoke(USER_A)
        finally:primary.release(USER_A);t.join(5)
        self.assertFalse(t.is_alive());self.assertFalse(errors);self.assertEqual(output,[])
        self.assertEqual(outcomes[0].reason,"GENERATION_STALE")
    def test_delivery_holds_fence_until_read_is_released(self):
        entered=threading.Event();attempted=threading.Event();done=threading.Event();output=[]
        def revoke():
            if entered.wait(3):attempted.set();self.f.primary.revoke(USER_A);done.set()
        t=threading.Thread(target=revoke);t.start()
        def delivery(body):
            entered.set();self.assertTrue(attempted.wait(1));self.assertFalse(done.wait(.05));output.append(body)
        try:d=self.h.read(self.f.request(),self.f.token(),deliver=delivery)
        finally:entered.set();t.join(4)
        self.assertFalse(t.is_alive());self.assertTrue(done.is_set());self.assertEqual(d.outcome,"ALLOW");self.assertEqual(len(output),1)
        self.deny(self.f.request(),"GENERATION_STALE")
    def test_final_session_revoked_during_audit_is_rejected(self):
        flag=multiprocessing.get_context("spawn").Value("i",0)
        self.h.adapters=replace(self.f.adapters,session=SharedSession(flag),emitter=FlipAtAudit(flag,1))
        self.deny(self.f.request(),"SESSION_REVOKED")
    def test_final_session_unknown_during_audit_is_quarantined(self):
        flag=multiprocessing.get_context("spawn").Value("i",0)
        self.h.adapters=replace(self.f.adapters,session=SharedSession(flag),emitter=FlipAtAudit(flag,2))
        d,_=self.call();self.assertEqual(d.outcome,"QUARANTINE");self.assertEqual(d.reason,"SESSION_UNKNOWN")
    def test_final_policy_revoked_during_audit_is_rejected(self):
        flag=multiprocessing.get_context("spawn").Value("i",0)
        self.h.adapters=replace(self.f.adapters,policy=SharedPolicy(flag),emitter=FlipAtAudit(flag,1))
        self.deny(self.f.request(),"POLICY_DENIED")
    def test_same_request_id_with_changed_valid_ticket_conflicts(self):
        req=self.f.request();self.assertEqual(self.call(req)[0].outcome,"ALLOW")
        c=self.f.consent(self.f.a,SESSION_A);self.f.register_consent(c)
        self.deny(replace(req,consent=c),"REQUEST_DIGEST_CONFLICT")
    def test_missing_delivery_does_not_create_allow_capability(self):
        d=self.h.read(self.f.request(),self.f.token())
        self.assertEqual(d.reason,"DELIVERY_REQUIRED");self.assertEqual(d.outcome,"QUARANTINE");self.assertFalse(self.h.used)
    def test_transport_failure_is_not_retried(self):
        calls=[]
        def failed(body):calls.append(body);raise RuntimeError()
        d=self.h.read(self.f.request(),self.f.token(),deliver=failed)
        self.assertEqual(d.reason,"DELIVERY_FAILED_NO_RETRY");self.assertEqual(len(calls),1)
        self.deny(self.f.request(),"CONSENT_REPLAY")
    def test_malformed_consent_clock_fails_closed(self):
        self.f.clock.now=float("nan")
        d,_=self.call();self.assertEqual(d.outcome,"QUARANTINE");self.assertEqual(d.reason,"CLOCK_OR_CONSENT_MALFORMED")
    def test_all_protocol_write_operations_are_absent(self):
        before=self.f.snapshot()
        for op in ("gainXP","addXP","mint","burn","transfer","upgradeTier"):
            self.deny(self.f.request(),"OPERATION_DENIED",operation=op)
        self.assertEqual(before,self.f.snapshot())

class SourceCompatibility(unittest.TestCase):
    def setUp(self):self.root=Path(__file__).resolve().parent/"evidence/sources"
    def test_verified_source_exactly_matches_contracts_copy(self):
        self.assertEqual((self.root/"etherscan/verified-PIECore.sol").read_bytes(),(self.root/"pie/mainContracts.sol").read_bytes())
    def test_verified_abi_exactly_matches_compiled_artifact(self):
        self.assertEqual(json.loads((self.root/"etherscan/abi.json").read_text()),json.loads((self.root/"pie/compiledABI.json").read_text()))
    def test_deployment_script_points_at_a_different_abi(self):
        deployed=json.loads((self.root/"etherscan/abi.json").read_text())
        old=json.loads((self.root/"pie/artifactABI.json").read_text())
        self.assertNotEqual(old,deployed)
        old_names={f.get("name") for f in old};live_names={f.get("name") for f in deployed}
        self.assertNotIn("getXP",old_names);self.assertIn("getXP",live_names)
        self.assertIn('./contracts_PIECore_sol_PIECore.abi',(self.root/"pie/deployScript.js").read_text())
    def test_legacy_gainxp_is_permissionless_source_oracle(self):
        text=(self.root/"etherscan/verified-PIECore.sol").read_text()
        self.assertIn('function gainXP(uint256 amount) external {',text)
        body=text.split('function gainXP(uint256 amount) external {')[1].split('}')[0]
        self.assertIn('identities[msg.sender].xp += amount;',body)
        self.assertEqual(body.count('require('),1)
        self.assertIn('path != Path.None',body)
    def test_baseline_test_explicitly_demonstrates_vulnerability(self):
        text=(self.root/"pie/baseline.js").read_text()
        self.assertIn('SECURITY FINDING: User can arbitrarily increase own XP via gainXP()',text)
        self.assertIn('gainXP(1000000)',text);self.assertIn('expect(identity.xp).to.equal(1000000)',text)
    def test_root_copy_is_not_deployed_implementation(self):
        a=(self.root/"pie/mainRoot.sol").read_text();b=(self.root/"etherscan/verified-PIECore.sol").read_text()
        self.assertNotEqual(a,b);self.assertNotIn('function gainXP(',a)
        self.assertIn('function upgradeTier(address user)',a)
    def test_pinned_v02_is_candidate_not_legacy_or_release_approval(self):
        text=(self.root/"pie/v02.sol").read_text()
        self.assertIn('GENESIS_XP = 25',text);self.assertNotIn('function gainXP(',text);self.assertNotIn('function addXP(',text)
        gate=(self.root/"pie/v02gates.md").read_text();self.assertIn('OPEN / NOT ACCEPTED',gate)
    def test_octogflo_adapters_are_types_only(self):
        text=(self.root/"octogflo/src/domain/octopass-adapters.ts").read_text()
        self.assertIn('Types only',text);self.assertIn('canonicalXp: number',text)
        self.assertIn('nothing implements them',text)
    def test_r6a_deadline_drift_is_reported_not_closed(self):
        self.assertEqual(inspect.signature(Gateway.__init__).parameters['timeout'].default,2.0)
        self.assertNotEqual(inspect.signature(Gateway.__init__).parameters['timeout'].default,1.0)
    def test_r6a_accepts_read_beyond_original_one_second_budget(self):
        # A passing diagnostic REPRODUCES the specification finding.
        f=Fixture()
        adapters=Adapters(*[DelayedReadOnly(a) for a in (
            OfflineJwtVerifier(f.jwt_key),OfflineUsers(),OfflineSessions(),OfflinePolicy(),OfflineEmitter())])
        gateway=Gateway(adapters,f.primary);data=[];start=time.monotonic()
        result=gateway.handle({"operation":"audit.summary.read","request_id":str(uuid.uuid4()),"payload":{}},f.token(),include_data=True,deliver=data.append)
        elapsed=time.monotonic()-start
        self.assertEqual(result.decision.value,"ALLOW");self.assertGreater(elapsed,1.0)
        self.assertFalse(gateway.workers.active);self.assertIn("data",data[0])
        print(f"DIAGNOSTIC: R6A ALLOW after {elapsed:.3f}s; original 1s requirement NOT MET",flush=True)
    def test_r6a_anchor_permissions_and_86_manifest_unchanged(self):
        check_anchor()
        manifest=json.loads((R6A_ROOT/'b23r6a/test-manifest.json').read_text())
        self.assertEqual(sum(map(len,manifest.values())),86)
        self.assertEqual((R6A_ROOT/'b23r6a/test-manifest.json').read_bytes(),subprocess.check_output(['git','show',R6A_HEAD+':b23r6a/test-manifest.json'],cwd=R6A_ROOT))
        self.assertEqual((R6A_ROOT/'b23r5/sql/005_operational_quarantine.sql').read_bytes(),subprocess.check_output(['git','show','2362ce622daf896248265a03efca00d6ef72a9a7:b23r5/sql/005_operational_quarantine.sql'],cwd=R6A_ROOT))
    def test_harness_has_no_http_rpc_database_or_transaction_client(self):
        source=ast.parse((Path(__file__).resolve().parent/'harness.py').read_text())
        imports=[n.module for n in ast.walk(source) if isinstance(n,ast.ImportFrom)]
        imports += [a.name for n in ast.walk(source) if isinstance(n,ast.Import) for a in n.names]
        for module in imports:self.assertNotIn(module.split('.')[0],('socket','http','requests','web3','psycopg','sqlalchemy','ethers'))

if __name__=='__main__':unittest.main(verbosity=2)

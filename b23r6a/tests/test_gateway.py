import json
import secrets
import tempfile
import threading
import time
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from b23r6a.contracts import *
from b23r6a.gateway import Gateway, Adapters
from b23r6a.adapters.offline import (OfflineJwtVerifier, OfflineUsers, OfflineSessions,
    OfflinePolicy, OfflineEmitter, OfflinePrimary, FaultAdapter, test_token, USER_A, USER_B, SESSION_A)

class SharedAuthority:
    def __init__(self, flag): self.flag=flag
    def observe(self, identity):
        if self.flag.value==5:
            return SessionObservation(identity.subject,identity.session_id,"ACTIVE",0)
        state=(SessionState.ACTIVE,SessionState.REVOKED,SessionState.UNKNOWN)[self.flag.value]
        return SessionObservation(identity.subject,identity.session_id,state,0)

class SwitchAtAudit:
    def __init__(self, flag, value): self.flag,self.value=flag,value
    def approve(self,event): self.flag.value=self.value;return True

class SharedPolicy:
    def __init__(self, flag): self.flag=flag
    def authorize(self,identity,request): return self.flag.value==0

class BrokenStore:
    def event(self,*args): return {}
    def summary(self): return {"secret":"must never be released"}
    def commit(self,event): raise RuntimeError("sink unavailable")

def configured(**changes):
    key = secrets.token_bytes(32)
    bundle = Adapters(OfflineJwtVerifier(key), OfflineUsers(), OfflineSessions(), OfflinePolicy(), OfflineEmitter())
    return key, replace(bundle, **changes)

def request(operation="audit.summary.read", **payload):
    return {"operation": operation, "request_id": str(uuid.uuid4()), "payload": payload}

class GatewaySecurity(unittest.TestCase):
    def setUp(self):
        self.key, self.adapters = configured()
        self.primary = OfflinePrimary()
        self.gateway = Gateway(self.adapters, self.primary)
        self.token = test_token(self.key)

    def call(self, value=None, token=None):
        output = []
        d = self.gateway.handle(value or request(), token or self.token, include_data=True, deliver=output.append)
        self.assertFalse(self.gateway.workers.active)
        return d, output[0]

    def test_valid_offline_observer_authorized(self):
        d, body = self.call()
        self.assertEqual(d.decision, Outcome.ALLOW)
        self.assertIn("data", body)

    def test_invalid_jwt_signature_denied(self):
        d, body = self.call(token=test_token(secrets.token_bytes(32)))
        self.assertEqual(d.reason_code, Reason.AUTH_INVALID)
        self.assertNotIn("data", body)

    def test_expired_jwt_denied(self):
        self.assertEqual(self.call(token=test_token(self.key, exp=1))[0].reason_code, Reason.AUTH_EXPIRED)

    def test_foreign_issuer_denied(self):
        self.assertEqual(self.call(token=test_token(self.key, iss="https://foreign.test"))[0].reason_code, Reason.AUTH_ISSUER)

    def test_foreign_audience_denied(self):
        self.assertEqual(self.call(token=test_token(self.key, aud="foreign"))[0].reason_code, Reason.AUTH_AUDIENCE)

    def test_foreign_project_denied(self):
        self.assertEqual(self.call(token=test_token(self.key, project="foreign"))[0].reason_code, Reason.AUTH_PROJECT)

    def test_missing_session_claim_denied(self):
        import jwt
        claims = jwt.decode(self.token, options={"verify_signature": False})
        del claims["session_id"]
        self.assertEqual(self.call(token=jwt.encode(claims, self.key, algorithm="HS256"))[0].reason_code, Reason.AUTH_INVALID)

    def test_body_auth_context_rejected(self):
        value=request(); value["authenticatedProfile"]=USER_B
        self.assertEqual(self.call(value)[0].reason_code, Reason.INVALID_REQUEST)

    def test_user_a_cannot_target_user_b(self):
        self.assertEqual(self.call(request("wallet.binding.suspend",target_profile_ref=USER_B))[0].reason_code, Reason.SUBJECT_MISMATCH)

    def test_revoked_session_denied(self):
        self.gateway.adapters=replace(self.adapters, session=OfflineSessions(((USER_A,SESSION_A,SessionState.REVOKED,0),)))
        self.assertEqual(self.call()[0].reason_code, Reason.SESSION_REVOKED)

    def test_unknown_session_quarantined(self):
        self.gateway.adapters=replace(self.adapters, session=OfflineSessions(()))
        d,body=self.call();self.assertEqual(d.reason_code,Reason.SESSION_UNKNOWN);self.assertNotIn("data",body)

    def test_user_lookup_does_not_prove_session(self):
        self.gateway.adapters=replace(self.adapters, session=None)
        self.assertEqual(self.call()[0].decision,Outcome.QUARANTINE)

    def test_auth_timeout_quarantined(self):
        self.gateway.adapters=replace(self.adapters, session=FaultAdapter(delay=2))
        self.assertEqual(self.call()[0].reason_code,Reason.AUTHORITY_TIMEOUT)

    def test_partial_authority_failure_quarantined(self):
        self.gateway.adapters=replace(self.adapters, session=FaultAdapter())
        self.assertEqual(self.call()[0].reason_code,Reason.AUTHORITY_UNAVAILABLE)

    def test_authority_recovery_requires_new_attempt(self):
        req=request();self.gateway.adapters=replace(self.adapters,session=None)
        d,_=self.call(req);self.assertEqual(d.decision,Outcome.QUARANTINE)
        self.gateway.adapters=self.adapters
        self.assertEqual(self.call(req)[0].decision,Outcome.ALLOW)

    def test_stale_generation_denied(self):
        self.primary.revoke(USER_A)
        self.assertEqual(self.call()[0].reason_code,Reason.GENERATION_STALE)

    def test_suspension_wins_before_authorization(self):
        self.primary.states[USER_A]=LocalState(0,"suspended")
        self.assertEqual(self.call()[0].reason_code,Reason.BINDING_SUSPENDED)

    def test_generation_change_during_read_denied(self):
        self.primary.acquire(USER_A,1)
        self.primary.states[USER_A]=LocalState(1,"suspended")
        self.primary.release(USER_A)
        d,body=self.call();self.assertEqual(d.decision,Outcome.DENY);self.assertNotIn("data",body)

    def test_identical_retry_revalidates_evidence(self):
        req=request();self.assertEqual(self.call(req)[0].decision,Outcome.ALLOW)
        self.gateway.adapters=replace(self.adapters,session=OfflineSessions(((USER_A,SESSION_A,SessionState.REVOKED,0),)))
        self.assertEqual(self.call(req)[0].reason_code,Reason.SESSION_REVOKED)

    def test_digest_conflict_denied(self):
        req=request("wallet.binding.suspend",chain_id=1)
        self.assertEqual(self.call(req)[0].reason_code,Reason.MUTATION_CAPABILITY_DISABLED)
        req["payload"]["chain_id"]=2
        self.assertEqual(self.call(req)[0].reason_code,Reason.REQUEST_DIGEST_CONFLICT)

    def test_sensitive_operation_never_allowed(self):
        for op in SENSITIVE:
            with self.subTest(op=op):
                self.assertEqual(self.call(request(op))[0].reason_code,Reason.MUTATION_CAPABILITY_DISABLED)

    def test_quarantine_has_no_domain_effects(self):
        before=dict(self.primary.states)
        d,body=self.call(request("wallet.binding.activate"))
        self.assertEqual(d.decision,Outcome.QUARANTINE);self.assertEqual(before,self.primary.states);self.assertNotIn("data",body)

    def test_quarantine_is_not_enqueued(self):
        self.call(request("wallet.binding.suspend"))
        self.assertFalse(self.gateway.workers.active)
        self.assertEqual(self.primary.snapshot(USER_A),LocalState())

    def test_health_survives_auth_outage(self):
        self.gateway.adapters=Adapters()
        d,body=self.call(request("system.health.read"))
        self.assertEqual(d.decision,Outcome.ALLOW);self.assertEqual(body["data"],{"status":"ok"})

    def test_observer_requires_explicit_scope(self):
        self.gateway.adapters=replace(self.adapters,policy=OfflinePolicy(frozenset()))
        self.assertEqual(self.call()[0].reason_code,Reason.POLICY_DENIED)

    def test_observer_has_no_domain_mutation(self):
        before=dict(self.primary.states);self.call();self.assertEqual(before,self.primary.states)

    def test_event_redaction(self):
        self.call();serialized=json.dumps(self.gateway.events.snapshot_for_test())
        for secret in (self.token,USER_A,SESSION_A,self.key.hex()):self.assertNotIn(secret,serialized)
        self.assertIn("actor_pseudonym",serialized)

    def test_audit_sink_failure_quarantines_protected_read(self):
        self.gateway.adapters=replace(self.adapters,emitter=FaultAdapter())
        d,body=self.call();self.assertEqual(d.reason_code,Reason.AUDIT_UNAVAILABLE);self.assertNotIn("data",body)

    def test_deadline_cancels_adapter(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=str(Path(tmp)/"late")
            self.gateway.adapters=replace(self.adapters,session=FaultAdapter(.8,late_write=path))
            before=time.monotonic();d,_=self.call()
            self.assertEqual(d.reason_code,Reason.AUTHORITY_TIMEOUT)
            self.assertLess(time.monotonic()-before,1.5)
            time.sleep(.85)
            self.assertFalse(Path(path).exists());self.assertFalse(self.gateway.workers.active)
            self.gateway.adapters=self.adapters
            self.assertEqual(self.call()[0].decision,Outcome.ALLOW)

    def test_repeated_timeouts_do_not_exhaust_workers(self):
        self.gateway.adapters=replace(self.adapters,session=FaultAdapter(2))
        for _ in range(3):self.assertEqual(self.call()[0].decision,Outcome.QUARANTINE)
        self.gateway.adapters=self.adapters
        self.assertEqual(self.call()[0].decision,Outcome.ALLOW)

    def test_delivery_holds_fence_against_revocation(self):
        entered=threading.Event();attempted=threading.Event();done=threading.Event();outputs=[];errors=[]
        def revoke():
            entered.wait(3);attempted.set();self.primary.revoke(USER_A);done.set()
        t=threading.Thread(target=revoke);t.start()
        def deliver(body):
            entered.set();self.assertTrue(attempted.wait(1))
            self.assertFalse(done.wait(.05));outputs.append(body)
        try:
            self.gateway.handle(request(),self.token,include_data=True,deliver=deliver)
        finally:
            entered.set();t.join(3)
        self.assertFalse(t.is_alive());self.assertTrue(done.is_set());self.assertIn("data",outputs[0])
        d,body=self.call();self.assertEqual(d.decision,Outcome.DENY);self.assertNotIn("data",body)

    def test_revocation_before_fence_prevents_delivery(self):
        attempted=threading.Event();output=[];errors=[]
        self.primary.acquire(USER_A,1)
        def read():
            try:attempted.set();self.gateway.handle(request(),self.token,include_data=True,deliver=output.append)
            except BaseException as e:errors.append(e)
        t=threading.Thread(target=read);t.start()
        try:
            self.assertTrue(attempted.wait(1))
            self.primary.revoke(USER_A)
        finally:
            self.primary.release(USER_A);t.join(3)
        self.assertFalse(errors);self.assertFalse(t.is_alive());self.assertNotIn("data",output[0])
        self.assertEqual(output[0]["decision"],"DENY")

    def test_unexpected_adapter_exception_quarantined(self):
        self.gateway.adapters=replace(self.adapters,session=FaultAdapter(fault="unexpected"))
        d,body=self.call();self.assertEqual(d.reason_code,Reason.INTERNAL_ERROR)
        self.assertNotIn("untrusted",json.dumps(body))

    def test_session_revocation_at_final_release_denied(self):
        import multiprocessing
        flag=multiprocessing.get_context("spawn").Value("i",0)
        self.gateway.adapters=replace(self.adapters,session=SharedAuthority(flag),emitter=SwitchAtAudit(flag,1))
        d,body=self.call();self.assertEqual(d.reason_code,Reason.SESSION_REVOKED);self.assertNotIn("data",body)

    def test_session_unknown_at_final_release_quarantined(self):
        import multiprocessing
        flag=multiprocessing.get_context("spawn").Value("i",0)
        self.gateway.adapters=replace(self.adapters,session=SharedAuthority(flag),emitter=SwitchAtAudit(flag,2))
        d,body=self.call();self.assertEqual(d.reason_code,Reason.AUTHORITY_UNAVAILABLE);self.assertNotIn("data",body)

    def test_policy_revocation_at_final_release_denied(self):
        import multiprocessing
        flag=multiprocessing.get_context("spawn").Value("i",0)
        self.gateway.adapters=replace(self.adapters,policy=SharedPolicy(flag),emitter=SwitchAtAudit(flag,1))
        d,body=self.call();self.assertEqual(d.reason_code,Reason.POLICY_DENIED);self.assertNotIn("data",body)

    def test_parent_audit_commit_failure_releases_no_data(self):
        self.gateway.events=BrokenStore()
        d,body=self.call();self.assertEqual(d.reason_code,Reason.AUDIT_UNAVAILABLE);self.assertNotIn("data",body)
        self.assertEqual(self.call(request("system.health.read"))[0].decision,Outcome.ALLOW)

    def test_failed_delivery_is_not_retried_and_releases_fence(self):
        calls=[]
        def failed(body): calls.append(body);raise ConnectionError()
        self.gateway.handle(request(),self.token,include_data=True,deliver=failed)
        self.assertEqual(len(calls),1)
        self.assertEqual(self.call()[0].decision,Outcome.ALLOW)

    def test_malformed_local_state_quarantined(self):
        self.primary.states[USER_A]=LocalState(0,"unknown")
        d,body=self.call();self.assertEqual(d.reason_code,Reason.EVIDENCE_INVALID);self.assertNotIn("data",body)

    def test_health_independent_of_protected_capacity(self):
        self.gateway=Gateway(self.adapters,self.primary,capacity=1)
        self.assertTrue(self.gateway.slots.acquire(blocking=False))
        try:
            d,body=self.call();self.assertEqual(d.reason_code,Reason.CAPACITY_EXHAUSTED);self.assertNotIn("data",body)
            self.assertEqual(self.call(request("system.health.read"))[0].decision,Outcome.ALLOW)
        finally:self.gateway.slots.release()

    def test_interrupted_adapter_is_reaped_without_late_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=str(Path(tmp)/"late-interrupted")
            self.gateway.adapters=replace(self.adapters,jwt=FaultAdapter(.8,late_write=path))
            receiver,sender=self.gateway.workers.context.Pipe(duplex=False)
            with patch.object(receiver,"poll",side_effect=InterruptedError()), patch.object(
                    self.gateway.workers.context,"Pipe",return_value=(receiver,sender)):
                d,body=self.call()
            self.assertEqual(d.reason_code,Reason.INTERNAL_ERROR);self.assertNotIn("data",body)
            self.assertFalse(self.gateway.workers.active)
            time.sleep(.85);self.assertFalse(Path(path).exists())
            self.gateway.adapters=self.adapters
            self.assertEqual(self.call()[0].decision,Outcome.ALLOW)

    def test_malformed_final_session_evidence_quarantined(self):
        import multiprocessing
        flag=multiprocessing.get_context("spawn").Value("i",0)
        self.gateway.adapters=replace(self.adapters,session=SharedAuthority(flag),emitter=SwitchAtAudit(flag,5))
        d,body=self.call();self.assertEqual(d.reason_code,Reason.EVIDENCE_INVALID);self.assertNotIn("data",body)

if __name__=="__main__":unittest.main(verbosity=2)

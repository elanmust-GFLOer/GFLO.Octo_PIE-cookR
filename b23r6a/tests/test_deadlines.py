"""Deterministic clock-based closure, plus preserved real process regressions."""
import importlib.util
import pickle
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch
from b23r6a.contracts import *
from b23r6a.deadline import Budget
from b23r6a.events import EventStore
from b23r6a.gateway import Gateway
from b23r6a.http_server import Handler,HttpDelivery
from b23r6a.workers import WorkerSupervisor
from b23r6a.adapters.offline import OfflinePrimary,test_token,USER_A
from b23r6a.tests.test_gateway import configured,request

BASE="12e2df4c32ef51d08c799ec63a565c90221e8bcd"
ROOT=Path(__file__).resolve().parents[2]
class Clock:
    def __init__(self):self.now=0.
    def __call__(self):return self.now
    def advance(self,value):self.now+=value

class ScriptedWorkers:
    def __init__(self,clock,steps=None):self.clock,self.steps,self.calls=clock,steps or {},0
    def _step(self,adapter,method,args):
        self.calls+=1;self.clock.advance(self.steps.get(self.calls,0))
        if adapter is None:raise Unavailable()
        return getattr(adapter,method)(*args)
    def run(self,adapter,method,args,deadline):
        from b23r6a.adapter_batches import InitialEvidence,FinalEvidence
        if type(adapter) in (InitialEvidence,FinalEvidence):return adapter.collect(args,self._step)
        return self._step(adapter,method,args)

class DelayedStore(EventStore):
    def __init__(self,clock,phase):super().__init__();self.clock,self.phase=clock,phase
    def summary_before_deadline(self,budget):
        if self.phase=="summary":self.clock.advance(1.001)
        return super().summary_before_deadline(budget)
    def commit_before_deadline(self,event,budget):
        if self.phase=="commit_before":self.clock.advance(1.001)
        super().commit_before_deadline(event,budget)
        if self.phase=="commit_after":self.clock.advance(1.001)

class PreparedDelivery:
    def __init__(self,clock):self.clock=clock;self.protected=[];self.terminal=[]
    def prepare(self,body,budget):
        self.clock.advance(1.001)
        return lambda:self.protected.append(body)
    def __call__(self,body):self.terminal.append(body)

class DeadlineClosure(unittest.TestCase):
    def setUp(self):
        self.clock=Clock();self.key,self.adapters=configured();self.primary=OfflinePrimary()
        self.gateway=Gateway(self.adapters,self.primary,clock=self.clock)
        self.gateway.workers=ScriptedWorkers(self.clock)
        self.token=test_token(self.key)
    def call(self):
        out=[];d=self.gateway.handle(request(),self.token,include_data=True,deliver=out.append)
        return d,out
    def timeout(self):
        d,out=self.call();self.assertEqual(d.decision,Outcome.QUARANTINE)
        self.assertEqual(d.reason_code,Reason.AUTHORITY_TIMEOUT)
        self.assertTrue(all("data" not in b for b in out));return d,out

    def test_exact_1857ms_old_allow_becomes_quarantine(self):
        # Import exact old source; relative imports resolve, workers scripted.
        code=subprocess.check_output(["git","show",BASE+":b23r6a/gateway.py"],cwd=ROOT,text=True)
        module=types.ModuleType("b23r6a._frozen_gateway")
        module.__package__="b23r6a"
        exec(compile(code,"frozen-r6a-gateway.py","exec"),module.__dict__)
        old=module.Gateway(self.adapters,self.primary);old.workers=ScriptedWorkers(self.clock,{7:1.857})
        output=[]
        with patch.object(module.time,"monotonic",self.clock):
            before=old.handle(request(),self.token,include_data=True,deliver=output.append)
        self.assertEqual(before.decision,Outcome.ALLOW);self.assertEqual(self.clock.now,1.857)
        self.assertIn("data",output[0])
        self.clock.now=0.;self.gateway.workers=ScriptedWorkers(self.clock,{7:1.857})
        self.timeout()
        print("DETERMINISTIC 1.857s: frozen R6A ALLOW -> R6A.1 QUARANTINE, zero protected release",flush=True)
    def test_one_second_is_maximum_configuration(self):
        for value in (2,1.001,float('inf'),float('nan'),True,0):
            with self.subTest(value=value),self.assertRaises(ValueError):Gateway(self.adapters,self.primary,timeout=value)
    def test_exact_expiration_during_final_policy(self):
        self.gateway.workers=ScriptedWorkers(self.clock,{7:1.0});self.timeout()
    def test_expiration_during_final_session(self):
        self.gateway.workers=ScriptedWorkers(self.clock,{6:1.001});self.timeout()
    def test_audit_approval_cannot_return_stale_allow(self):
        self.gateway.workers=ScriptedWorkers(self.clock,{5:1.001})
        d,out=self.call();self.assertEqual(d.decision,Outcome.QUARANTINE);self.assertTrue(all('data' not in b for b in out))
    def test_audit_commit_expiration_before_append(self):
        self.gateway.events=DelayedStore(self.clock,"commit_before");self.timeout()
        self.assertFalse(any(e['decision']=='ALLOW' for e in self.gateway.events.snapshot_for_test()))
    def test_audit_commit_returning_late_cannot_release(self):
        self.gateway.events=DelayedStore(self.clock,"commit_after");self.timeout()
    def test_response_summary_expiration_cannot_release(self):
        self.gateway.events=DelayedStore(self.clock,"summary");self.timeout()
    def test_response_dictionary_preparation_is_charged(self):
        original=Decision.as_dict
        def prepare(decision):
            if decision.decision==Outcome.ALLOW:self.clock.advance(1.001)
            return original(decision)
        with patch.object(Decision,"as_dict",prepare):self.timeout()
    def test_transport_preparation_expiration_prevents_initial_release(self):
        sink=PreparedDelivery(self.clock)
        result=self.gateway.handle(request(),self.token,include_data=True,deliver=sink)
        self.assertEqual(result.decision,Outcome.QUARANTINE);self.assertEqual(sink.protected,[])
        self.assertTrue(all("data" not in b for b in sink.terminal))
    def test_no_new_allow_returned_after_slow_consumer(self):
        out=[]
        def consume(body):
            out.append((self.clock(),body))
            if body['decision']=='ALLOW':self.clock.advance(1.001)
        d=self.gateway.handle(request(),self.token,include_data=True,deliver=consume)
        self.assertEqual(d.decision,Outcome.QUARANTINE)
        self.assertTrue(all(at<1 for at,b in out if b['decision']=='ALLOW'))
    def test_generation_fence_wait_is_charged(self):
        original=self.primary.acquire
        def acquire(subject,remaining):
            self.assertLessEqual(remaining,1);held=original(subject,remaining);self.clock.advance(1.001);return held
        with patch.object(self.primary,"acquire",acquire):self.timeout()
        self.assertTrue(self.primary.acquire(USER_A,.01));self.primary.release(USER_A)
    def test_immediately_before_expiration_can_allow(self):
        self.gateway.workers=ScriptedWorkers(self.clock,{7:.999})
        d,out=self.call();self.assertEqual(d.decision,Outcome.ALLOW);self.assertIn('data',out[0])
    def test_cleanup_expiration_cannot_return_new_allow(self):
        original=self.primary.release
        def release(subject):
            original(subject);self.clock.advance(1.001)
        with patch.object(self.primary,"release",release):
            d,out=self.call()
        self.assertEqual(d.decision,Outcome.QUARANTINE)
        self.assertEqual(d.reason_code,Reason.AUTHORITY_TIMEOUT)
        # First delivery was timely; no second response follows cleanup.
        self.assertEqual(len(out),1)
    def test_expiration_after_handoff_never_retries_transport(self):
        out=[]
        def consume(body):
            out.append(body);self.clock.advance(1.001)
        d=self.gateway.handle(request(),self.token,include_data=True,deliver=consume)
        self.assertEqual(d.decision,Outcome.QUARANTINE);self.assertEqual(len(out),1)
    def test_health_remains_independent_after_expiration(self):
        self.gateway.workers=ScriptedWorkers(self.clock,{7:1.857});self.timeout()
        d=self.gateway.handle(request("system.health.read"));self.assertEqual(d.decision,Outcome.ALLOW)
    def test_non_monotonic_clock_fails_closed(self):
        budget=Budget(clock=self.clock);self.clock.now=-1
        with self.assertRaises(ExpiredDeadline):budget.check()
    def test_audit_lock_acquisition_uses_remaining_budget(self):
        store=EventStore();store._lock.acquire();self.gateway.events=store
        self.gateway.workers=ScriptedWorkers(self.clock,{7:.999})
        try:self.timeout()
        finally:store._lock.release()

class FakeHandler:
    def __init__(self,clock,phase=None):
        self.clock,self.phase=clock,phase;self._authorization_budget=Budget(clock=clock)
        self.body_writes=[];self.headers_sent=False;self._headers_buffer=[]
        self.connection=types.SimpleNamespace(settimeout=lambda timeout:None)
        self.wfile=types.SimpleNamespace(write=lambda raw:self.body_writes.append((clock(),raw)),flush=lambda:None)
    def send_response(self,code):pass
    def send_header(self,k,v):
        if self.phase=="headers":self.clock.advance(1.001);self.phase=None
    def end_headers(self):
        self.headers_sent=True
        if self.phase=="after_headers":self.clock.advance(1.001)

class TransportDeadline(unittest.TestCase):
    def body(self):return Decision(Outcome.ALLOW,Reason.READ_AUTHORIZED,'trace','request').as_dict()|{'data':{'protected':True}}
    def test_http_response_serialization_precedes_release_guard(self):
        import b23r6a.http_server as http
        clock=Clock();handler=FakeHandler(clock);original=http.json.dumps
        def serialize(*a,**kw):clock.advance(1.001);return original(*a,**kw)
        with patch.object(http.json,'dumps',serialize),self.assertRaises(ExpiredDeadline):Handler.reply(handler,self.body())
        self.assertFalse(handler.headers_sent);self.assertEqual(handler.body_writes,[])
    def test_http_header_preparation_cannot_release_late(self):
        h=FakeHandler(Clock(),'headers')
        with self.assertRaises(ExpiredDeadline):Handler.reply(h,self.body())
        self.assertFalse(h.headers_sent);self.assertEqual(h.body_writes,[])
    def test_expiration_after_headers_never_writes_protected_body(self):
        from b23r6a.gateway import DeliveryFailed
        h=FakeHandler(Clock(),'after_headers')
        with self.assertRaises(DeliveryFailed):Handler.reply(h,self.body())
        self.assertEqual(h.body_writes,[])
    def test_http_first_application_write_is_guarded(self):
        c=Clock();h=FakeHandler(c);c.now=.999;Handler.reply(h,self.body())
        self.assertTrue(h.headers_sent);self.assertEqual(h.body_writes[0][0],.999)
    def test_unbound_protected_http_delivery_fails_closed(self):
        h=FakeHandler(Clock());h._authorization_budget=None
        with self.assertRaises(ExpiredDeadline):Handler.reply(h,self.body())
        self.assertEqual(h.body_writes,[])

class WorkerBudget(unittest.TestCase):
    def simulate(self,start_delay,cleanup_delay):
        clock=Clock();supervisor=WorkerSupervisor()
        receiver,sender=supervisor.context.Pipe(duplex=False)
        sender.send_bytes(pickle.dumps(('ok',True)))
        class Process:
            pid=321;alive=True
            def start(self):clock.advance(start_delay)
            def is_alive(self):return self.alive
            def terminate(self):self.alive=False
            def kill(self):self.alive=False
            def join(self,timeout):clock.advance(cleanup_delay)
            def close(self):pass
        process=Process()
        with patch.object(supervisor.context,'Pipe',return_value=(receiver,sender)),patch.object(supervisor.context,'Process',return_value=process),patch('b23r6a.workers.time.monotonic',clock):
            with self.assertRaises(ExpiredDeadline):supervisor.run(object(),'verify',(),1.)
        self.assertFalse(process.alive);self.assertFalse(supervisor.active)
    def test_process_startup_is_in_stage_budget(self):self.simulate(.401,0)
    def test_reaping_cannot_return_a_stale_result(self):self.simulate(0,1.001)

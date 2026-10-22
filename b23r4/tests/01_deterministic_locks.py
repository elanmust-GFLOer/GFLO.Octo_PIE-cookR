#!/usr/bin/env python3
"""Deterministic PostgreSQL blocking-observation tests on disposable B2.3-R3 simulator."""
import os,uuid,time,unittest
from threading import Event,Thread
import psycopg
from psycopg import errors
assert os.environ.get("PGHOST")=="127.0.0.1" and os.environ.get("PGDATABASE")=="b2test_r4_transition"
D=bytes.fromhex("ac"*32)
def db():
 c=psycopg.connect(autocommit=True,connect_timeout=4)
 c.execute("SET lock_timeout='8s'")
 c.execute("SET statement_timeout='12s'")
 return c
def fixture():
 u,s,b=uuid.uuid4(),uuid.uuid4(),uuid.uuid4()
 with db() as c:
  c.execute("INSERT INTO private.wallet_binding_state(user_id,chain_id,binding_status) VALUES(%s,1,'active')",(u,))
  c.execute("INSERT INTO b23_auth_sim.sessions(session_id,user_id) VALUES(%s,%s)",(s,u))
  c.execute("INSERT INTO private.wallet_bindings(binding_id,user_id,chain_id,wallet_address,epoch,consent_version,consent_digest,scopes) VALUES(%s,%s,1,%s,0,'R4',%s,ARRAY['bind:wallet'])",
            (b,u,uuid.uuid4().bytes+uuid.uuid4().bytes[:4],D))
 return u,s,b
def observe_wait(pid,blocker):
 end=time.monotonic()+4
 with db() as c:
  while time.monotonic()<end:
   ids=c.execute("SELECT pg_blocking_pids(%s)",(pid,)).fetchone()[0]
   if blocker in ids:return
   time.sleep(.035)
 raise AssertionError("No observed SQL lock wait against expected blocking PID")
class R4Locks(unittest.TestCase):
 def test_revoke_first_update_blocks_mutation(self):
  u,s,b=fixture();r=uuid.uuid4(); started=Event();ready=Event(); release=Event();error=[]
  with db() as a, db() as q:
   with a.transaction():
    blocker=a.execute("SELECT pg_backend_pid()").fetchone()[0]
    a.execute("UPDATE b23_auth_sim.sessions SET revoked_at=clock_timestamp() WHERE session_id=%s",(s,))
    def work():
     try:
      with db() as c:
       pid=c.execute("SELECT pg_backend_pid()").fetchone()[0]
       ready.pid=pid;ready.set()
       with self.assertRaises(errors.InsufficientPrivilege):
        c.execute("SELECT private.b23r3_suspend_lab(%s,%s,1,%s,0,%s,%s)",(u,s,b,r,D))
     except BaseException as e:error.append(e)
    t=Thread(target=work);t.start();self.assertTrue(ready.wait(3))
    try:observe_wait(ready.pid,blocker)
    finally:
     # Exit this transaction only after the contender is confirmed blocked.
     pass
   t.join(5);self.assertFalse(t.is_alive());self.assertFalse(error,error)
   self.assertEqual(q.execute("SELECT status::text FROM private.wallet_bindings WHERE binding_id=%s",(b,)).fetchone()[0],"active")
   self.assertEqual(q.execute("SELECT count(*) FROM private.wallet_binding_audit WHERE request_id=%s",(r,)).fetchone()[0],0)
 def test_mutation_first_blocks_revoke(self):
  u,s,b=fixture();r=uuid.uuid4();ready=Event();error=[]
  with db() as a,db() as q:
   with a.transaction():
    blocker=a.execute("SELECT pg_backend_pid()").fetchone()[0]
    self.assertEqual(a.execute("SELECT private.b23r3_suspend_lab(%s,%s,1,%s,0,%s,%s)",(u,s,b,r,D)).fetchone()[0],"suspended")
    def work():
     try:
      with db() as c:
       ready.pid=c.execute("SELECT pg_backend_pid()").fetchone()[0];ready.set()
       c.execute("UPDATE b23_auth_sim.sessions SET revoked_at=clock_timestamp() WHERE session_id=%s",(s,))
     except BaseException as e:error.append(e)
    t=Thread(target=work);t.start();self.assertTrue(ready.wait(3))
    observe_wait(ready.pid,blocker)
   t.join(5);self.assertFalse(t.is_alive());self.assertFalse(error,error)
   self.assertEqual(q.execute("SELECT count(*) FROM private.wallet_binding_audit WHERE request_id=%s",(r,)).fetchone()[0],1)
   self.assertEqual(q.execute("SELECT epoch FROM private.wallet_binding_state WHERE user_id=%s",(u,)).fetchone()[0],1)
 def test_controller_lock_blocks_challenge_issue(self):
  u,s=uuid.uuid4(),uuid.uuid4();ready=Event();error=[]
  with db() as a,db() as q:
   a.execute("INSERT INTO private.wallet_binding_state(user_id,chain_id,binding_status) VALUES(%s,1,'unbound')",(u,))
   with a.transaction():
    blocker=a.execute("SELECT pg_backend_pid()").fetchone()[0]
    a.execute("UPDATE private.wallet_binding_state SET binding_status='suspended',epoch=epoch+1 WHERE user_id=%s",(u,))
    def work():
     try:
      with db() as c:
       ready.pid=c.execute("SELECT pg_backend_pid()").fetchone()[0];ready.set()
       with self.assertRaises(errors.InsufficientPrivilege):
        c.execute("SELECT private.b23r1_issue_challenge(%s,1,%s,%s,%s,%s,%s)",
                  (u,bytes.fromhex("23"*20),uuid.uuid4().bytes+uuid.uuid4().bytes,s,D,D))
     except BaseException as e:error.append(e)
    t=Thread(target=work);t.start();self.assertTrue(ready.wait(3))
    observe_wait(ready.pid,blocker)
   t.join(5);self.assertFalse(t.is_alive());self.assertFalse(error,error)
   self.assertEqual(q.execute("SELECT count(*) FROM private.wallet_binding_challenges WHERE user_id=%s AND status='pending'",(u,)).fetchone()[0],0)
if __name__=="__main__":unittest.main(verbosity=2)

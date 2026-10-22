#!/usr/bin/env python3
"""B2.3-R3 disposable role/audit transaction tests. No production credentials."""
import os,uuid,unittest
import psycopg
from psycopg import errors
assert os.getenv("PGDATABASE","").startswith("b2test_")
assert os.getenv("B23_DISPOSABLE_ACK")=="YES"
assert os.getenv("PGHOST") in ("localhost","127.0.0.1")
digest=bytes.fromhex("bc"*32)
def db():
 c=psycopg.connect(autocommit=True)
 c.execute("SET statement_timeout='12s'")
 return c
def fixture():
 u,s,b=uuid.uuid4(),uuid.uuid4(),uuid.uuid4()
 with db() as c:
  c.execute("INSERT INTO private.wallet_binding_state(user_id,chain_id,binding_status) VALUES(%s,1,'active')",(u,))
  c.execute("INSERT INTO b23_auth_sim.sessions(session_id,user_id) VALUES(%s,%s)",(s,u))
  c.execute("""INSERT INTO private.wallet_bindings(binding_id,user_id,chain_id,wallet_address,epoch,consent_version,consent_digest,scopes)
   VALUES(%s,%s,1,%s,0,'R3',%s,ARRAY['bind:wallet'])""",
   (b,u,uuid.uuid4().bytes+uuid.uuid4().bytes[:4],digest))
 return u,s,b
CALL="SELECT private.b23r3_suspend_lab(%s,%s,1,%s,0,%s,%s)"
def mutation(u,s,b,r,p=digest,role=True):
 with db() as c:
  if role:c.execute("SET ROLE b23r3_lab_caller")
  return c.execute(CALL,(u,s,b,r,p)).fetchone()[0]
class R3(unittest.TestCase):
 def test_01_exact_audit_and_epoch(self):
  u,s,b=fixture();r=uuid.uuid4()
  self.assertEqual(mutation(u,s,b,r),"suspended")
  with db() as c:
   self.assertEqual(c.execute("SELECT status::text FROM private.wallet_bindings WHERE binding_id=%s",(b,)).fetchone()[0],"suspended")
   self.assertEqual(c.execute("SELECT epoch FROM private.wallet_binding_state WHERE user_id=%s",(u,)).fetchone()[0],1)
   self.assertEqual(c.execute("SELECT count(*) FROM private.wallet_binding_audit WHERE request_id=%s",(r,)).fetchone()[0],1)
   self.assertEqual(c.execute("SELECT count(*) FROM private.b23r3_requests WHERE request_id=%s",(r,)).fetchone()[0],1)
 def test_02_retry_and_payload_mismatch(self):
  u,s,b=fixture();r=uuid.uuid4()
  self.assertEqual(mutation(u,s,b,r),"suspended")
  self.assertEqual(mutation(u,s,b,r),"suspended")
  with self.assertRaises(errors.UniqueViolation):mutation(u,s,b,r,bytes.fromhex("aa"*32))
  with db() as c:
   self.assertEqual(c.execute("SELECT count(*) FROM private.wallet_binding_audit WHERE request_id=%s",(r,)).fetchone()[0],1)
   self.assertEqual(c.execute("SELECT epoch FROM private.wallet_binding_state WHERE user_id=%s",(u,)).fetchone()[0],1)
 def test_03_direct_dml_denied(self):
  u,s,b=fixture()
  for role in ["b23_runtime","b23r3_lab_caller","b23_untrusted"]:
   with self.subTest(role=role):
    with db() as c:
     c.execute("SET ROLE "+role)
     with self.assertRaises(errors.InsufficientPrivilege):
      c.execute("UPDATE private.wallet_bindings SET status='suspended' WHERE binding_id=%s",(b,))
 def test_04_lab_caller_cannot_enumerate_sessions(self):
  with db() as c:
   c.execute("SET ROLE b23r3_lab_caller")
   with self.assertRaises(errors.InsufficientPrivilege):c.execute("SELECT * FROM b23_auth_sim.sessions")
 def test_05_trusted_prototype_not_browser_callable(self):
  with db() as c:
   for role in ["b23_runtime","b23_untrusted"]:
    self.assertFalse(c.execute("SELECT has_function_privilege(%s,'private.b23r3_suspend_lab(uuid,uuid,bigint,uuid,bigint,uuid,bytea)','EXECUTE')",(role,)).fetchone()[0])
 def test_06_audit_failure_rolls_back(self):
  u,s,b=fixture();r=uuid.uuid4()
  with db() as c:
   c.execute("""CREATE FUNCTION private.r3_forced_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$
       BEGIN IF NEW.request_id=current_setting('gflo.test_forced_request',true)::uuid
       THEN RAISE EXCEPTION 'simulated audit storage failure'; END IF; RETURN NEW; END $$""")
   c.execute("CREATE TRIGGER r3_forced_failure BEFORE INSERT ON private.wallet_binding_audit FOR EACH ROW EXECUTE FUNCTION private.r3_forced_audit_failure()")
   try:
    with self.assertRaises(psycopg.Error):
     with c.transaction():
      c.execute("SELECT set_config('gflo.test_forced_request',%s,true)",(str(r),))
      c.execute(CALL,(u,s,b,r,digest))
   finally:
    c.execute("DROP TRIGGER r3_forced_failure ON private.wallet_binding_audit")
    c.execute("DROP FUNCTION private.r3_forced_audit_failure()")
   self.assertEqual(c.execute("SELECT epoch FROM private.wallet_binding_state WHERE user_id=%s",(u,)).fetchone()[0],0)
   self.assertEqual(c.execute("SELECT status::text FROM private.wallet_bindings WHERE binding_id=%s",(b,)).fetchone()[0],"active")
   self.assertEqual(c.execute("SELECT count(*) FROM private.wallet_binding_audit WHERE request_id=%s",(r,)).fetchone()[0],0)
   self.assertEqual(c.execute("SELECT count(*) FROM private.b23r3_requests WHERE request_id=%s",(r,)).fetchone()[0],0)
if __name__=="__main__":unittest.main(verbosity=2)

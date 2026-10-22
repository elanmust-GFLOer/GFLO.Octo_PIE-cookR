#!/usr/bin/env python3
"""R5 isolated PostgreSQL transaction race + lifecycle negatives, not real Supabase Auth."""
import os, uuid, time, unittest
from threading import Event, Thread
import psycopg
from psycopg import errors

if (os.getenv("PGHOST") != "127.0.0.1" or os.getenv("PGDATABASE") != "b2test_r5_transition"
        or os.getenv("B23_DISPOSABLE_ACK") != "YES"):
    raise SystemExit("R5 tests require acknowledged disposable localhost database")

D = bytes.fromhex("ac" * 32)
CALL = "SELECT private.b23r3_suspend_lab(%s,%s,1,%s,0,%s,%s)"

def conn():
    c = psycopg.connect(autocommit=True, connect_timeout=4)
    c.execute("SET lock_timeout='8s'")
    c.execute("SET statement_timeout='12s'")
    return c

def fixture(with_challenge=False):
    u, s, b = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    with conn() as c:
        c.execute("INSERT INTO private.wallet_binding_state(user_id,chain_id,binding_status) VALUES(%s,1,'active')", (u,))
        c.execute("INSERT INTO b23_auth_sim.sessions(session_id,user_id) VALUES(%s,%s)", (s,u))
        c.execute("""INSERT INTO private.wallet_bindings
        (binding_id,user_id,chain_id,wallet_address,epoch,consent_version,consent_digest,scopes)
        VALUES (%s,%s,1,%s,0,'R5',%s,ARRAY['bind:wallet'])""",
                  (b,u,uuid.uuid4().bytes+uuid.uuid4().bytes[:4],D))
        if with_challenge:
            c.execute("""INSERT INTO private.wallet_binding_challenges
            (user_id,chain_id,wallet_address,nonce_hash,epoch,auth_session_id,auth_generation,
            domain,uri,siwe_message_digest,consent_digest,consent_version,scopes,expires_at)
            VALUES(%s,1,%s,%s,0,%s,0,'example.test','https://example.test',%s,%s,
            'R5',ARRAY['bind:wallet'],clock_timestamp()+interval '4 minutes')""",
            (u,bytes.fromhex("31"*20),uuid.uuid4().bytes+uuid.uuid4().bytes,s,D,D))
    return u,s,b

def observe_block(waiter, blocker):
    deadline = time.monotonic() + 5
    with conn() as obs:
        while time.monotonic() < deadline:
            if blocker in obs.execute("SELECT pg_blocking_pids(%s)", (waiter,)).fetchone()[0]:
                return
            time.sleep(.025)
    raise AssertionError("Expected blocker PID not observed before releasing first transaction")

def launch(statement, parameters):
    """Contender runs on a distinct PostgreSQL connection; main caller holds lock."""
    ready = Event()
    results = {}
    def worker():
        try:
            with conn() as c:
                results["pid"] = c.execute("SELECT pg_backend_pid()").fetchone()[0]
                ready.set()
                try:
                    results["value"] = c.execute(statement, parameters).fetchone()
                except psycopg.Error as ex:
                    results["error"] = ex.sqlstate
        except BaseException as ex:
            results["unexpected"] = repr(ex)
            ready.set()
    t = Thread(target=worker, daemon=True)
    t.start()
    if not ready.wait(3):
        raise AssertionError("Contender never acquired a connection")
    if "unexpected" in results:
        raise AssertionError(results["unexpected"])
    return t, results

def complete(testcase, thread, result):
    thread.join(timeout=7)
    testcase.assertFalse(thread.is_alive(), "contender failed to finish")
    testcase.assertNotIn("unexpected", result, result.get("unexpected"))

class R5Additional(unittest.TestCase):
    def test_01_delete_first_blocked_mutation_denied(self):
        u,s,b = fixture(); req=uuid.uuid4()
        with conn() as a:
            with a.transaction():
                blocker=a.execute("SELECT pg_backend_pid()").fetchone()[0]
                a.execute("DELETE FROM b23_auth_sim.sessions WHERE session_id=%s",(s,))
                t,res=launch(CALL,(u,s,b,req,D))
                observe_block(res["pid"],blocker)
            complete(self,t,res)
            self.assertEqual(res.get("error"),"42501",res)
            self.assertEqual(a.execute("SELECT status::text FROM private.wallet_bindings WHERE binding_id=%s",(b,)).fetchone()[0],"active")
            self.assertEqual(a.execute("SELECT count(*) FROM private.wallet_binding_audit WHERE request_id=%s",(req,)).fetchone()[0],0)

    def test_02_mutation_rollback_blocks_session_delete(self):
        u,s,b=fixture();req=uuid.uuid4()
        with conn() as a:
            try:
                with a.transaction():
                    blocker=a.execute("SELECT pg_backend_pid()").fetchone()[0]
                    self.assertEqual(a.execute(CALL,(u,s,b,req,D)).fetchone()[0],"suspended")
                    t,res=launch("DELETE FROM b23_auth_sim.sessions WHERE session_id=%s RETURNING session_id",(s,))
                    observe_block(res["pid"],blocker)
                    raise RuntimeError("rollback intentional after observed wait")
            except RuntimeError as ex:
                self.assertIn("intentional",str(ex))
            complete(self,t,res)
            self.assertEqual(res.get("value"),(s,),res)
            self.assertEqual(a.execute("SELECT status::text FROM private.wallet_bindings WHERE binding_id=%s",(b,)).fetchone()[0],"active")
            self.assertEqual(a.execute("SELECT epoch FROM private.wallet_binding_state WHERE user_id=%s",(u,)).fetchone()[0],0)
            self.assertEqual(a.execute("SELECT count(*) FROM private.wallet_binding_audit WHERE request_id=%s",(req,)).fetchone()[0],0)
            self.assertEqual(a.execute("SELECT count(*) FROM private.b23r3_requests WHERE request_id=%s",(req,)).fetchone()[0],0)

    def test_03_two_identical_requests_one_audit(self):
        u,s,b=fixture();req=uuid.uuid4()
        with conn() as a:
            with a.transaction():
                blocker=a.execute("SELECT pg_backend_pid()").fetchone()[0]
                self.assertEqual(a.execute(CALL,(u,s,b,req,D)).fetchone()[0],"suspended")
                t,res=launch(CALL,(u,s,b,req,D))
                observe_block(res["pid"],blocker)
            complete(self,t,res)
            self.assertEqual(res.get("value"),("suspended",),res)
            self.assertEqual(a.execute("SELECT count(*) FROM private.wallet_binding_audit WHERE request_id=%s",(req,)).fetchone()[0],1)
            self.assertEqual(a.execute("SELECT count(*) FROM private.b23r3_requests WHERE request_id=%s",(req,)).fetchone()[0],1)
            self.assertEqual(a.execute("SELECT epoch FROM private.wallet_binding_state WHERE user_id=%s",(u,)).fetchone()[0],1)

    def test_04_conflicting_payload_same_request_refused(self):
        u,s,b=fixture();req=uuid.uuid4();bad=bytes.fromhex("ee"*32)
        with conn() as a:
            with a.transaction():
                blocker=a.execute("SELECT pg_backend_pid()").fetchone()[0]
                self.assertEqual(a.execute(CALL,(u,s,b,req,D)).fetchone()[0],"suspended")
                t,res=launch(CALL,(u,s,b,req,bad))
                observe_block(res["pid"],blocker)
            complete(self,t,res)
            self.assertEqual(res.get("error"),"23505",res)
            self.assertEqual(a.execute("SELECT count(*) FROM private.wallet_binding_audit WHERE request_id=%s",(req,)).fetchone()[0],1)

    def test_05_stale_epoch_and_wrong_binding_refused(self):
        u,s,b=fixture()
        with conn() as a:
            for statement, params in [
                ("SELECT private.b23r3_suspend_lab(%s,%s,1,%s,5,%s,%s)",(u,s,b,uuid.uuid4(),D)),
                (CALL,(u,s,uuid.uuid4(),uuid.uuid4(),D))
            ]:
                with self.assertRaises(errors.CheckViolation):
                    a.execute(statement,params)
            self.assertEqual(a.execute("SELECT count(*) FROM private.wallet_binding_audit WHERE actor_ref=%s",(str(u),)).fetchone()[0],0)
            self.assertEqual(a.execute("SELECT epoch FROM private.wallet_binding_state WHERE user_id=%s",(u,)).fetchone()[0],0)

    def test_06_audit_specific_failure_restores_pending(self):
        u,s,b=fixture(with_challenge=True);req=uuid.uuid4()
        with conn() as c:
            c.execute("""CREATE FUNCTION private.r5_audit_inject_failure() RETURNS trigger LANGUAGE plpgsql AS $fn$
            BEGIN
                IF NEW.request_id::text = current_setting('gflo.r5_fault_id',true)
                THEN RAISE EXCEPTION 'R5_AUDIT_WRITE_INJECTED' USING ERRCODE='P0001'; END IF;
                RETURN NEW;
            END $fn$""")
            c.execute("""CREATE TRIGGER r5_audit_inject BEFORE INSERT ON private.wallet_binding_audit
                        FOR EACH ROW EXECUTE FUNCTION private.r5_audit_inject_failure()""")
            try:
                with self.assertRaises(errors.RaiseException) as caught:
                    with c.transaction():
                        c.execute("SELECT set_config('gflo.r5_fault_id',%s,true)",(str(req),))
                        c.execute(CALL,(u,s,b,req,D))
                self.assertEqual(caught.exception.diag.message_primary,"R5_AUDIT_WRITE_INJECTED")
            finally:
                c.execute("DROP TRIGGER r5_audit_inject ON private.wallet_binding_audit")
                c.execute("DROP FUNCTION private.r5_audit_inject_failure()")
            self.assertEqual(c.execute("SELECT status::text FROM private.wallet_bindings WHERE binding_id=%s",(b,)).fetchone()[0],"active")
            self.assertEqual(c.execute("SELECT epoch FROM private.wallet_binding_state WHERE user_id=%s",(u,)).fetchone()[0],0)
            self.assertEqual(c.execute("SELECT status::text FROM private.wallet_binding_challenges WHERE user_id=%s",(u,)).fetchone()[0],"pending")
            self.assertEqual(c.execute("SELECT count(*) FROM private.wallet_binding_audit WHERE request_id=%s",(req,)).fetchone()[0],0)
            self.assertEqual(c.execute("SELECT count(*) FROM private.b23r3_requests WHERE request_id=%s",(req,)).fetchone()[0],0)

if __name__ == "__main__":
    unittest.main(verbosity=2)

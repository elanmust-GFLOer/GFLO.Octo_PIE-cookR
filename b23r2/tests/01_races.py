#!/usr/bin/env python3
"""B2.3-R2: independent-connection PostgreSQL 16 laboratory races; not Supabase Auth."""
import os, uuid, unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Event
import psycopg
from psycopg import errors
assert os.getenv("PGDATABASE","").startswith("b2test_")
assert os.getenv("B23_DISPOSABLE_ACK")=="YES"
assert os.getenv("PGHOST") in ("127.0.0.1","localhost")
D=bytes.fromhex("ab"*32)
W=bytes.fromhex("12"*20)
def con():
    c=psycopg.connect(autocommit=True,connect_timeout=5)
    c.execute("SET lock_timeout='6s'")
    c.execute("SET statement_timeout='12s'")
    return c
def fixture():
    u,s=uuid.uuid4(),uuid.uuid4()
    with con() as c:
        c.execute("INSERT INTO private.wallet_binding_state(user_id,chain_id,binding_status) VALUES(%s,1,'active')",(u,))
        c.execute("INSERT INTO b23_auth_sim.sessions(session_id,user_id) VALUES(%s,%s)",(s,u))
        c.execute("""INSERT INTO private.wallet_bindings(binding_id,user_id,chain_id,wallet_address,epoch,consent_version,consent_digest,scopes)
        VALUES(%s,%s,1,%s,0,'R2',%s,ARRAY['bind:wallet'])""",(uuid.uuid4(),u,uuid.uuid4().bytes+uuid.uuid4().bytes[:4],D))
    return u,s
def audit(c,u):
    return c.execute("SELECT count(*) FROM private.wallet_binding_audit WHERE actor_ref=%s AND event_type='BINDING_SUSPENDED'",(str(u),)).fetchone()[0]
class R2(unittest.TestCase):
    def test_revoke_first_update(self):
        u,s=fixture(); locked=Event();release=Event()
        def revoke():
            with con() as c:
                with c.transaction():
                    c.execute("UPDATE b23_auth_sim.sessions SET revoked_at=clock_timestamp() WHERE session_id=%s",(s,))
                    locked.set()
                    if not release.wait(4):raise AssertionError("release absent")
        def suspend():
            if not locked.wait(4):raise AssertionError("revoke absent")
            with con() as c:
                with self.assertRaises(errors.InsufficientPrivilege):
                    c.execute("SELECT private.b23_suspend(%s,%s,1,%s)",(u,s,uuid.uuid4()))
        with ThreadPoolExecutor(max_workers=2) as ex:
            a=ex.submit(revoke)
            self.assertTrue(locked.wait(4))
            b=ex.submit(suspend)
            release.set();a.result(timeout=8);b.result(timeout=8)
        with con() as c:
            self.assertEqual(c.execute("SELECT status::text FROM private.wallet_bindings WHERE user_id=%s",(u,)).fetchone()[0],"active")
            self.assertEqual(audit(c,u),0)
    def test_revoke_first_delete(self):
        u,s=fixture();locked=Event();release=Event()
        def revoke():
            with con() as c:
                with c.transaction():
                    c.execute("DELETE FROM b23_auth_sim.sessions WHERE session_id=%s",(s,))
                    locked.set()
                    if not release.wait(4):raise AssertionError("no release")
        def suspend():
            if not locked.wait(4):raise AssertionError("no revoke")
            with con() as c:
                with self.assertRaises(errors.InsufficientPrivilege):
                    c.execute("SELECT private.b23_suspend(%s,%s,1,%s)",(u,s,uuid.uuid4()))
        with ThreadPoolExecutor(max_workers=2) as ex:
            a=ex.submit(revoke);b=ex.submit(suspend)
            self.assertTrue(locked.wait(4));release.set()
            a.result(timeout=8);b.result(timeout=8)
        with con() as c:
            self.assertEqual(audit(c,u),0)
            self.assertEqual(c.execute("SELECT status::text FROM private.wallet_bindings WHERE user_id=%s",(u,)).fetchone()[0],"active")
    def test_mutation_first_then_revoke(self):
        u,s=fixture();locked=Event();release=Event()
        def suspend():
            with con() as c:
                with c.transaction():
                    result=c.execute("SELECT private.b23_suspend(%s,%s,1,%s)",(u,s,uuid.uuid4())).fetchone()[0]
                    self.assertEqual(result,"suspended")
                    locked.set()
                    if not release.wait(4):raise AssertionError("no release")
        def revoke():
            if not locked.wait(4):raise AssertionError("no mutation")
            with con() as c:
                c.execute("UPDATE b23_auth_sim.sessions SET revoked_at=clock_timestamp() WHERE session_id=%s",(s,))
        with ThreadPoolExecutor(max_workers=2) as ex:
            a=ex.submit(suspend);self.assertTrue(locked.wait(4))
            b=ex.submit(revoke);release.set()
            a.result(timeout=8);b.result(timeout=8)
        with con() as c:
            self.assertEqual(audit(c,u),1)
            self.assertEqual(c.execute("SELECT epoch FROM private.wallet_binding_state WHERE user_id=%s",(u,)).fetchone()[0],1)
    def test_mutation_rollback_then_revoke(self):
        u,s=fixture();locked=Event();release=Event()
        def suspend_rollback():
            with con() as c:
                try:
                    with c.transaction():
                        c.execute("SELECT private.b23_suspend(%s,%s,1,%s)",(u,s,uuid.uuid4()))
                        locked.set()
                        if not release.wait(4):raise AssertionError("no release")
                        raise RuntimeError("forced rollback")
                except RuntimeError:pass
        def revoke():
            if not locked.wait(4):raise AssertionError("no mutation")
            with con() as c:
                c.execute("UPDATE b23_auth_sim.sessions SET revoked_at=clock_timestamp() WHERE session_id=%s",(s,))
        with ThreadPoolExecutor(max_workers=2) as ex:
            a=ex.submit(suspend_rollback);self.assertTrue(locked.wait(4))
            b=ex.submit(revoke);release.set()
            a.result(timeout=8);b.result(timeout=8)
        with con() as c:
            self.assertEqual(audit(c,u),0)
            self.assertEqual(c.execute("SELECT epoch FROM private.wallet_binding_state WHERE user_id=%s",(u,)).fetchone()[0],0)
    def test_missing_session_fails_closed(self):
        u,s=fixture()
        with con() as c:
            c.execute("DELETE FROM b23_auth_sim.sessions WHERE session_id=%s",(s,))
            with self.assertRaises(errors.InsufficientPrivilege):
                c.execute("SELECT private.b23_suspend(%s,%s,1,%s)",(u,s,uuid.uuid4()))
            self.assertEqual(audit(c,u),0)
    def test_suspended_issue_rejected(self):
        u,s=uuid.uuid4(),uuid.uuid4()
        with con() as c:
            c.execute("INSERT INTO private.wallet_binding_state(user_id,chain_id,binding_status) VALUES(%s,1,'suspended')",(u,))
            with self.assertRaises(errors.InsufficientPrivilege):
                c.execute("""SELECT private.b23r1_issue_challenge(%s,1,%s,%s,%s,%s,%s)""",(u,W,uuid.uuid4().bytes+uuid.uuid4().bytes,s,D,D))
            self.assertEqual(c.execute("SELECT count(*) FROM private.wallet_binding_challenges WHERE user_id=%s AND status='pending'",(u,)).fetchone()[0],0)
    def test_issue_lock_race_then_suspend_state(self):
        # R1 lab issuer checks 'unbound'. Same controller lock prevents issuing after a concurrent transition.
        u,s=uuid.uuid4(),uuid.uuid4()
        with con() as c:
            c.execute("INSERT INTO private.wallet_binding_state(user_id,chain_id,binding_status) VALUES(%s,1,'unbound')",(u,))
        held=Event();release=Event()
        def transition():
            with con() as c:
                with c.transaction():
                    c.execute("UPDATE private.wallet_binding_state SET binding_status='suspended',epoch=epoch+1 WHERE user_id=%s",(u,))
                    held.set()
                    if not release.wait(4):raise AssertionError("release absent")
        def issue():
            if not held.wait(4):raise AssertionError("transition absent")
            with con() as c:
                with self.assertRaises(errors.InsufficientPrivilege):
                    c.execute("SELECT private.b23r1_issue_challenge(%s,1,%s,%s,%s,%s,%s)",
                    (u,W,uuid.uuid4().bytes+uuid.uuid4().bytes,s,D,D))
        with ThreadPoolExecutor(max_workers=2) as ex:
            a=ex.submit(transition);self.assertTrue(held.wait(4))
            b=ex.submit(issue);release.set();a.result(timeout=8);b.result(timeout=8)
        with con() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM private.wallet_binding_challenges WHERE user_id=%s AND status='pending'",(u,)).fetchone()[0],0)
if __name__=="__main__":unittest.main(verbosity=2)

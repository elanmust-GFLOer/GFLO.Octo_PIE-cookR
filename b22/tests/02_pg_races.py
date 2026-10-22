#!/usr/bin/env python3
"""Disposable B2.2 SQL protocol experiments. Not an Auth/crypto/production security test."""
import os, uuid, time, unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Event
import psycopg
from psycopg import errors
if not os.getenv("PGDATABASE","").startswith("b2test_") or os.getenv("B22_DISPOSABLE_ACK")!="YES":
    raise SystemExit("Refusing non-disposable database")
if os.getenv("PGHOST") not in ("127.0.0.1","localhost","/var/run/postgresql"):
    raise SystemExit("Refusing remote database")
DIGEST=bytes.fromhex("ab"*32)
def connect():
    c=psycopg.connect(autocommit=True,connect_timeout=4)
    c.execute("SET lock_timeout='4s'")
    c.execute("SET statement_timeout='10s'")
    return c
def controller(c,u):
    c.execute("INSERT INTO private.wallet_binding_state(user_id,chain_id) VALUES(%s,1)",(u,))
def binding(c,u,w):
    c.execute("""INSERT INTO private.wallet_bindings(binding_id,user_id,chain_id,wallet_address,epoch,consent_version,consent_digest,scopes)
       VALUES(%s,%s,1,%s,0,'B2.2',%s,ARRAY['bind:wallet'])""",(uuid.uuid4(),u,w,DIGEST))
def challenge(c,u):
    cid=uuid.uuid4()
    c.execute("""INSERT INTO private.wallet_binding_challenges
     (challenge_id,user_id,chain_id,wallet_address,nonce_hash,epoch,auth_session_id,auth_generation,domain,uri,siwe_message_digest,consent_digest,consent_version,scopes,expires_at)
     VALUES(%s,%s,1,%s,%s,0,%s,0,'example.test','https://example.test',%s,%s,'B2.2',ARRAY['bind:wallet'],clock_timestamp()+interval '4 minutes')""",
      (cid,u,bytes.fromhex("11"*20),uuid.uuid4().bytes+uuid.uuid4().bytes,uuid.uuid4(),DIGEST,DIGEST))
    return cid
class B22(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with connect() as c:
            v=int(c.execute("SHOW server_version_num").fetchone()[0])
            assert v//10000==16,f"expected PG16 got {v}"
    def test_01_wallet_race(self):
        u1,u2=uuid.uuid4(),uuid.uuid4();w=uuid.uuid4().bytes+uuid.uuid4().bytes[:4]
        with connect() as c:controller(c,u1);controller(c,u2)
        started,second_attempt=Event(),Event()
        def first():
            with connect() as c:
                with c.transaction():
                    binding(c,u1,w);started.set()
                    if not second_attempt.wait(3):raise AssertionError("second participant missing")
                    time.sleep(.3)
            return "committed"
        def second():
            if not started.wait(3):raise AssertionError("first participant missing")
            with connect() as c:
                try:
                    with c.transaction():
                        second_attempt.set();binding(c,u2,w)
                    return "unexpected-success"
                except errors.UniqueViolation:return "unique-violation"
        with ThreadPoolExecutor(max_workers=2) as pool:
            a=pool.submit(first);b=pool.submit(second)
            self.assertEqual(a.result(timeout=9),"committed")
            self.assertEqual(b.result(timeout=9),"unique-violation")
        with connect() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM private.wallet_bindings WHERE wallet_address=%s",(w,)).fetchone()[0],1)
    def test_02_challenge_race(self):
        u=uuid.uuid4()
        with connect() as c:controller(c,u)
        started,second_attempt=Event(),Event()
        def first():
            with connect() as c:
                with c.transaction():
                    challenge(c,u);started.set()
                    if not second_attempt.wait(3):raise AssertionError("second participant missing")
                    time.sleep(.3)
            return "committed"
        def second():
            if not started.wait(3):raise AssertionError("first participant missing")
            with connect() as c:
                try:
                    with c.transaction():second_attempt.set();challenge(c,u)
                    return "unexpected-success"
                except errors.UniqueViolation:return "unique-violation"
        with ThreadPoolExecutor(max_workers=2) as pool:
            a=pool.submit(first);b=pool.submit(second)
            self.assertEqual(a.result(timeout=9),"committed")
            self.assertEqual(b.result(timeout=9),"unique-violation")
    def test_03_consume_once(self):
        u=uuid.uuid4()
        with connect() as c:
            controller(c,u);cid=challenge(c,u)
            statement="UPDATE private.wallet_binding_challenges SET status='consumed',consumed_at=clock_timestamp() WHERE challenge_id=%s AND status='pending' RETURNING challenge_id"
            self.assertIsNotNone(c.execute(statement,(cid,)).fetchone())
            self.assertIsNone(c.execute(statement,(cid,)).fetchone())
    def test_04_rollback(self):
        u=uuid.uuid4();w=uuid.uuid4().bytes+uuid.uuid4().bytes[:4]
        with connect() as c:
            controller(c,u)
            with self.assertRaisesRegex(RuntimeError,"simulated crash"):
                with c.transaction():
                    binding(c,u,w)
                    raise RuntimeError("simulated crash")
            self.assertEqual(c.execute("SELECT count(*) FROM private.wallet_bindings WHERE user_id=%s",(u,)).fetchone()[0],0)
    def test_05_unprivileged_read_denied(self):
        with connect() as c:
            c.execute("DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='b2test_browser') THEN CREATE ROLE b2test_browser NOLOGIN; END IF; END$$")
            with self.assertRaises(errors.InsufficientPrivilege):
                with c.transaction():
                    c.execute("SET LOCAL ROLE b2test_browser")
                    c.execute("SELECT * FROM private.wallet_bindings LIMIT 1")
    def test_06_known_audit_gap_is_exposed(self):
        u=uuid.uuid4();w=uuid.uuid4().bytes+uuid.uuid4().bytes[:4]
        with connect() as c:
            controller(c,u);binding(c,u,w)
            prior=c.execute("SELECT count(*) FROM private.wallet_binding_audit").fetchone()[0]
            c.execute("UPDATE private.wallet_bindings SET status='suspended',suspended_at=clock_timestamp() WHERE user_id=%s",(u,))
            later=c.execute("SELECT count(*) FROM private.wallet_binding_audit").fetchone()[0]
            self.assertEqual(prior,later)
        print("KNOWN BLOCKER: privileged owner mutations do not require audit append")
if __name__=="__main__":unittest.main(verbosity=2)

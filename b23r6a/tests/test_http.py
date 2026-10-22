import http.client
import json
import threading
import unittest
import uuid
from unittest.mock import patch
from dataclasses import replace
from b23r6a.http_server import Server,Handler
from b23r6a.gateway import Gateway, Adapters
from b23r6a.adapters.offline import OfflinePrimary, FaultAdapter, test_token
from b23r6a.tests.test_gateway import configured,request,SharedAuthority,SwitchAtAudit
from b23r6a.adapters.offline import USER_A

class HttpSecurity(unittest.TestCase):
    def setUp(self):
        self.key,self.adapters=configured()
        self.gateway=Gateway(self.adapters,OfflinePrimary())
        self.server=Server(("127.0.0.1",0),self.gateway)
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={"poll_interval":.02})
        self.thread.start()

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(3)
        self.assertFalse(self.thread.is_alive());self.assertFalse(self.gateway.workers.active)

    def call(self,method,path,body=None,headers=None):
        conn=http.client.HTTPConnection("127.0.0.1",self.server.server_port,timeout=4)
        try:
            conn.request(method,path,body=body,headers=headers or {})
            r=conn.getresponse();return r.status,json.loads(r.read())
        finally:conn.close()

    def test_server_binds_loopback_only(self):
        with self.assertRaises(ValueError):Server(("0.0.0.0",0),self.gateway)
        code,body=self.call("GET","/healthz");self.assertEqual(code,200);self.assertEqual(body["decision"],"ALLOW")

    def test_oversized_request_rejected(self):
        self.assertEqual(self.call("POST","/v1/decisions","x"*16385,{"Content-Type":"application/json"})[0],413)

    def test_cookie_cannot_supply_identity(self):
        self.assertEqual(self.call("GET","/v1/audit/summary",headers={"Cookie":"userId=victim"})[0],400)

    def test_http_protected_read_requires_authority(self):
        token=test_token(self.key)
        code,body=self.call("GET","/v1/audit/summary",headers={"Authorization":"Bearer "+token})
        self.assertEqual(code,200);self.assertIn("data",body)
        self.gateway.adapters=replace(self.adapters,session=None)
        code,body=self.call("GET","/v1/audit/summary",headers={"Authorization":"Bearer "+token})
        self.assertEqual(code,503);self.assertNotIn("data",body)

    def test_unknown_and_audit_outage_never_release_http_data(self):
        from b23r6a.adapters.offline import OfflineSessions
        for change in ({"session":OfflineSessions(())},{"emitter":FaultAdapter()}):
            self.gateway.adapters=replace(self.adapters,**change)
            code,body=self.call("GET","/v1/audit/summary",headers={"Authorization":"Bearer "+test_token(self.key)})
            self.assertEqual(code,503);self.assertNotIn("data",body)

    def test_http_mutation_quarantined(self):
        code,body=self.call("POST","/v1/decisions",json.dumps(request("wallet.binding.suspend")),
            {"Content-Type":"application/json","Authorization":"Bearer "+test_token(self.key)})
        self.assertEqual(code,200);self.assertEqual(body["decision"],"QUARANTINE");self.assertNotIn("data",body)

    def test_host_and_origin_rejected(self):
        self.assertEqual(self.call("GET","/healthz",headers={"Host":"evil.test"})[0],400)
        self.assertEqual(self.call("GET","/healthz",headers={"Origin":"https://evil.test"})[0],400)

    def test_duplicate_json_and_auth_context_rejected(self):
        headers={"Content-Type":"application/json"}
        for body in ('{"operation":"x","operation":"y"}',json.dumps({**request(),"AuthContext":{}})):
            self.assertEqual(self.call("POST","/v1/decisions",body,headers)[1]["decision"],"DENY")

    def test_no_mutation_http_methods(self):
        for method in ("DELETE","PUT","PATCH"):
            self.assertEqual(self.call(method,"/v1/audit/summary")[0],405)

    def test_http_delivery_is_inside_generation_fence(self):
        entered=threading.Event();attempted=threading.Event();done=threading.Event();results=[];errors=[]
        original=Handler.reply
        def reply(handler,body,code=200):
            if body.get("reason_code")=="READ_AUTHORIZED":
                entered.set()
                if not attempted.wait(2) or done.wait(.05): raise AssertionError("fence did not order delivery")
            return original(handler,body,code)
        def revoke():
            if not entered.wait(4): return
            attempted.set();self.gateway.primary.revoke(USER_A);done.set()
        def read():
            try:results.append(self.call("GET","/v1/audit/summary",headers={"Authorization":"Bearer "+test_token(self.key)}))
            except BaseException as e:errors.append(e)
        revoker=threading.Thread(target=revoke);client=threading.Thread(target=read)
        with patch.object(Handler,"reply",reply):
            revoker.start();client.start();client.join(5);revoker.join(5)
        self.assertFalse(client.is_alive());self.assertFalse(revoker.is_alive());self.assertFalse(errors)
        self.assertTrue(done.is_set());self.assertEqual(results[0][0],200);self.assertIn("data",results[0][1])
        code,body=self.call("GET","/v1/audit/summary",headers={"Authorization":"Bearer "+test_token(self.key)})
        self.assertEqual(code,403);self.assertNotIn("data",body)

    def test_http_revocation_wins_before_fence(self):
        primary=self.gateway.primary;attempted=threading.Event();results=[];errors=[]
        original=primary.acquire
        primary.acquire(USER_A,1)
        def acquire(subject,timeout):attempted.set();return original(subject,timeout)
        def read():
            try:results.append(self.call("GET","/v1/audit/summary",headers={"Authorization":"Bearer "+test_token(self.key)}))
            except BaseException as e:errors.append(e)
        client=threading.Thread(target=read)
        try:
            with patch.object(primary,"acquire",acquire):
                client.start();self.assertTrue(attempted.wait(4));primary.revoke(USER_A)
        finally:
            primary.release(USER_A);client.join(5)
        self.assertFalse(client.is_alive());self.assertFalse(errors)
        self.assertEqual(results[0][0],403);self.assertNotIn("data",results[0][1])

    def test_http_final_authority_unknown_releases_no_data(self):
        import multiprocessing
        flag=multiprocessing.get_context("spawn").Value("i",0)
        self.gateway.adapters=replace(self.adapters,session=SharedAuthority(flag),emitter=SwitchAtAudit(flag,2))
        code,body=self.call("GET","/v1/audit/summary",headers={"Authorization":"Bearer "+test_token(self.key)})
        self.assertEqual(code,503);self.assertEqual(body["reason_code"],"AUTHORITY_UNAVAILABLE");self.assertNotIn("data",body)

if __name__=="__main__":unittest.main(verbosity=2)

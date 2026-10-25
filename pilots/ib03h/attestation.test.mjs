// IB-03H synthetic verifier uses local ephemeral MAC key; real DB validates HMAC.
import {spawnSync} from "node:child_process";
import {randomBytes,createHmac,createHash} from "node:crypto";
import assert from "node:assert/strict";
const key=randomBytes(32), keyId="lab-key-1",subject="alice",wallet="0x"+"ab".repeat(20),chain=11155111;
const digest=createHash("sha256").update("GFLO IB03H synthetic SIWE verified message").digest("hex");
const quote=v=>"'"+String(v).replaceAll("'","''")+"'";
const run=(q,role="gflo_admission_lab",pw="lab-service-only")=>{
 const z=spawnSync("psql",["-X","-qAt","-v","ON_ERROR_STOP=1","-c",q],{encoding:"utf8",timeout:15000,
 env:{...process.env,PGHOST:"127.0.0.1",PGPORT:"5432",PGDATABASE:"gflo_test",PGUSER:role,PGPASSWORD:pw}});
 if(z.status!==0)throw Error("DENIED:"+z.stderr.slice(0,300));
 return z.stdout.trim();
};
const owner=q=>run(q,"gflo_test","test_only_password");
const noAccess=q=>{assert.throws(()=>run(q))};
owner("INSERT INTO ib03h.attestation_keys VALUES ("+quote(keyId)+",decode("+quote(key.toString("hex"))+",'hex'),true)");
noAccess("SELECT key_bytes FROM ib03h.attestation_keys");
noAccess("SELECT ib03g.redeem_verified_session('x','alice',11155111,'x','x','x',1,1,60)");
noAccess("SELECT ib03f.issue_session('x','alice',11155111,'x','x','x',1,1,60)");
assert.throws(()=>run("SELECT ib03g.register_verification('x','alice',11155111,'x','x')","gflo_verifier_lab","lab-verifier-only"));
console.log("PASS admission key not readable; unsigned IB03F/G paths denied");
function setup(n){
 owner("INSERT INTO ib03d2.challenges VALUES("+quote(n)+","+quote(subject)+","+quote(wallet)+","+chain+",'example.test',now()+interval '5 minutes',NULL,"+quote(digest)+")");
}
owner("INSERT INTO ib03d2.bindings VALUES("+quote(subject)+","+chain+","+quote(wallet)+",'ACTIVE',1)");
owner("INSERT INTO ib03d2.consents VALUES("+quote(subject)+","+chain+",'pie:xp:read',true,now()+interval '10 minutes',1)");
const expiry=BigInt(Math.floor(Date.now()/1000)+75),ttl=300;
const sign=(n,s)=>{const payload=["GFLO_IB03H_V1",keyId,n,subject,String(chain),wallet,digest,s,"1","1",String(ttl),String(expiry)].join("|");return createHmac("sha256",key).update(payload).digest("hex")};
const call=(n,s,tag)=>"SELECT ib03h.issue_attested_session("+[
 quote(n),quote(subject),chain,quote(wallet),quote(digest),quote(s),1,1,ttl,expiry,quote(keyId),quote(tag)
 ].join(",")+")";
const nonce="GFLO_NONCE_H_001",sess="SESSION_IB03H_00001";setup(nonce);
assert.equal(run(call(nonce,sess,"0".repeat(64))),"f");
assert.equal(run(call(nonce,sess,sign(nonce,sess.slice(0,-1)+"2"))),"f");
assert.equal(owner("SELECT consumed_at IS NULL FROM ib03d2.challenges WHERE id="+quote(nonce)),"t");
console.log("PASS forged MAC and session substitution rejected without nonce consumption");
assert.equal(run(call(nonce,sess,sign(nonce,sess))),"t");
assert.equal(run(call(nonce,sess,sign(nonce,sess))),"f");
assert.equal(owner("SELECT count(*) FROM ib03d2.sessions WHERE session_id="+quote(sess)),"1");
console.log("PASS authentic HMAC single-use and replay rejection");
const n2="GFLO_NONCE_H_002",s2="SESSION_IB03H_00002";setup(n2);
assert.equal(owner("UPDATE ib03h.attestation_keys SET active=false WHERE key_id="+quote(keyId)),"");
assert.equal(run(call(n2,s2,sign(n2,s2))),"f");
owner("UPDATE ib03h.attestation_keys SET active=true WHERE key_id="+quote(keyId));
assert.equal(owner("SELECT ib03d2.revoke_consent('alice',11155111)"),"2");
assert.equal(run(call(n2,s2,sign(n2,s2))),"f");
console.log("PASS inactive attestor key or revoked consent prevents issuance");
console.log("IB03H_HMAC_ADMISSION_LAB_PASS production=BLOCK");

import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {generateKeyPairSync,sign,verify,randomBytes} from "node:crypto";
import {canonicalRequest} from "../ib03q/request-auth.mjs";
const q=x=>"'"+String(x).replaceAll("'","''")+"'";
const pg=(query,role="gflo_issuer_replay_lab",pw="lab-replay-only")=>{
 const r=spawnSync("psql",["-X","-Atq","-v","ON_ERROR_STOP=1","-c",query],{encoding:"utf8",timeout:15000,
 env:{...process.env,PGHOST:"127.0.0.1",PGDATABASE:"gflo_test",PGPORT:"5432",PGUSER:role,PGPASSWORD:pw}});
 if(r.status!==0)throw Error("DB:"+r.stderr.slice(0,120));return r.stdout.trim();
};
const owner=s=>pg(s,"gflo_test","test_only_password");
const pair=generateKeyPairSync("ed25519");const kid="admission_A";
owner("INSERT INTO ib03r.keys VALUES("+q(kid)+",1,true,"+q(pair.publicKey.export({type:"spki",format:"pem"}))+")");
const now=Math.floor(Date.now()/1000);
const payload={message:"lab",signature:"sig",subject:"alice",sessionId:"SESSION_IB03R_0000001",
 expectedDomain:"example.test",expectedUri:"https://example.test/login",expectedChain:11155111,issuerKeyId:"labIssuer1",keyEpoch:1,sessionSeconds:300};
const env={kid,nonce:randomBytes(16).toString("hex"),issuedAt:now,expiresAt:now+25,audience:"gflo-issuer-ib03q",request:payload};
const signed={...env,signature:sign(null,Buffer.from(canonicalRequest(env)),pair.privateKey).toString("base64url")};
function validate(e){
 const row=pg("SELECT epoch,public_key FROM ib03r.active_key("+q(e.kid)+")");
 if(!row)return false;
 const [epoch,publicKey]=row.split("|");if(Number(epoch)!==1)return false;
 if(!verify(null,Buffer.from(canonicalRequest(e)),publicKey,Buffer.from(e.signature,"base64url")))return false;
 return pg("SELECT ib03r.claim_authenticated_request("+q(e.kid)+","+epoch+","+q(e.nonce)+","+e.expiresAt+")")==="t";
}
assert.equal(validate({...signed,nonce:randomBytes(16).toString("hex")}),false);
console.log("PASS altered signed nonce rejected before shared DB claim");
const cmd="SELECT ib03r.claim_authenticated_request("+q(kid)+",1,"+q(signed.nonce)+","+signed.expiresAt+")";
const kids=Array.from({length:8},()=>spawnSync("psql",["-X","-Atq","-v","ON_ERROR_STOP=1","-c",cmd],{
 encoding:"utf8",env:{...process.env,PGHOST:"127.0.0.1",PGDATABASE:"gflo_test",PGPORT:"5432",PGUSER:"gflo_issuer_replay_lab",PGPASSWORD:"lab-replay-only"}}));
assert.equal(kids.filter(x=>x.status===0&&x.stdout.trim()==="t").length,1);
assert.equal(validate(signed),false);
console.log("PASS shared nonce consumed once among 8 independent PostgreSQL clients");
const second={...signed,nonce:randomBytes(16).toString("hex")};
const s2={...second,signature:sign(null,Buffer.from(canonicalRequest(second)),pair.privateKey).toString("base64url")};
owner("UPDATE ib03r.keys SET active=false,epoch=epoch+1 WHERE kid="+q(kid));
assert.equal(validate(s2),false);
owner("UPDATE ib03r.keys SET active=true WHERE kid="+q(kid));
assert.equal(validate(s2),false);
console.log("PASS retired key and stale epoch denied after reactivation");
assert.throws(()=>pg("SELECT * FROM ib03r.keys"));
assert.throws(()=>pg("UPDATE ib03r.keys SET active=true"));
console.log("PASS issuer DB role cannot modify authoritative key registry");
console.log("IB03R_SHARED_REPLAY_ROTATION_LAB_PASS production=BLOCK");

import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {generateKeyPairSync,sign,randomBytes} from "node:crypto";
import {canonicalRequest} from "../ib03q/request-auth.mjs";
const q=x=>"'"+String(x).replaceAll("'","''")+"'";
function db(s){
 const p=spawnSync("psql",["-Atq","-v","ON_ERROR_STOP=1","-c",s],{
 encoding:"utf8",env:{...process.env,PGHOST:"127.0.0.1",PGPORT:"5432",PGUSER:"gflo_test",PGPASSWORD:"test_only_password",PGDATABASE:"gflo_test"}});
 assert.equal(p.status,0,p.stderr);return p.stdout.trim();
}
const keys=generateKeyPairSync("ed25519"),kid="admission_A";
db("INSERT INTO ib03r.keys VALUES("+q(kid)+",1,true,"+q(keys.publicKey.export({type:"spki",format:"pem"}))+")");
function request(){
 const now=Math.floor(Date.now()/1000);
 const e={kid,nonce:randomBytes(16).toString("hex"),issuedAt:now,expiresAt:now+25,
 audience:"gflo-issuer-ib03q",request:{message:"INVALID_SIWE_FIXTURE",signature:"invalid",subject:"alice",
 sessionId:"SESSION_IB03S_00001",expectedDomain:"example.test",expectedUri:"https://example.test/login",
 expectedChain:11155111,issuerKeyId:"labIssuer1",keyEpoch:1,sessionSeconds:300}};
 return {...e,signature:sign(null,Buffer.from(canonicalRequest(e)),keys.privateKey).toString("base64url")};
}
function gateway(e,port="5432"){
 const p=spawnSync(process.execPath,["pilots/ib03s/gateway.mjs"],{encoding:"utf8",input:JSON.stringify(e),
 env:{...process.env,IB03S_PGPASSWORD:"lab-replay-only",IB03S_PGPORT:port},timeout:14000});
 assert.equal(p.status,0,p.stderr);return JSON.parse(p.stdout);
}
const a=request();
assert.equal(gateway({...a,signature:"A".repeat(86)}).reason,"BAD_SIGNATURE");
assert.equal(db("SELECT count(*) FROM ib03r.claims"),"0");
console.log("PASS forged gateway request never claims shared nonce");
assert.equal(gateway(a).ok,false);
assert.equal(db("SELECT count(*) FROM ib03r.claims"),"1");
assert.equal(gateway(a).reason,"REPLAY_OR_ROTATED");
console.log("PASS signed request claimed once; invalid SIWE fails closed; replay denied");
const b=request();
assert.equal(gateway(b,"1").reason,"STORE_UNAVAILABLE");
assert.equal(db("SELECT count(*) FROM ib03r.claims"),"1");
console.log("PASS shared PostgreSQL outage fails closed with no claim");
const c=request();
db("UPDATE ib03r.keys SET active=false,epoch=epoch+1 WHERE kid="+q(kid));
assert.equal(gateway(c).reason,"KEY_REVOKED");
assert.equal(db("SELECT count(*) FROM ib03r.claims"),"1");
console.log("PASS revoked public key rejected by all gateway calls");
console.log("IB03S_SHARED_GATEWAY_FAILURE_LAB_PASS production=BLOCK");

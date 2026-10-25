import assert from "node:assert/strict";
import {spawn,spawnSync} from "node:child_process";
import {generateKeyPairSync,sign,randomBytes} from "node:crypto";
import {Wallet} from "ethers";
import {messageDigest} from "../ib03m/trust-chain.mjs";
import {canonicalEpochRequest} from "./epoch-auth.mjs";
const q=v=>"'"+String(v).replaceAll("'","''")+"'";
function pg(query,role="gflo_test",password="test_only_password"){
 const p=spawnSync("psql",["-X","-Atq","-v","ON_ERROR_STOP=1","-c",query],{encoding:"utf8",timeout:12000,
 env:{...process.env,PGHOST:"127.0.0.1",PGPORT:"5432",PGDATABASE:"gflo_test",PGUSER:role,PGPASSWORD:password}});
 if(p.status!==0)throw Error("PG:"+p.stderr.slice(0,130));return p.stdout.trim();
}
const priv=generateKeyPairSync("ed25519"),kid="admission_A",pub=priv.publicKey.export({type:"spki",format:"pem"});
pg("INSERT INTO ib03r.keys VALUES("+q(kid)+",1,true,"+q(pub)+")");
const w=new Wallet("0x"+"11".repeat(32)),bad=new Wallet("0x"+"22".repeat(32));
const addr=w.address.toLowerCase();
pg("INSERT INTO ib03d2.bindings VALUES('alice',11155111,"+q(addr)+",'ACTIVE',1)");
pg("INSERT INTO ib03d2.consents VALUES('alice',11155111,'pie:xp:read',true,now()+interval '10 minutes',1)");
function makeEnvelope(request,epoch=1,nonce=randomBytes(16).toString("hex")){
 const now=Math.floor(Date.now()/1000);
 const e={kid,keyEpoch:epoch,nonce,issuedAt:now,expiresAt:now+25,
 audience:"gflo-issuer-ib03q",request};
 return {...e,signature:sign(null,Buffer.from(canonicalEpochRequest(e)),priv.privateKey).toString("base64url")};
}
async function validRequest(){
 const nonce="GFLOT"+randomBytes(12).toString("hex"),issued=new Date().toISOString().replace(/\.\d{3}Z$/,"Z");
 const message=["example.test wants you to sign in with your Ethereum account:",w.address,"",
 "GFLO IB03T two-issuer race","","URI: https://example.test/login","Version: 1",
 "Chain ID: 11155111","Nonce: "+nonce,"Issued At: "+issued].join("\n");
 const digest=messageDigest(message);
 pg("BEGIN; INSERT INTO ib03d2.challenges VALUES("+q(nonce)+",'alice',"+q(addr)+
 ",11155111,'example.test',now()+interval '5 minutes',NULL,"+q(digest)+");"+
 "INSERT INTO ib03n.context VALUES("+q(nonce)+",'alice',"+q(addr)+
 ",11155111,'example.test','https://example.test/login',"+q(digest)+
 ",'pie:xp:read',1,1,date_trunc('second',now()),date_trunc('second',now())+interval '4 minutes'); COMMIT");
 return {message,signature:await w.signMessage(message),subject:"alice",
 sessionId:"SESSION_IB03T_"+randomBytes(9).toString("hex"),
 expectedDomain:"example.test",expectedUri:"https://example.test/login",
 expectedChain:11155111,issuerKeyId:"labIssuer1",keyEpoch:1,sessionSeconds:300};
}
function gateway(e,port="5432"){
 const p=spawnSync("sudo",["-u","gflo_issuer_os","env",
 "PATH="+process.env.PATH,"IB03T_REPLAY_PASSWORD=lab-replay-only","IB03T_DBPORT="+port,
 "IB03P_SECRET_PATH="+process.env.IB03P_SECRET_PATH,
 "IB03P_PGPASSFILE="+process.env.IB03P_PGPASSFILE,process.execPath,"pilots/ib03t/gateway.mjs"],{
 input:JSON.stringify(e),encoding:"utf8",timeout:18000});
 if(p.status!==0)throw Error("GATEWAY:"+p.stderr.slice(0,180));
 return JSON.parse(p.stdout);
}
function gatewayAsync(e){
 return new Promise((resolve,reject)=>{
  const p=spawn("sudo",["-u","gflo_issuer_os","env",
   "PATH="+process.env.PATH,"IB03T_REPLAY_PASSWORD=lab-replay-only",
   "IB03P_SECRET_PATH="+process.env.IB03P_SECRET_PATH,"IB03P_PGPASSFILE="+process.env.IB03P_PGPASSFILE,
   process.execPath,"pilots/ib03t/gateway.mjs"],{stdio:["pipe","pipe","pipe"]});
  let out="",err="";p.stdout.on("data",x=>out+=x);p.stderr.on("data",x=>err+=x);
  p.on("error",reject);p.on("close",code=>{if(code!==0)return reject(Error(err.slice(0,140)));try{resolve(JSON.parse(out))}catch(e){reject(e)}});
  p.stdin.end(JSON.stringify(e));
 });
}
function redeem(att){
 const f=att.fields;
 return pg("SELECT ib03o.admit_atomic("+[
 q(f.challenge),q(f.subject),f.chain,q(f.wallet),q(f.digest),q(f.session),
 f.bindingGen,f.consentGen,f.ttl,f.expires,q(f.kid),f.keyEpoch,q(att.mac)].join(",")+")",
 "gflo_enforcer_lab","lab-enforcer-only");
}
const req=await validRequest(),envelope=makeEnvelope(req);
assert.equal(gateway({...envelope,keyEpoch:2}).reason,"EPOCH_MISMATCH");
assert.equal(gateway({...envelope,signature:"A".repeat(86)}).reason,"BAD_SIGNATURE");
assert.equal(pg("SELECT count(*) FROM ib03r.claims"),"0");
console.log("PASS unsigned epoch mutation and forged signature cannot claim request");
const [a,b]=await Promise.all([gatewayAsync(envelope),gatewayAsync(envelope)]);
const results=[a,b];
assert.equal(results.filter(x=>x.ok===true).length,1,JSON.stringify(results));
assert.equal(results.filter(x=>x.reason==="REPLAY_OR_ROTATED").length,1,JSON.stringify(results));
const att=results.find(x=>x.ok===true);
assert.equal(redeem(att),"t");assert.equal(redeem(att),"f");
assert.equal(pg("SELECT count(*) FROM ib03d2.sessions"),"1");
assert.equal(pg("SELECT count(*) FROM ib03r.claims"),"1");
console.log("PASS two independent issuer gateway processes: one proof, one session, replay denied");
const after=await validRequest(),old=makeEnvelope(after);
pg("UPDATE ib03r.keys SET epoch=2 WHERE kid="+q(kid));
assert.equal(gateway(old).reason,"EPOCH_MISMATCH");
const fresh=makeEnvelope(after,2);
assert.equal(gateway(fresh).ok,true);
assert.equal(pg("SELECT count(*) FROM ib03r.claims"),"2");
console.log("PASS signed key epoch 1 refused after rotation, epoch 2 accepted");
const offline=await validRequest(),down=makeEnvelope(offline,2);
assert.equal(gateway(down,"1").reason,"DB_UNAVAILABLE");
assert.equal(pg("SELECT count(*) FROM ib03r.claims"),"2");
console.log("PASS shared replay DB outage blocks gateway without consuming nonce");
console.log("IB03T_EPOCH_TWO_ISSUER_E2E_LAB_PASS production=BLOCK");

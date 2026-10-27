// IB-03Q attack suite: independent admission UID, issuer UID, request rotation and replay.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {spawnSync} from "node:child_process";
import {generateKeyPairSync,randomBytes} from "node:crypto";
import {Wallet} from "ethers";
import {messageDigest} from "../ib03m/trust-chain.mjs";
const quote=x=>"'"+String(x).replaceAll("'","''")+"'";
const run=(program,args,opts={})=>{
 const p=spawnSync(program,args,{encoding:"utf8",timeout:15000,...opts});
 if(p.status!==0)throw Error("PROCESS_FAILED:"+program+":"+p.stderr?.slice(0,150));
 return p.stdout.trim();
};
const pg=(statement,role="gflo_test",password="test_only_password")=>run("psql",["-X","-qAt","-v","ON_ERROR_STOP=1","-c",statement],
 {env:{...process.env,PGHOST:"127.0.0.1",PGPORT:"5432",PGDATABASE:"gflo_test",PGUSER:role,PGPASSWORD:password}});
const admin=pg;
const temp=fs.mkdtempSync(path.join(os.tmpdir(),"gflo-q-"));
function installOwned(dst,content,user){
 const local=path.join(temp,randomBytes(8).toString("hex"));fs.writeFileSync(local,content,{mode:0o600});
 run("sudo",["install","-m","0400","-o",user,"-g",user,local,dst]);fs.unlinkSync(local);
}
const admissionDir=process.env.IB03Q_ADMISSION_DIR,trustPath=process.env.IB03Q_TRUST_PATH;
const keys=new Map();
for(const id of ["A","B"]){
 const pair=generateKeyPairSync("ed25519");const kid="admission_"+id;
 const priv=admissionDir+"/"+kid+".pem";
 installOwned(priv,pair.privateKey.export({type:"pkcs8",format:"pem"}),"gflo_admission_os");
 keys.set(id,{kid,priv,pub:pair.publicKey.export({type:"spki",format:"pem"})});
}
function trust(active){
 const keysData=[...keys.values()].map(x=>({kid:x.kid,publicKey:x.pub,active:active.includes(x.kid)}));
 installOwned(trustPath,JSON.stringify({keys:keysData}),"gflo_issuer_os");
}
trust(["admission_A"]);
const deniedAdmission=spawnSync("sudo",["-u","gflo_admission_os","cat",process.env.IB03P_SECRET_PATH],{encoding:"utf8"});
const deniedIssuer=spawnSync("sudo",["-u","gflo_issuer_os","cat",keys.get("A").priv],{encoding:"utf8"});
assert.notEqual(deniedAdmission.status,0);assert.notEqual(deniedIssuer.status,0);
console.log("PASS isolated admission and issuer Unix UIDs cannot read each other's private keys");
const w=new Wallet("0x"+"11".repeat(32)),evil=new Wallet("0x"+"22".repeat(32));
const wallet=w.address.toLowerCase();
admin("INSERT INTO ib03d2.bindings VALUES('alice',11155111,"+quote(wallet)+",'ACTIVE',1)");
admin("INSERT INTO ib03d2.consents VALUES('alice',11155111,'pie:xp:read',true,now()+interval '10 minutes',1)");
async function challenge(){
 const nonce="GFLOQ"+randomBytes(12).toString("hex");
 const issued=new Date().toISOString().replace(/\.\d{3}Z$/,"Z");
 const message=["example.test wants you to sign in with your Ethereum account:",w.address,"",
 "GFLO IB03Q issuer isolation","","URI: https://example.test/login","Version: 1",
 "Chain ID: 11155111","Nonce: "+nonce,"Issued At: "+issued].join("\n");
 const digest=messageDigest(message);
 admin("BEGIN;INSERT INTO ib03d2.challenges VALUES("+quote(nonce)+",'alice',"+quote(wallet)+
 ",11155111,'example.test',now()+interval '5 minutes',NULL,"+quote(digest)+");"+
 "INSERT INTO ib03n.context VALUES("+quote(nonce)+",'alice',"+quote(wallet)+
 ",11155111,'example.test','https://example.test/login',"+quote(digest)+
 ",'pie:xp:read',1,1,date_trunc('second',now()),date_trunc('second',now())+interval '4 minutes');COMMIT");
 return {message,signature:await w.signMessage(message),subject:"alice",sessionId:"SESSION_IB03Q_"+randomBytes(7).toString("hex"),expectedDomain:"example.test",
 expectedUri:"https://example.test/login",expectedChain:11155111,issuerKeyId:"labIssuer1",keyEpoch:1,sessionSeconds:300};
}
function signRequest(request,label){
 const a=keys.get(label);return JSON.parse(run("sudo",["-u","gflo_admission_os","env",
 "IB03Q_SIGNER_KEY_PATH="+a.priv,"IB03Q_SIGNER_KID="+a.kid,"PATH="+process.env.PATH,
 process.execPath,"pilots/ib03q/admission-sign.mjs"],{input:JSON.stringify(request)}));
}
function gateway(envelope){
 return JSON.parse(run("sudo",["-u","gflo_issuer_os","env",
 "IB03P_SECRET_PATH="+process.env.IB03P_SECRET_PATH,
 "IB03P_PGPASSFILE="+process.env.IB03P_PGPASSFILE,
 "IB03Q_REPLAY_DIR="+process.env.IB03Q_REPLAY_DIR,
 "IB03Q_TRUST_PATH="+trustPath,"PATH="+process.env.PATH,
 process.execPath,"pilots/ib03q/gateway.mjs"],{input:JSON.stringify(envelope)}));
}
function redeem(g){
 const f=g.fields;
 return pg("SELECT ib03o.admit_atomic("+[quote(f.challenge),quote(f.subject),f.chain,quote(f.wallet),quote(f.digest),
 quote(f.session),f.bindingGen,f.consentGen,f.ttl,f.expires,quote(f.kid),f.keyEpoch,quote(g.mac)].join(",")+")",
 "gflo_enforcer_lab","lab-enforcer-only");
}
const first=await challenge();
const signedA=signRequest(first,"A");
assert.equal(gateway({...signedA,request:{...signedA.request,subject:"bob"}}).ok,false);
assert.equal(gateway({...signedA,audience:"evil-service"}).ok,false);
assert.equal(gateway({...signedA,expiresAt:0}).ok,false);
console.log("PASS tampered client identity, audience and expiration fail request signature/clock gate");
const bad=await challenge();
const wrongWallet=signRequest({...bad,signature:await evil.signMessage(bad.message)},"A");
assert.equal(gateway(wrongWallet).ok,false);
console.log("PASS authenticated but compromised admission cannot bypass independent SIWE verification");
const good=gateway(signedA);
assert.equal(good.ok,true);
assert.equal(gateway(signedA).reason,"REPLAY");
assert.equal(redeem(good),"t");
assert.equal(redeem(good),"f");
assert.equal(pg("SELECT count(*) FROM ib03d2.sessions"),"1");
console.log("PASS authenticated request -> independent issuer -> DB session; transport and nonce replay denied");
const second=await challenge();
const oldSignature=signRequest(second,"A");
trust(["admission_B"]);
assert.equal(gateway(oldSignature).reason,"KEY_REVOKED");
const newSignature=signRequest(second,"B");
const newResult=gateway(newSignature);assert.equal(newResult.ok,true);
assert.equal(redeem(newResult),"t");
assert.equal(pg("SELECT count(*) FROM ib03d2.sessions"),"2");
console.log("PASS admission key rotation retires A and accepts B");
const third=await challenge();const thirdResult=gateway(signRequest(third,"B"));
assert.equal(thirdResult.ok,true);
admin("UPDATE ib03l.keys SET enabled=false,epoch=epoch+1 WHERE kid='labIssuer1'");
assert.equal(redeem(thirdResult),"f");
console.log("PASS HMAC issuer key revocation blocks previously issued but unredeemed MAC");
console.log("IB03Q_AUTH_ROTATION_CONTAINMENT_LAB_PASS production=BLOCK");
fs.rmSync(temp,{recursive:true,force:true});

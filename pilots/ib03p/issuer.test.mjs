import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {randomBytes} from "node:crypto";
import {Wallet} from "ethers";
import {messageDigest} from "../ib03m/trust-chain.mjs";
const quote=x=>"'"+String(x).replaceAll("'","''")+"'";
const sql=(s,role="gflo_test",pass="test_only_password")=>{
 const p=spawnSync("psql",["-X","-Atq","-v","ON_ERROR_STOP=1","-c",s],{encoding:"utf8",timeout:10000,
 env:{...process.env,PGHOST:"127.0.0.1",PGPORT:"5432",PGDATABASE:"gflo_test",PGUSER:role,PGPASSWORD:pass}});
 if(p.status!==0)throw Error("DB:"+p.stderr.slice(0,140));return p.stdout.trim();
};
const wallet=new Wallet("0x"+"11".repeat(32)),evil=new Wallet("0x"+"22".repeat(32));
const nonce="GFLOP"+randomBytes(12).toString("hex");
const domain="example.test",uri="https://example.test/login",addr=wallet.address.toLowerCase();
const issued=new Date().toISOString().replace(/\.\d{3}Z$/,"Z");
const message=[domain+" wants you to sign in with your Ethereum account:",wallet.address,"",
"GFLO issuer isolation","","URI: "+uri,"Version: 1","Chain ID: 11155111",
"Nonce: "+nonce,"Issued At: "+issued].join("\n");
const digest=messageDigest(message);
sql("INSERT INTO ib03l.keys VALUES('labIssuer1',decode("+quote(process.env.IB03P_FIXTURE_KEY_HEX)+",'hex'),true,1)");
sql("INSERT INTO ib03d2.bindings VALUES('alice',11155111,"+quote(addr)+",'ACTIVE',1)");
sql("INSERT INTO ib03d2.consents VALUES('alice',11155111,'pie:xp:read',true,now()+interval '10 minutes',1)");
sql("BEGIN;INSERT INTO ib03d2.challenges VALUES("+quote(nonce)+",'alice',"+quote(addr)+
",11155111,"+quote(domain)+",now()+interval '5 minutes',NULL,"+quote(digest)+");"+
"INSERT INTO ib03n.context VALUES("+quote(nonce)+",'alice',"+quote(addr)+",11155111,"+
quote(domain)+","+quote(uri)+","+quote(digest)+",'pie:xp:read',1,1,date_trunc('second',now()),date_trunc('second',now())+interval '4 minutes');COMMIT");
const base={message,signature:await wallet.signMessage(message),subject:"alice",
sessionId:"SESSION_IB03P_000001",expectedDomain:domain,expectedUri:uri,expectedChain:11155111,
issuerKeyId:"labIssuer1",keyEpoch:1,sessionSeconds:300};
function issuer(req){
 const p=spawnSync("sudo",["-u","gflo_issuer_os","env",
 "IB03P_SECRET_PATH="+process.env.IB03P_SECRET_PATH,
 "IB03P_PG_PASSWORD=lab-issuer-reader-only",
 "PATH="+process.env.PATH,process.execPath,"pilots/ib03p/issuer.mjs"],{
 input:JSON.stringify(req),encoding:"utf8",timeout:12000});
 if(p.status!==0)throw Error("ISSUER:"+p.stderr.slice(0,150));return JSON.parse(p.stdout);
}
const expectDenied=(r)=>assert.equal(issuer(r).ok,false);
const readAttempt=spawnSync("sudo",["-u","gflo_admission_os","cat",process.env.IB03P_SECRET_PATH],{encoding:"utf8"});
assert.notEqual(readAttempt.status,0);
assert.throws(()=>sql("SELECT ib03n.read_context("+quote(nonce)+")","gflo_attestation_issuer_lab","lab-issuer-only"));
assert.throws(()=>sql("SELECT secret FROM ib03l.keys","gflo_issuer_reader_lab","lab-issuer-reader-only"));
console.log("PASS separated Unix UID admission cannot read issuer key; SQL issuer role cannot read secret");
expectDenied({...base,signature:await evil.signMessage(message)});
expectDenied({...base,subject:"bob"});
expectDenied({...base,sessionId:"SESSION_IB03P_000001",expectedUri:"https://evil.test"});
console.log("PASS issuer independently rejects forged EOA, subject and origin before MAC");
const signed=issuer(base);assert.equal(signed.ok,true);
const f=signed.fields;
const redeem=()=>sql("SELECT ib03o.admit_atomic("+[
quote(f.challenge),quote(f.subject),f.chain,quote(f.wallet),quote(f.digest),quote(f.session),
f.bindingGen,f.consentGen,f.ttl,f.expires,quote(f.kid),f.keyEpoch,quote(signed.mac)
].join(",")+")","gflo_enforcer_lab","lab-enforcer-only");
assert.equal(redeem(),"t");
assert.equal(redeem(),"f");
assert.equal(sql("SELECT count(*) FROM ib03d2.sessions"),"1");
console.log("PASS separate issuer -> DB authenticated context/HMAC -> atomic session, replay DENY");
console.log("IB03P_ISSUER_PROCESS_CUSTODY_LAB_PASS production=BLOCK");

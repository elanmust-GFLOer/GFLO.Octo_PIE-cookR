// IB-03F disposable CI-only psql adapter, no production credentials and no live user.
import {spawnSync} from "node:child_process";
import {Wallet} from "ethers";
import {createAdmissionOrchestrator,exactMessageSha256} from "../ib03e/admission.mjs";
import assert from "node:assert/strict";
const wallet=new Wallet("0x"+"11".repeat(32)),nonce="GFLOnonce1234",domain="example.test",uri="https://example.test/login";
const time=Date.parse("2026-10-25T12:00:00Z");
const msg=[domain+" wants you to sign in with your Ethereum account:",wallet.address,"","GFLO admission fixture","","URI: "+uri,"Version: 1","Chain ID: 11155111","Nonce: "+nonce,"Issued At: 2026-10-25T11:59:00Z"].join("\n");
const digest=exactMessageSha256(msg);
const sqlLiteral=value=>"'"+String(value).replaceAll("'","''")+"'";
const run=(query,role="gflo_admission_lab",password="lab-service-only")=>{
 const child=spawnSync("psql",["-X","-qAt","-v","ON_ERROR_STOP=1","-c",query],{encoding:"utf8",env:{...process.env,PGHOST:"127.0.0.1",PGDATABASE:"gflo_test",PGUSER:role,PGPASSWORD:password,PGPORT:"5432"},timeout:10000});
 if(child.status!==0)throw Error("DATABASE_DENIED:"+child.stderr?.slice(0,150));return child.stdout.trim();
};
const denySQL=sql=>{let failed=false;try{run(sql,"gflo_browser_lab","lab-browser-only")}catch{failed=true}assert.equal(failed,true)};
const serviceOnlySQL=sql=>{let failed=false;try{run(sql)}catch{failed=true}assert.equal(failed,true)};
function prepare(){
 const sql=`INSERT INTO ib03d2.bindings VALUES('alice',11155111,${sqlLiteral(wallet.address)},'ACTIVE',1);
 INSERT INTO ib03d2.consents VALUES('alice',11155111,'pie:xp:read',true,now()+interval '1 hour',1);
 INSERT INTO ib03d2.challenges VALUES(${sqlLiteral(nonce)},'alice',${sqlLiteral(wallet.address)},11155111,${sqlLiteral(domain)},now()+interval '1 hour',NULL,${sqlLiteral(digest)});`;
 const s=spawnSync("psql",["-X","-qAt","-v","ON_ERROR_STOP=1"],{input:sql,encoding:"utf8",env:{...process.env,PGUSER:"gflo_test",PGPASSWORD:"test_only_password",PGHOST:"127.0.0.1",PGDATABASE:"gflo_test"},timeout:10000});if(s.status!==0)throw Error("SETUP_FAILED:"+s.stderr);
}
prepare();
assert.equal(run("SELECT count(*) FROM ib03f.lookup_challenge("+sqlLiteral(nonce)+")"),"1");
console.log("PASS trusted backend reads challenge through restricted facade");
denySQL("SELECT * FROM ib03f.lookup_challenge("+sqlLiteral(nonce)+")");
denySQL("SELECT * FROM ib03d2.challenges");
denySQL("SELECT ib03f.issue_session('x','alice',11155111,'x','x','x',1,1,10)");
serviceOnlySQL("UPDATE ib03d2.challenges SET consumed_at=now()");
serviceOnlySQL("SELECT ib03d2.issue_verified_session('x','alice',11155111,'x','x','x',1,1,10)");
console.log("PASS browser and backend denied direct issuance, raw mutation and public facade access");
const challenge={nonce,id:nonce,subject:"alice",domain,uri,chainId:"11155111",wallet:wallet.address,
 messageHash:digest,expiresAt:time+600000,bindingGeneration:1,consentGeneration:1};
const adapter={
 challenges:{load:async n=>{
 const row=run("SELECT id,subject_id,wallet,chain_id,domain,proof_digest FROM ib03f.lookup_challenge("+sqlLiteral(n)+")");
 if(!row)return null;
 const [id,subject,walletAddress,chainId,domainValue,proofDigest]=row.split("|");
 return {...challenge,id,subject, wallet:walletAddress,chainId,domain:domainValue,messageHash:proofDigest};
 }},
 ledger:{issue:async a=>run("SELECT ib03f.issue_session("+[
 a.challengeId,a.subject,a.chainId,a.wallet,a.proofDigest,a.sessionId,a.bindingGeneration,a.consentGeneration,a.sessionSeconds
 ].map((v,i)=>[2,6,7,8].includes(i)?String(v):sqlLiteral(v)).join(",")+")")==="t"}
};
const reader=createAdmissionOrchestrator({...adapter,clock:()=>time,config:{domain,uri,chainId:"11155111",maxAgeSeconds:600,sessionSeconds:600}});
const valid={message:msg,signature:await wallet.signMessage(msg),subject:"alice",sessionId:"GFLO_SESSION_E2E_001"};
const invalid={...valid,signature:await new Wallet("0x"+"22".repeat(32)).signMessage(msg)};
assert.equal((await reader.admit(invalid)).status,"DENIED");
assert.equal(run("SELECT count(*) FROM ib03f.lookup_challenge("+sqlLiteral(nonce)+")"),"1");
console.log("PASS invalid EOA signature never consumed nonce");
const result=await reader.admit(valid);
assert.equal(result.status,"LAB_SESSION_ISSUED");
assert.equal((await reader.admit(valid)).status,"DENIED");
assert.equal(run("SELECT count(*) FROM ib03f.lookup_challenge("+sqlLiteral(nonce)+")"),"0");
console.log("PASS real EIP191 signature -> privileged PG transaction -> one session; replay denied");
console.log("IB03F_END_TO_END_LAB_PASS production=BLOCK");

import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {randomBytes} from "node:crypto";
import {Wallet} from "ethers";
import {createSiweAttestedAdmission,messageDigest,makeLabMacSigner} from "./trust-chain.mjs";
const pw=(v)=>"'"+String(v).replaceAll("'","''")+"'";
function pg(query,role="gflo_enforcer_lab",pass="lab-enforcer-only"){
 const out=spawnSync("psql",["-X","-Atq","-v","ON_ERROR_STOP=1","-c",query],{
 encoding:"utf8",timeout:15000,env:{...process.env,PGHOST:"127.0.0.1",PGPORT:"5432",PGDATABASE:"gflo_test",PGUSER:role,PGPASSWORD:pass}});
 if(out.status!==0)throw Error("DB_DENIED:"+out.stderr.slice(0,120));
 return out.stdout.trim();
}
const admin=q=>pg(q,"gflo_test","test_only_password");
const wallet=new Wallet("0x"+"11".repeat(32)),evil=new Wallet("0x"+"22".repeat(32));
const serverClock=()=>Date.now(),domain="example.test",uri="https://example.test/login",chain=11155111;
const subject="alice",kid="labkey1",epoch=1,ttl=300,secret=randomBytes(32);
admin("INSERT INTO ib03l.keys VALUES("+pw(kid)+",decode("+pw(secret.toString("hex"))+",'hex'),true,1)");
admin("INSERT INTO ib03d2.bindings VALUES("+pw(subject)+","+chain+","+pw(wallet.address.toLowerCase())+",'ACTIVE',1)");
admin("INSERT INTO ib03d2.consents VALUES("+pw(subject)+","+chain+",'pie:xp:read',true,now()+interval '10 minutes',1)");
const policy={domain,uri,chainId:chain,keyId:kid,keyEpoch:epoch,maxAgeSeconds:600,attestationTtlSeconds:60,sessionTtlSeconds:ttl};
const nonce=(prefix)=>prefix+randomBytes(12).toString("hex");
const msg=n=>[domain+" wants you to sign in with your Ethereum account:",wallet.address,"",
 "GFLO OctoPass isolated trust-chain","","URI: "+uri,"Version: 1","Chain ID: "+chain,
 "Nonce: "+n,"Issued At: "+new Date().toISOString().replace(/\.\d{3}Z$/,"Z")].join("\n");
async function fixture(n){
 const message=msg(n),digest=messageDigest(message);
 admin("INSERT INTO ib03d2.challenges VALUES("+pw(n)+","+pw(subject)+","+pw(wallet.address.toLowerCase())+","+
 chain+","+pw(domain)+",now()+interval '5 minutes',NULL,"+pw(digest)+")");
 return {message,signature:await wallet.signMessage(message),nonce:n,digest};
}
let signCalls=0;
const macSigner=makeLabMacSigner(secret);
const admission=createSiweAttestedAdmission({
 loadChallenge:async n=>{
  const row=pg("SELECT id,subject_id,wallet,chain_id,domain,proof_digest FROM ib03f.lookup_challenge("+pw(n)+")","gflo_admission_lab","lab-service-only");
  if(!row)return null;
  const f=row.split("|");if(f.length!==6)throw Error("DB_ROW");
  return {id:f[0],subject:f[1],wallet:f[2],chainId:Number(f[3]),domain:f[4],
   uri,messageDigest:f[5],expiresAt:Date.now()+60000,bindingGen:1,consentGen:1};
 },
 redeem:async f=>pg("SELECT ib03l.admit("+[
 pw(f.challenge),pw(f.subject),f.chain,pw(f.wallet),pw(f.digest),pw(f.session),f.bindingGen,
 f.consentGen,f.ttl,f.expires,pw(f.kid),f.keyEpoch,pw(f.mac)].join(",")+")")==="t",
 signMac:async fields=>{signCalls++;return macSigner(fields)},
 clock:serverClock,policy
});
const valid=await fixture(nonce("GFLOM1"));
const request=(fixture,s)=>({message:fixture.message,signature:fixture.signature,subject,sessionId:s});
const forged=await evil.signMessage(valid.message);
assert.equal((await admission.admit({...request(valid,"SESSION_IB03M_00001"),signature:forged})).status,"DENIED");
assert.equal(signCalls,0);
assert.equal(admin("SELECT consumed_at IS NULL FROM ib03d2.challenges WHERE id="+pw(valid.nonce)),"t");
console.log("PASS bad real EOA signature never reaches MAC signer or consumes nonce");
assert.equal((await admission.admit(request(valid,"SESSION_IB03M_00001"))).status,"LAB_SESSION_ISSUED");
assert.equal((await admission.admit(request(valid,"SESSION_IB03M_00001"))).status,"DENIED");
assert.equal(admin("SELECT count(*) FROM ib03d2.sessions"),"1");
console.log("PASS real EIP191 -> HMAC issuer -> DB-native MAC -> atomic session and replay DENY");
const second=await fixture(nonce("GFLOM2"));
assert.equal((await admission.admit({...request(second,"SESSION_IB03M_00002"),subject:"bob"})).status,"DENIED");
const swapped=second.message.replace("Chain ID: 11155111","Chain ID: 1");
assert.equal((await admission.admit({...request(second,"SESSION_IB03M_00002"),message:swapped})).status,"DENIED");
console.log("PASS altered chain and subject cannot sign an attestation");
assert.equal(admin("SELECT ib03d2.revoke_consent('alice',11155111)"),"2");
assert.equal((await admission.admit(request(second,"SESSION_IB03M_00002"))).status,"DENIED");
assert.equal(admin("SELECT count(*) FROM ib03d2.sessions"),"1");
console.log("PASS revoked consent denies valid EOA signed request");
console.log("IB03M_SIWE_ATTESTATION_PG_LAB_PASS production=BLOCK");

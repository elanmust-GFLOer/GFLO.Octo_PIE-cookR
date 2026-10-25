import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {randomBytes,createHmac} from "node:crypto";
import {Wallet} from "ethers";
import {createImmutableAdmission} from "./admission.mjs";
import {messageDigest} from "../ib03m/trust-chain.mjs";
const quote=x=>"'"+String(x).replaceAll("'","''")+"'";
function pg(q,role="gflo_challenge_reader_lab",password="lab-reader-only"){
 const z=spawnSync("psql",["-X","-qAt","-v","ON_ERROR_STOP=1","-c",q],{
 encoding:"utf8",timeout:15000,env:{...process.env,PGHOST:"127.0.0.1",PGPORT:"5432",
 PGDATABASE:"gflo_test",PGUSER:role,PGPASSWORD:password}});
 if(z.status!==0)throw Error("DB_DENY:"+z.stderr.slice(0,150));return z.stdout.trim();
}
const admin=q=>pg(q,"gflo_test","test_only_password");
const wallet=new Wallet("0x"+"11".repeat(32)),badSigner=new Wallet("0x"+"22".repeat(32));
const domain="example.test",uri="https://example.test/login",chain=11155111,subject="alice";
const key=randomBytes(32),kid="NKEY01",sessionSeconds=300,clock=()=>Date.now();
const policy={domain,uri,chainId:chain,maxAgeSeconds:600,keyId:kid,keyEpoch:1,sessionSeconds};
admin("INSERT INTO ib03l.keys VALUES("+quote(kid)+",decode("+quote(key.toString("hex"))+",'hex'),true,1)");
admin("INSERT INTO ib03d2.bindings VALUES('alice',11155111,"+quote(wallet.address.toLowerCase())+",'ACTIVE',1)");
admin("INSERT INTO ib03d2.consents VALUES('alice',11155111,'pie:xp:read',true,now()+interval '10 minutes',1)");
let signerCalls=0;
const admission=createImmutableAdmission({serverPolicy:policy,clock,
 readContext:async nonce=>{const res=pg("SELECT ib03n.read_context("+quote(nonce)+")");return res?JSON.parse(res):null},
 signAttestation:async ({canonicalPayload})=>{signerCalls++;return createHmac("sha256",key).update(canonicalPayload).digest("hex")},
 redeem:async f=>pg("SELECT ib03l.admit("+[
 quote(f.challenge),quote(f.subject),f.chain,quote(f.wallet),quote(f.digest),
 quote(f.session),f.bindingGen,f.consentGen,f.ttl,f.expires,quote(f.kid),f.keyEpoch,quote(f.mac)
 ].join(",")+")","gflo_enforcer_lab","lab-enforcer-only")==="t"
});
const n="GFLO"+"a".repeat(24);
const issuedAt=new Date().toISOString().replace(/\.\d{3}Z$/,"Z");
const message=[domain+" wants you to sign in with your Ethereum account:",wallet.address,"",
 "GFLO OctoPass immutable context","","URI: "+uri,"Version: 1","Chain ID: "+chain,
 "Nonce: "+n,"Issued At: "+issuedAt].join("\n");
const digest=messageDigest(message);
admin("BEGIN;INSERT INTO ib03d2.challenges VALUES("+quote(n)+",'alice',"+
 quote(wallet.address.toLowerCase())+",11155111,'example.test',now()+interval '5 minutes',NULL,"+quote(digest)+");"+
 "INSERT INTO ib03n.context VALUES("+quote(n)+",'alice',"+quote(wallet.address.toLowerCase())+
 ",11155111,"+quote(domain)+","+quote(uri)+","+quote(digest)+
 ",'pie:xp:read',1,1,now(),now()+interval '5 minutes');COMMIT");
assert.throws(()=>pg("SELECT * FROM ib03n.context"));
assert.throws(()=>pg("SELECT * FROM ib03d2.challenges"));
assert.throws(()=>pg("SELECT ib03n.read_context("+quote(n)+")","gflo_attestation_issuer_lab","lab-issuer-only"));
assert.throws(()=>pg("UPDATE ib03n.context SET uri='https://evil.test' WHERE challenge_id="+quote(n),"gflo_attestation_issuer_lab","lab-issuer-only"));
assert.throws(()=>admin("UPDATE ib03n.context SET consent_generation=99 WHERE challenge_id="+quote(n)));
assert.throws(()=>admin("DELETE FROM ib03n.context WHERE challenge_id="+quote(n)));
console.log("PASS challenge context immutable in SQL; reader-only and issuer-only DB roles separated");
const req={message,signature:await wallet.signMessage(message),subject,sessionId:"SESSION_IB03N_000001"};
assert.equal((await admission.admit({...req,signature:await badSigner.signMessage(message)})).status,"DENIED");
assert.equal(signerCalls,0);
assert.equal((await admission.admit({...req,subject:"bob"})).status,"DENIED");
assert.equal((await admission.admit({...req,message:message.replace("Chain ID: 11155111","Chain ID: 1")})).status,"DENIED");
console.log("PASS forged EOA, wrong subject and chain cannot reach isolated issuer");
assert.equal((await admission.admit(req)).status,"LAB_SESSION_ISSUED");
assert.equal((await admission.admit(req)).status,"DENIED");
assert.equal(admin("SELECT count(*) FROM ib03d2.sessions"),"1");
console.log("PASS DB canonical challenge -> EIP191 EOA -> MAC -> PG atomic one-time session");
console.log("IB03N_IMMUTABLE_ISSUER_ROLE_LAB_PASS production=BLOCK");

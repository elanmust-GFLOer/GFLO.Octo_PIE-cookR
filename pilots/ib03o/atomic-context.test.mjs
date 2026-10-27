import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {randomBytes} from "node:crypto";
import {Wallet} from "ethers";
import {messageDigest} from "../ib03m/trust-chain.mjs";
import {createAtomicContextAdmission} from "./admission.mjs";
const quote=x=>"'"+String(x).replaceAll("'","''")+"'";
function sql(s,role="gflo_challenge_reader_lab",password="lab-reader-only"){
 const p=spawnSync("psql",["-X","-qAt","-v","ON_ERROR_STOP=1","-c",s],{encoding:"utf8",timeout:12000,
 env:{...process.env,PGHOST:"127.0.0.1",PGDATABASE:"gflo_test",PGPORT:"5432",PGUSER:role,PGPASSWORD:password}});
 if(p.status!==0)throw Error("SQL_DENIED:"+p.stderr.slice(0,120));
 return p.stdout.trim();
}
const admin=x=>sql(x,"gflo_test","test_only_password");
const enforcer=x=>sql(x,"gflo_enforcer_lab","lab-enforcer-only");
const issuer=x=>sql(x,"gflo_attestation_issuer_lab","lab-issuer-only");
const wallet=new Wallet("0x"+"11".repeat(32)),attacker=new Wallet("0x"+"22".repeat(32));
const key=randomBytes(32),kid="Okey1",policy={domain:"example.test",uri:"https://example.test/login",
 chainId:11155111,maxAgeSeconds:600,kid,keyEpoch:1,sessionSeconds:300};
const addr=wallet.address.toLowerCase(),now=()=>Date.now();
admin("INSERT INTO ib03l.keys VALUES("+quote(kid)+",decode("+quote(key.toString("hex"))+",'hex'),true,1)");
admin("INSERT INTO ib03d2.bindings VALUES('alice',11155111,"+quote(addr)+",'ACTIVE',1)");
admin("INSERT INTO ib03d2.consents VALUES('alice',11155111,'pie:xp:read',true,now()+interval '10 minutes',1)");
assert.throws(()=>issuer("SELECT * FROM ib03n.context"));
assert.throws(()=>issuer("SELECT * FROM ib03d2.challenges"));
assert.throws(()=>issuer("SELECT * FROM ib03l.keys"));
assert.throws(()=>issuer("SELECT ib03o.admit_atomic('x','x',1,'x','x','x',1,1,1,1,'x',1,'x')"));
assert.throws(()=>enforcer("SELECT ib03l.admit('x','x',1,'x','x','x',1,1,1,1,'x',1,'x')"));
assert.throws(()=>enforcer("SELECT secret FROM ib03l.keys"));
console.log("PASS issuer DB role cannot read challenge/key or issue session; old bypass disabled");
const access=async n=>{const v=sql("SELECT ib03n.read_context("+quote(n)+")");return v?JSON.parse(v):null};
let macCount=0;
const signer=async payload=>{macCount++;const r=spawnSync(process.execPath,["pilots/ib03o/signer.mjs",payload],
 {encoding:"utf8",timeout:10000,env:{IB03O_LAB_SECRET:key.toString("hex")}});
 if(r.status!==0)throw Error("SIGNER_DOWN");return r.stdout.trim()};
const redeem=async f=>enforcer("SELECT ib03o.admit_atomic("+[
 quote(f.challenge),quote(f.subject),f.chain,quote(f.wallet),quote(f.digest),quote(f.session),
 f.bindingGen,f.consentGen,f.ttl,f.expires,quote(f.kid),f.keyEpoch,quote(f.mac)
].join(",")+")")==="t";
const gate=createAtomicContextAdmission({readContext:access,signMac:signer,redeem,clock:now,policy});
const timestamp=new Date().toISOString().replace(/\.\d{3}Z$/,"Z");
const makeNonce=()=>("GFLOO"+randomBytes(12).toString("hex"));
async function challenge({nonce=makeNonce(),contextUri=policy.uri,contextScope="pie:xp:read",contextGeneration=1}={}){
 const message=[policy.domain+" wants you to sign in with your Ethereum account:",wallet.address,"",
 "GFLO frozen challenge","","URI: "+policy.uri,"Version: 1","Chain ID: 11155111",
 "Nonce: "+nonce,"Issued At: "+timestamp].join("\n"), digest=messageDigest(message);
 admin("BEGIN; INSERT INTO ib03d2.challenges VALUES("+quote(nonce)+",'alice',"+quote(addr)+",11155111,"+
 quote(policy.domain)+",now()+interval '4 minutes',NULL,"+quote(digest)+"); "+
 "INSERT INTO ib03n.context VALUES("+quote(nonce)+",'alice',"+quote(addr)+",11155111,"+
 quote(policy.domain)+","+quote(contextUri)+","+quote(digest)+","+quote(contextScope)+",1,"+
 contextGeneration+",date_trunc('second',now()),date_trunc('second',now())+interval '3 minutes'); COMMIT");
 return {nonce,message,signature:await wallet.signMessage(message)};
}
const req=(c,s="SESSION_IB03O_00000001")=>({message:c.message,signature:c.signature,subject:"alice",sessionId:s});
const a=await challenge();
assert.equal((await gate.admit({...req(a),signature:await attacker.signMessage(a.message)})).status,"DENIED");
assert.equal(macCount,0);
assert.equal((await gate.admit({...req(a),subject:"bob"})).status,"DENIED");
assert.equal(macCount,0);
console.log("PASS forged SIWE and subject denied before issuer is invoked");
assert.equal((await gate.admit(req(a))).status,"LAB_SESSION_ISSUED");
assert.equal((await gate.admit(req(a))).status,"DENIED");
assert.equal(admin("SELECT count(*) FROM ib03d2.sessions"),"1");
console.log("PASS frozen DB context + EIP191 EOA + separately executed MAC signer + atomic DB session and replay DENY");
const b=await challenge({contextUri:"https://evil.test/login"});
assert.equal((await gate.admit(req(b,"SESSION_IB03O_00000002"))).status,"DENIED");
const c=await challenge({contextGeneration:2});
assert.equal((await gate.admit(req(c,"SESSION_IB03O_00000003"))).status,"DENIED");
assert.equal(admin("SELECT count(*) FROM ib03d2.sessions"),"1");
console.log("PASS altered canonical URI and stale/forged binding consent generation denied");
const d=await challenge();
assert.equal(admin("SELECT ib03d2.revoke_consent('alice',11155111)"),"2");
assert.equal((await gate.admit(req(d,"SESSION_IB03O_00000004"))).status,"DENIED");
console.log("PASS revoked consent blocks otherwise valid SIWE to MAC issuance");
console.log("IB03O_ATOMIC_CONTEXT_ISSUER_BOUNDARY_LAB_PASS production=BLOCK");

// IB-03K: adversary has gflo_verifier_lab DB credentials, but not signing private key
// and not gflo_enforcer_lab. Independent Node enforcer verifies signed proof.
import {spawnSync} from "node:child_process";
import {generateKeyPairSync,sign,verify,createHash,createPublicKey} from "node:crypto";
import assert from "node:assert/strict";
const lit=s=>"'"+String(s).replaceAll("'","''")+"'";
function pg(q,role="gflo_enforcer_lab",password="lab-enforcer-only"){
 const x=spawnSync("psql",["-X","-qAt","-v","ON_ERROR_STOP=1","-c",q],
 {encoding:"utf8",timeout:15000,env:{...process.env,PGHOST:"127.0.0.1",PGPORT:"5432",PGDATABASE:"gflo_test",PGUSER:role,PGPASSWORD:password}});
 if(x.status!==0)throw Error("PG_DENIED "+x.stderr.slice(0,150));return x.stdout.trim();
}
const owner=q=>pg(q,"gflo_test","test_only_password");
const verifier=q=>pg(q,"gflo_verifier_lab","lab-verifier-only");
const admission=q=>pg(q,"gflo_admission_lab","lab-service-only");
const deny=f=>assert.throws(f);
const pair=generateKeyPairSync("ed25519"), kid="IB03K_K1",wallet="0x"+"ab".repeat(20),subject="alice",chain="11155111";
const pub=pair.publicKey.export({format:"pem",type:"spki"});
const digest=createHash("sha256").update("GFLO fake wallet SIWE fixture").digest("hex");
owner("INSERT INTO ib03j.keys VALUES("+lit(kid)+","+lit(pub)+",true,1)");
owner("INSERT INTO ib03d2.bindings VALUES("+lit(subject)+","+chain+","+lit(wallet)+",'ACTIVE',1)");
owner("INSERT INTO ib03d2.consents VALUES("+lit(subject)+","+chain+",'pie:xp:read',true,now()+interval '10 minutes',1)");
deny(()=>verifier("SELECT ib03j.redeem_receipt('x','x',300)"));
deny(()=>admission("SELECT ib03j.redeem_receipt('x','x',300)"));
deny(()=>verifier("SELECT * FROM ib03k.read_for_enforcement('x')"));
deny(()=>admission("SELECT * FROM ib03k.read_for_enforcement('x')"));
deny(()=>verifier("SELECT public_spki FROM ib03j.keys"));
console.log("PASS verifier compromise lacks redeem and trusted-enforcer read privileges");
const expiry=BigInt(Math.floor(Date.now()/1000)+90), generation="1";
const payload=(n,s)=>["GFLO-IB03J-ED25519-V1",kid,generation,n,subject,chain,wallet,digest,s,"1","1",String(expiry),"gflo-octopass"].join("|");
const signature=(n,s)=>sign(null,Buffer.from(payload(n,s)),pair.privateKey).toString("base64url");
function setup(n){
 owner("INSERT INTO ib03d2.challenges VALUES("+lit(n)+","+lit(subject)+","+lit(wallet)+","+chain+",'example.test',now()+interval '5 minutes',NULL,"+lit(digest)+")");
}
function register(n,s,sig){
 return verifier("SELECT ib03j.register_receipt("+[lit(n),lit(kid),generation,lit(subject),chain,lit(wallet),lit(digest),lit(s),"1","1",String(expiry),lit(sig)].join(",")+")");
}
function enforce(n){
 const row=pg("SELECT * FROM ib03k.read_for_enforcement("+lit(n)+")");
 if(!row)return false;
 const f=row.split("|");if(f.length!==13)throw Error("BAD_ROW");
 const [challenge,id,gen,sub,ch,w,d,s,bg,cg,exp,sig,pubHex]=f;
 const content=["GFLO-IB03J-ED25519-V1",id,gen,challenge,sub,ch,w,d,s,bg,cg,exp,"gflo-octopass"].join("|");
 if(!verify(null,Buffer.from(content),createPublicKey(Buffer.from(pubHex,"hex").toString("utf8")),Buffer.from(sig,"base64url")))return false;
 return pg("SELECT ib03j.redeem_receipt("+lit(challenge)+","+lit(s)+",300)")==="t";
}
const badNonce="GFLO_K_ATTACK_001",badSession="SESSION_IB03K_ATTACK_0001";setup(badNonce);
const forged=signature(badNonce,badSession).replace(/^./,c=>c==="A"?"B":"A");
assert.equal(register(badNonce,badSession,forged),"t"); // Verifier compromised: can register fake receipt!
assert.equal(enforce(badNonce),false);
assert.equal(owner("SELECT consumed_at IS NULL FROM ib03d2.challenges WHERE id="+lit(badNonce)),"t");
assert.equal(owner("SELECT count(*) FROM ib03d2.sessions"),"0");
console.log("PASS forged receipt accepted by compromised verifier SQL role but refused by independent Ed25519 enforcer");
const nonce="GFLO_K_VALID_0001",session="SESSION_IB03K_VALID_0001";setup(nonce);
assert.equal(register(nonce,session,signature(nonce,session)),"t");
assert.equal(enforce(nonce),true);
assert.equal(enforce(nonce),false);
assert.equal(owner("SELECT count(*) FROM ib03d2.sessions"),"1");
console.log("PASS independent signature check permits exactly one PG session; replay denied");
owner("UPDATE ib03j.keys SET active=false,generation=2 WHERE key_id="+lit(kid));
const n2="GFLO_K_REVOKED_001",s2="SESSION_IB03K_REVOKED_001";setup(n2);
assert.equal(register(n2,s2,signature(n2,s2)),"f");
assert.equal(enforce(n2),false);
console.log("PASS key revoked and rotated epoch blocks new receipts");
console.log("IB03K_COMPROMISED_VERIFIER_DB_LAB_PASS production=BLOCK");

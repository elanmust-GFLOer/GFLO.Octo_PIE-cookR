// IB-03J isolated Ed25519 verifier-to-PG handoff. No real wallet, no production secrets.
import {spawnSync} from "node:child_process";
import {randomBytes,createHash,generateKeyPairSync,sign,verify} from "node:crypto";
import assert from "node:assert/strict";
const pg=(sql,role="gflo_admission_lab",pass="lab-service-only")=>{
 const c=spawnSync("psql",["-X","-qAt","-v","ON_ERROR_STOP=1","-c",sql],{encoding:"utf8",timeout:15000,
 env:{...process.env,PGHOST:"127.0.0.1",PGPORT:"5432",PGDATABASE:"gflo_test",PGUSER:role,PGPASSWORD:pass}});
 if(c.status!==0)throw Error("PG_DENIED "+c.stderr.slice(0,180));return c.stdout.trim();
};
const admin=q=>pg(q,"gflo_test","test_only_password");
const verifyDb=q=>pg(q,"gflo_verifier_lab","lab-verifier-only");
const q=s=>"'"+String(s).replaceAll("'","''")+"'";
const deny=(f)=>assert.throws(f);
const keys=generateKeyPairSync("ed25519"),kid="key-1",keyGen=1n;
const pub=keys.publicKey.export({type:"spki",format:"pem"});
admin("INSERT INTO ib03j.keys(key_id,public_spki,active,generation) VALUES("+q(kid)+","+q(pub)+",true,1)");
const verifierLookup=verifyDb("SELECT public_spki FROM ib03j.verifier_key("+q(kid)+")");
assert.ok(verifierLookup.includes("BEGIN PUBLIC KEY"));
deny(()=>pg("SELECT * FROM ib03j.keys"));deny(()=>pg("SELECT * FROM ib03j.receipts"));
deny(()=>pg("SELECT ib03j.register_receipt('x','x',1,'x',1,'x','x','x',1,1,1,'x')"));
deny(()=>verifyDb("SELECT ib03j.redeem_receipt('x','x',60)"));
deny(()=>pg("SELECT ib03h.issue_attested_session('x','x',1,'x','x','x',1,1,60,100,'x','x')"));
console.log("PASS public-only verifier, role split, and legacy HMAC ingress disabled");
const wallet="0x"+"ab".repeat(20),subject="alice",chain=11155111n,bg=1n,cg=1n;
const digest=createHash("sha256").update("IB03J synthetic EOA-verified proof").digest("hex");
admin("INSERT INTO ib03d2.bindings VALUES("+q(subject)+","+chain+","+q(wallet)+",'ACTIVE',1)");
admin("INSERT INTO ib03d2.consents VALUES("+q(subject)+","+chain+",'pie:xp:read',true,now()+interval '10 minutes',1)");
const expires=()=>BigInt(Math.floor(Date.now()/1000)+90);
const msg=(n,s,e)=>["GFLO-IB03J-ED25519-V1",kid,"1",n,subject,String(chain),wallet,digest,s,String(bg),String(cg),String(e),"gflo-octopass"].join("|");
const create=(n,s,e)=>{
 const raw=msg(n,s,e);const signature=sign(null,Buffer.from(raw),keys.privateKey).toString("base64url");
 return {raw,signature,n,s,e};
};
const register=c=>"SELECT ib03j.register_receipt("+[
 q(c.n),q(kid),keyGen,q(subject),chain,q(wallet),q(digest),q(c.s),bg,cg,c.e,q(c.signature)
 ].join(",")+")";
const redeem=(n,s)=>"SELECT ib03j.redeem_receipt("+q(n)+","+q(s)+",300)";
const insertChallenge=n=>admin("INSERT INTO ib03d2.challenges VALUES("+q(n)+","+q(subject)+","+q(wallet)+","+chain+",'example.test',now()+interval '5 minutes',NULL,"+q(digest)+")");
function verifierRegister(c){
 const pubkey=verifyDb("SELECT public_spki FROM ib03j.verifier_key("+q(kid)+")");
 if(!pubkey)throw Error("KEY_REVOKED");
 if(!verify(null,Buffer.from(c.raw),pubkey,Buffer.from(c.signature,"base64url")))return false;
 return verifyDb(register(c))==="t";
}
const n="GFLO_NONCE_J_001",s="SESSION_IB03J_00001";insertChallenge(n);
assert.equal(pg(redeem(n,s)),"f");
const valid=create(n,s,expires());
const forged={...valid,signature:create(n,s+"x",valid.e).signature};
assert.equal(verifierRegister(forged),false);
assert.equal(admin("SELECT count(*) FROM ib03j.receipts"),"0");
console.log("PASS unsigned admission and forged verifier signature cannot make receipt");
assert.equal(verifierRegister(valid),true);
assert.equal(pg(redeem(n,"SESSION_IB03J_SWAP")),"f");
assert.equal(pg(redeem(n,s)),"t");
assert.equal(pg(redeem(n,s)),"f");
assert.equal(admin("SELECT count(*) FROM ib03d2.sessions"),"1");
console.log("PASS authentic attestation -> PG transaction one session, replay and substitution blocked");
const n2="GFLO_NONCE_J_002",s2="SESSION_IB03J_00002";insertChallenge(n2);
const next=create(n2,s2,expires());
admin("UPDATE ib03j.keys SET active=false,generation=generation+1 WHERE key_id="+q(kid));
assert.equal(verifierRegister(next),false);
assert.equal(pg(redeem(n2,s2)),"f");
console.log("PASS key revocation prevents new verifier receipts");
admin("UPDATE ib03j.keys SET active=true WHERE key_id="+q(kid));
const oldGenAttempt=verifierRegister(next);
assert.equal(oldGenAttempt,false);
console.log("PASS key-epoch mismatch after rotation blocks stale attestation");
console.log("IB03J_ASYMMETRIC_PG_LAB_PASS production=BLOCK");

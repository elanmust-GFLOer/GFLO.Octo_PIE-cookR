// IB-03P separate issuer process, ephemeral CI-only key file under dedicated Unix UID.
// Requests are untrusted; issuer performs its own EIP-191 and immutable PG context checks.
import fs from "node:fs";
import {spawnSync} from "node:child_process";
import {createHmac} from "node:crypto";
import {parseSiwe,verifySiweCore} from "../ib03d/siwe-core.mjs";
import {messageDigest} from "../ib03m/trust-chain.mjs";
import {canonicalContextMac} from "../ib03o/admission.mjs";
const json=JSON.parse(fs.readFileSync(0,"utf8"));
const deny=(reason)=>{process.stdout.write(JSON.stringify({ok:false,reason}));};
const quote=x=>"'"+String(x).replaceAll("'","''")+"'";
function db(query){
 const p=spawnSync("psql",["-X","-Atq","-v","ON_ERROR_STOP=1","-c",query],{encoding:"utf8",timeout:10000,
 env:{PGHOST:"127.0.0.1",PGPORT:"5432",PGDATABASE:"gflo_test",PGUSER:"gflo_issuer_reader_lab",PGPASSWORD:process.env.IB03P_PG_PASSWORD??""}});
 if(p.status!==0)throw Error("CONTEXT_UNAVAILABLE");return p.stdout.trim();
}
try{
 const {message,signature,subject,sessionId,expectedDomain,expectedUri,expectedChain,issuerKeyId,keyEpoch,sessionSeconds}=json;
 if(typeof message!=="string"||typeof signature!=="string"||typeof subject!=="string"||
 !/^[A-Za-z0-9_-]{1,128}$/.test(subject)||!/^[A-Za-z0-9_-]{16,128}$/.test(sessionId)||
 expectedDomain!=="example.test"||expectedUri!=="https://example.test/login"||
 expectedChain!==11155111||issuerKeyId!=="labIssuer1"||keyEpoch!==1||sessionSeconds!==300)throw Error("POLICY");
 const siwe=parseSiwe(message);
 const row=db("SELECT ib03n.read_context("+quote(siwe.nonce)+")");
 if(!row)throw Error("CHALLENGE_MISSING");
 const c=JSON.parse(row),now=Date.now();
 if(c.challenge_id!==siwe.nonce||c.subject_id!==subject||
 c.wallet!==siwe.address.toLowerCase()||c.chain_id!==expectedChain||
 c.domain!==expectedDomain||c.uri!==expectedUri||c.scope!=="pie:xp:read"||
 c.message_digest!==messageDigest(message)||Date.parse(c.expires_at)<=now||
 Date.parse(c.issued_at)>now)throw Error("CONTEXT");
 const v=await verifySiweCore({message,signature,accountKind:"EOA",now,expected:{
  domain:c.domain,uri:c.uri,nonce:c.challenge_id,chainId:String(c.chain_id),maxAgeSeconds:600}});
 if(!v.ok||v.address.toLowerCase()!==c.wallet)throw Error("INVALID_SIGNATURE");
 const f={kid:issuerKeyId,keyEpoch,challenge:c.challenge_id,subject:c.subject_id,
 chain:c.chain_id,wallet:c.wallet,digest:c.message_digest,session:sessionId,
 bindingGen:c.binding_generation,consentGen:c.consent_generation,ttl:sessionSeconds,
 expires:Math.floor(now/1000)+25,domain:c.domain,uri:c.uri,scope:c.scope,
 issuedEpoch:Math.floor(Date.parse(c.issued_at)/1000),
 contextExpiryEpoch:Math.floor(Date.parse(c.expires_at)/1000)};
 const stat=fs.statSync(process.env.IB03P_SECRET_PATH);
 if((stat.mode&0o077)!==0||stat.uid!==process.getuid())throw Error("KEY_PERMISSIONS");
 const key=Buffer.from(fs.readFileSync(process.env.IB03P_SECRET_PATH,"utf8").trim(),"hex");
 if(key.length!==32)throw Error("KEY_SIZE");
 const mac=createHmac("sha256",key).update(canonicalContextMac(f)).digest("hex");
 process.stdout.write(JSON.stringify({ok:true,fields:f,mac,nonProduction:true}));
}catch(e){deny(e instanceof Error?e.message:"ISSUER_UNAVAILABLE")}

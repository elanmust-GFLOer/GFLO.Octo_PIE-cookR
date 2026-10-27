// GFLO IB-03M. Server-only composition; no externally supplied "verified" flags.
import {createHash,createHmac} from "node:crypto";
import {parseSiwe,verifySiweCore} from "../ib03d/siwe-core.mjs";
export const messageDigest = x => createHash("sha256").update(x,"utf8").digest("hex");
const deny = why=>Object.freeze({status:"DENIED",reason:why});
export function createSiweAttestedAdmission({loadChallenge,redeem,signMac,clock,policy}) {
 if(typeof loadChallenge!=="function"||typeof redeem!=="function"||
 typeof signMac!=="function"||typeof clock!=="function"||!policy)throw Error("INVALID_CONFIG");
 return Object.freeze({async admit({message,signature,subject,sessionId}) {
  try {
   if(typeof subject!=="string"||!/^[A-Za-z0-9_-]{1,128}$/.test(subject)||
      typeof sessionId!=="string"||!/^[A-Za-z0-9_-]{16,128}$/.test(sessionId))return deny("BAD_REQUEST");
   const parsed=parseSiwe(message);
   const ch=await loadChallenge(parsed.nonce);
   const digest=messageDigest(message);
   if(!ch||ch.id!==parsed.nonce||ch.subject!==subject||
     ch.domain!==policy.domain||ch.uri!==policy.uri||
     String(ch.chainId)!==String(policy.chainId)||
     ch.wallet.toLowerCase()!==parsed.address.toLowerCase()||
     ch.messageDigest!==digest||ch.expiresAt<=clock())return deny("CHALLENGE_MISMATCH");
   const verified=await verifySiweCore({message,signature,now:clock(),accountKind:"EOA",
    expected:{domain:policy.domain,uri:policy.uri,nonce:ch.id,chainId:String(policy.chainId),
    maxAgeSeconds:policy.maxAgeSeconds}});
   if(!verified.ok||verified.status!=="CRYPTO_VERIFIED_ONLY"||verified.address!==parsed.address)
     return deny("SIWE_INVALID");
   const exp=Math.floor(clock()/1000)+Math.min(60,policy.attestationTtlSeconds);
   const fields={challenge:ch.id,subject,chain:policy.chainId,wallet:parsed.address.toLowerCase(),
     digest,session:sessionId,bindingGen:ch.bindingGen,consentGen:ch.consentGen,
     ttl:policy.sessionTtlSeconds,expires:exp,kid:policy.keyId,keyEpoch:policy.keyEpoch};
   // The signing port must only be owned by isolated server; never accept a caller MAC.
   const mac=await signMac(fields);
   if(typeof mac!=="string"||!/^[0-9a-f]{64}$/.test(mac))return deny("SIGNER_UNAVAILABLE");
   return (await redeem({...fields,mac}))===true
     ?Object.freeze({status:"LAB_SESSION_ISSUED",nonProduction:true})
     :deny("DATABASE_DENIED");
  }catch{return deny("ADMISSION_UNAVAILABLE")}
 }});
}
export function canonicalMacBody(v){
 return ["GFLO_IB03L_V1",v.kid,v.keyEpoch,v.challenge,v.subject,v.chain,v.wallet,
  v.digest,v.session,v.bindingGen,v.consentGen,v.ttl,v.expires].join("|");
}
export function makeLabMacSigner(secret){
 return async fields=>createHmac("sha256",secret).update(canonicalMacBody(fields)).digest("hex");
}

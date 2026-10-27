// GFLO IB-03O: SIWE with DB-frozen challenge context and DB-native MAC gate.
// Lab-only, verifier and issuer are still controlled by fixture processes.
import {verifySiweCore,parseSiwe} from "../ib03d/siwe-core.mjs";
import {messageDigest} from "../ib03m/trust-chain.mjs";
const deny=reason=>Object.freeze({status:"DENIED",reason});
export function canonicalContextMac(f){
 return ["GFLO_IB03O_V1",f.kid,f.keyEpoch,f.challenge,f.subject,f.chain,f.wallet,
 f.digest,f.session,f.bindingGen,f.consentGen,f.ttl,f.expires,
 f.domain,f.uri,f.scope,f.issuedEpoch,f.contextExpiryEpoch].join("|");
}
export function createAtomicContextAdmission({readContext,signMac,redeem,clock,policy}){
 if(![readContext,signMac,redeem,clock].every(x=>typeof x==="function")||!policy)throw Error("CONFIG");
 return Object.freeze({async admit({message,signature,subject,sessionId}){
 try{
  if(typeof subject!=="string"||!/^[A-Za-z0-9_-]{1,128}$/.test(subject)
   ||typeof sessionId!=="string"||!/^[A-Za-z0-9_-]{16,128}$/.test(sessionId))return deny("REQUEST");
  const p=parseSiwe(message),c=await readContext(p.nonce);
  if(!c||c.challenge_id!==p.nonce||c.subject_id!==subject||
     c.domain!==policy.domain||c.uri!==policy.uri||
     String(c.chain_id)!==String(policy.chainId)||c.wallet!==p.address.toLowerCase()||
     c.message_digest!==messageDigest(message)||c.scope!=="pie:xp:read"||
     Date.parse(c.expires_at)<=clock()||Date.parse(c.issued_at)>clock())return deny("CONTEXT");
  const v=await verifySiweCore({message,signature,accountKind:"EOA",now:clock(),
   expected:{domain:c.domain,uri:c.uri,chainId:String(c.chain_id),nonce:c.challenge_id,maxAgeSeconds:policy.maxAgeSeconds}});
  if(!v.ok||v.status!=="CRYPTO_VERIFIED_ONLY")return deny("SIWE");
  const f={kid:policy.kid,keyEpoch:policy.keyEpoch,challenge:c.challenge_id,
   subject:c.subject_id,chain:c.chain_id,wallet:c.wallet,digest:c.message_digest,
   session:sessionId,bindingGen:c.binding_generation,consentGen:c.consent_generation,
   ttl:policy.sessionSeconds,expires:Math.floor(clock()/1000)+30,
   domain:c.domain,uri:c.uri,scope:c.scope,
   issuedEpoch:Math.floor(Date.parse(c.issued_at)/1000),
   contextExpiryEpoch:Math.floor(Date.parse(c.expires_at)/1000)};
  const mac=await signMac(canonicalContextMac(f));
  if(!/^[0-9a-f]{64}$/.test(mac??""))return deny("ISSUER");
  return await redeem({...f,mac})===true?
   Object.freeze({status:"LAB_SESSION_ISSUED",nonProduction:true}):deny("DATABASE");
 }catch{return deny("UNAVAILABLE")}
 }});
}

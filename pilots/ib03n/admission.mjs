// IB-03N server admission: DB-only challenge facts, no browser "verified" flag.
import {verifySiweCore,parseSiwe} from "../ib03d/siwe-core.mjs";
import {messageDigest,canonicalMacBody} from "../ib03m/trust-chain.mjs";
const deny=r=>Object.freeze({status:"DENIED",reason:r});
export function createImmutableAdmission({readContext,signAttestation,redeem,clock,serverPolicy}){
 if(typeof readContext!=="function"||typeof signAttestation!=="function"||
 typeof redeem!=="function"||typeof clock!=="function"||!serverPolicy)throw Error("BAD_CONFIG");
 return Object.freeze({async admit({message,signature,subject,sessionId}){
  try{
   if(typeof subject!=="string"||!/^[A-Za-z0-9_-]{1,128}$/.test(subject)
    ||typeof sessionId!=="string"||!/^[A-Za-z0-9_-]{16,128}$/.test(sessionId))return deny("INVALID_REQUEST");
   const p=parseSiwe(message);
   const c=await readContext(p.nonce); // immutable DB row, never request-supplied
   if(!c||c.challenge_id!==p.nonce||c.subject_id!==subject||
    c.wallet!==p.address.toLowerCase()||
    c.domain!==serverPolicy.domain||c.uri!==serverPolicy.uri||
    String(c.chain_id)!==String(serverPolicy.chainId)||
    c.scope!=="pie:xp:read"||c.message_digest!==messageDigest(message)||
    Date.parse(c.expires_at)<=clock())return deny("CONTEXT_MISMATCH");
   const v=await verifySiweCore({message,signature,accountKind:"EOA",now:clock(),expected:{
    domain:c.domain,uri:c.uri,nonce:c.challenge_id,chainId:String(c.chain_id),
    maxAgeSeconds:serverPolicy.maxAgeSeconds}});
   if(!v.ok||v.status!=="CRYPTO_VERIFIED_ONLY"||v.address.toLowerCase()!==c.wallet)
    return deny("INVALID_SIWE");
   const fields={kid:serverPolicy.keyId,keyEpoch:serverPolicy.keyEpoch,challenge:c.challenge_id,
    subject:c.subject_id,chain:c.chain_id,wallet:c.wallet,digest:c.message_digest,
    session:sessionId,bindingGen:c.binding_generation,consentGen:c.consent_generation,
    ttl:serverPolicy.sessionSeconds,expires:Math.floor(clock()/1000)+60};
   const mac=await signAttestation({canonicalPayload:canonicalMacBody(fields)});
   if(!/^[0-9a-f]{64}$/.test(mac??""))return deny("SIGNER_UNAVAILABLE");
   return (await redeem({...fields,mac}))===true?
    Object.freeze({status:"LAB_SESSION_ISSUED",nonProduction:true}):deny("DATABASE_DENIED");
  }catch{return deny("ADMISSION_UNAVAILABLE")}
 }});
}

// IB-03E isolated trusted admission composition. No live secrets, accounts or production DB.
// The challenge and transaction ports must be backed by a trusted, restricted server.
import {createHash,randomBytes} from "node:crypto";
import {parseSiwe,verifySiweCore} from "../ib03d/siwe-core.mjs";
const deny=reason=>Object.freeze({status:"DENIED",reason});
const sha=s=>createHash("sha256").update(s,"utf8").digest("hex");
export function createAdmissionOrchestrator({challenges,ledger,clock,config,erc1271}){
 if(typeof clock!=="function"||!config||typeof config.domain!=="string"||
 !config.uri||!String(config.chainId).match(/^[1-9][0-9]*$/)||
 !Number.isSafeInteger(config.maxAgeSeconds)||config.maxAgeSeconds<1||
 typeof challenges?.load!=="function"||typeof ledger?.issue!=="function")throw Error("ADMISSION_CONFIG");
 return Object.freeze({
  async admit({message,signature,subject,sessionId,accountKind="EOA"}){
   try{
    if(typeof subject!=="string"||!subject||typeof sessionId!=="string"||
       !/^[A-Za-z0-9_-]{16,128}$/.test(sessionId))return deny("REQUEST_INVALID");
    const p=parseSiwe(message);
    const challenge=await challenges.load(p.nonce);
    if(!challenge||challenge.consumed||challenge.subject!==subject||
      challenge.domain!==config.domain||challenge.uri!==config.uri||
      String(challenge.chainId)!==String(config.chainId)||
      challenge.wallet.toLowerCase()!==p.address.toLowerCase()||
      challenge.messageHash!==sha(message)||challenge.expiresAt<=clock())
      return deny("CHALLENGE_INVALID");
    const verified=await verifySiweCore({message,signature,
      expected:{domain:config.domain,uri:config.uri,nonce:challenge.nonce,
        chainId:String(config.chainId),maxAgeSeconds:config.maxAgeSeconds},
      now:clock(),accountKind,erc1271});
    if(!verified.ok||verified.status!=="CRYPTO_VERIFIED_ONLY"||
      verified.nonce!==challenge.nonce||verified.address.toLowerCase()!==challenge.wallet.toLowerCase())
      return deny("CRYPTO_INVALID");
    // This call MUST be on a backend-only DB role and atomic; there is no fallback.
    const issued=await ledger.issue({
      challengeId:challenge.id,subject,chainId:String(config.chainId),
      wallet:verified.address,proofDigest:challenge.messageHash,sessionId,
      bindingGeneration:challenge.bindingGeneration,consentGeneration:challenge.consentGeneration,
      sessionSeconds:config.sessionSeconds
    });
    return issued===true?Object.freeze({status:"LAB_SESSION_ISSUED",sessionId,nonProduction:true}):deny("TRANSACTION_REJECTED");
   }catch{return deny("ADMISSION_UNAVAILABLE");}
  }
 });
}
export function randomChallengeNonce(){return randomBytes(24).toString("base64url");}
export function exactMessageSha256(message){if(typeof message!=="string")throw Error("MESSAGE_REQUIRED");return sha(message);}

// E1-A: isolated protocol-contract laboratory. NOT a production authorization service.
import {createHash, sign, verify, generateKeyPairSync} from "node:crypto";

export const KINDS=Object.freeze(["PERSON","AGENT","SERVICE"]);
export const EVENT_TYPE="builder.reviewed";
const hex64=v=>typeof v==="string"&&/^[0-9a-f]{64}$/.test(v);
function canonical(value){
  if(value===null||typeof value==="boolean"||typeof value==="string")return JSON.stringify(value);
  if(typeof value==="number"&&Number.isSafeInteger(value))return JSON.stringify(value);
  if(Array.isArray(value))return "["+value.map(canonical).join(",")+"]";
  if(typeof value==="object"&&value!==null&&Object.getPrototypeOf(value)===Object.prototype)
    return "{"+Object.keys(value).sort().map(k=>JSON.stringify(k)+":"+canonical(value[k])).join(",")+"}";
  throw Error("NON_CANONICAL_INPUT");
}
export const digest=v=>createHash("sha256").update(canonical(v),"utf8").digest("hex");
export function assertPrincipal(p){
 if(!p||!KINDS.includes(p.kind)||typeof p.id!=="string"||!/^gflo:[a-z0-9:_-]{4,128}$/.test(p.id))throw Error("INVALID_PRINCIPAL");
 if(p.kind==="PERSON"&&p.id.startsWith("gflo:agent:"))throw Error("IDENTITY_TYPE_COLLISION");
 if(p.kind!=="PERSON"&&p.id.startsWith("gflo:person:"))throw Error("IDENTITY_TYPE_COLLISION");
 return true;
}
export function authorizeDelegation({actor,subject,delegation,scope,projectId,now}){
 assertPrincipal(actor);assertPrincipal(subject);
 if(actor.kind==="PERSON")return actor.id===subject.id; // no impersonation, own actions only
 if(subject.kind!=="PERSON"||!delegation||!Number.isSafeInteger(now))return false;
 return delegation.actorId===actor.id&&delegation.subjectId===subject.id&&
  delegation.scope===scope&&delegation.projectId===projectId&&
  Number.isSafeInteger(delegation.expiresAt)&&now<delegation.expiresAt&&
  delegation.revoked===false&&delegation.consentGranted===true;
}
function checkReview(review){
 if(!review||review.type!==EVENT_TYPE||review.schemaVersion!==1||review.decision!=="APPROVED"||
 !/^[-a-zA-Z0-9_]{12,128}$/.test(review.eventId??"")||
 !/^[-a-zA-Z0-9_]{12,128}$/.test(review.projectId??"")||
 !hex64(review.evidenceDigest)||typeof review.issuerId!=="string"||
 !/^[-a-zA-Z0-9_:]{6,128}$/.test(review.reviewerId??"")||
 !/^[-a-zA-Z0-9_:]{6,128}$/.test(review.ownerId??"")||
 review.ownerId===review.reviewerId||
 !Number.isSafeInteger(review.issuedAt)||review.issuedAt<=0)throw Error("REVIEW_INVALID");
}
export function issueLabReview({review,authorizedReviewers,privateKey}){
 checkReview(review);
 if(!authorizedReviewers.has(review.reviewerId))throw Error("REVIEWER_UNAUTHORIZED");
 // A trusted server is responsible for obtaining review from its own database!
 // This function only demonstrates envelope signing, not review truth.
 const hash=digest(review),signature=sign(null,Buffer.from(hash,"hex"),privateKey).toString("hex");
 return Object.freeze({body:Object.freeze({...review}),bodyDigest:hash,algorithm:"Ed25519-LAB",signature});
}
export function verifyLabReview({envelope,pinnedIssuerId,publicKey,alreadySeen}){
 try {
  const {body,bodyDigest,algorithm,signature}=envelope;
  checkReview(body);
  if(algorithm!=="Ed25519-LAB"||body.issuerId!==pinnedIssuerId||
    !hex64(bodyDigest)||digest(body)!==bodyDigest||typeof signature!=="string"||
    !/^[0-9a-f]{128}$/.test(signature)||alreadySeen.has(body.eventId))return false;
  return verify(null,Buffer.from(bodyDigest,"hex"),publicKey,Buffer.from(signature,"hex"));
 }catch{return false;}
}
export function labKeys(){return generateKeyPairSync("ed25519");}

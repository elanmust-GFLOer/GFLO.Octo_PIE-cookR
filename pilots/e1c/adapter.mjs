// E1-C boundary contract. Trusted adapters MUST be provided by authenticated server.
import {issueLabReview,verifyLabReview} from "../e1a/gateway.mjs";
const str=x=>typeof x==="string"&&x.length>0;
export function createAuthenticatedReviewHandler({verifySession,resolveReviewer,issueReview}){
 if([verifySession,resolveReviewer,issueReview].some(f=>typeof f!=="function"))throw Error("BAD_SERVER_CONFIG");
 return async ({bearerToken,input})=>{
  if(!str(bearerToken)||!input||typeof input!=="object"||Array.isArray(input))throw Error("UNAUTHENTICATED");
  // Never accept reviewer/owner/issuer identifiers from a caller, even if ignored.
  if(Object.keys(input).sort().join(",")!=="decision,evidenceDigest,projectId,revision")throw Error("INPUT_NOT_ALLOWED");
  if(input.decision!=="APPROVED"||!str(input.projectId)||
    !Number.isSafeInteger(input.revision)||input.revision<1||
    !/^[0-9a-f]{64}$/.test(input.evidenceDigest))throw Error("INVALID_INPUT");
  const session=await verifySession(bearerToken);
  if(!session||!str(session.userId)||session.active!==true)throw Error("UNAUTHENTICATED");
  const reviewer=await resolveReviewer(session.userId);
  if(!reviewer||reviewer.active!==true||!str(reviewer.principalId)||
     reviewer.userId!==session.userId||reviewer.role!=="reviewer")throw Error("REVIEWER_UNAUTHORIZED");
  // issueReview must read owner/revision & validate actual evidence on trusted DB side.
  return issueReview({projectId:input.projectId,revision:input.revision,evidenceDigest:input.evidenceDigest,
    decision:input.decision,reviewerId:reviewer.principalId,authenticatedUserId:session.userId});
 };
}
export function serverEventToProof({row,privateKey,authorizedReviewers}){
 if(!row||row.decision!=="APPROVED")throw Error("UNAPPROVED_EVENT");
 const review={type:row.type,schemaVersion:1,eventId:row.event_id,projectId:row.project_id,
  ownerId:row.owner_id,reviewerId:row.reviewer_id,issuerId:row.issuer_id,
  decision:row.decision,evidenceDigest:row.evidence_digest,issuedAt:Number(row.issued_at)};
 return issueLabReview({review,authorizedReviewers,privateKey});
}
export function verifyForOctoPass({envelope,pinnedIssuerId,publicKey,alreadySeen,consent,profileId}){
 if(!consent||consent.granted!==true||consent.revoked===true||
    consent.scope!=="builder:reviewed:read"||consent.profileId!==profileId||
    envelope?.body?.ownerId!==profileId)return false;
 return verifyLabReview({envelope,pinnedIssuerId,publicKey,alreadySeen});
}

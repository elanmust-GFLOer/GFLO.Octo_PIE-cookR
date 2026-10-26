import assert from "node:assert/strict";
import {test} from "node:test";
import {digest,issueLabReview,verifyLabReview,labKeys} from "../e1a/gateway.mjs";
// SQL event shape mapped to E1-A signed envelope. Synthetic only.
const projectId="GFLOProject0001",now=1793000000;
const row={event_id:"review_event_aabbccddeeff00112233445566778899",
 project_id:projectId,revision:1,owner_id:"gflo:person:alpha",
 reviewer_id:"gflo:person:reviewer",issuer_id:"octopush:review-issuer",
 type:"builder.reviewed",evidence_digest:"a".repeat(64)};
test("E1-B event maps to E1-A proof envelope with exact issuer and owner",()=>{
 const keys=labKeys();
 const review={type:row.type,schemaVersion:1,eventId:row.event_id,
   projectId:row.project_id,ownerId:row.owner_id,reviewerId:row.reviewer_id,
   issuerId:row.issuer_id,evidenceDigest:row.evidence_digest,issuedAt:now,decision:"APPROVED"};
 const envelope=issueLabReview({review,authorizedReviewers:new Set([row.reviewer_id]),privateKey:keys.privateKey});
 assert.equal(verifyLabReview({envelope,pinnedIssuerId:row.issuer_id,publicKey:keys.publicKey,alreadySeen:new Set()}),true);
 assert.equal(verifyLabReview({envelope,pinnedIssuerId:row.issuer_id,publicKey:keys.publicKey,alreadySeen:new Set([row.event_id])}),false);
 assert.equal(verifyLabReview({envelope:{...envelope,body:{...envelope.body,ownerId:"gflo:person:evil"}},
   pinnedIssuerId:row.issuer_id,publicKey:keys.publicKey,alreadySeen:new Set()}),false);
});
console.log("E1B_TO_E1A_ENVELOPE_LAB_PASS production=BLOCK");

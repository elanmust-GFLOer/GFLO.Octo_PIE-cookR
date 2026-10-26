import assert from "node:assert/strict";
import {test} from "node:test";
import {assertPrincipal,authorizeDelegation,issueLabReview,verifyLabReview,labKeys,digest} from "./gateway.mjs";

const person={id:"gflo:person:alpha",kind:"PERSON"},agent={id:"gflo:agent:alpha",kind:"AGENT"},service={id:"gflo:service:mcp1",kind:"SERVICE"};
const projectId="GFLOProject0001",now=1793000000;
const delegation={actorId:agent.id,subjectId:person.id,scope:"builder:read",projectId,expiresAt:now+300,revoked:false,consentGranted:true};

test("distinct actor namespaces; MCP service is not automatically a person",()=>{
 for(const p of [person,agent,service])assert.equal(assertPrincipal(p),true);
 assert.throws(()=>assertPrincipal({kind:"PERSON",id:"gflo:agent:alpha"}));
 assert.equal(authorizeDelegation({actor:service,subject:person,scope:"builder:read",projectId,now}),false);
});
test("agent delegation requires explicit scope, consent, TTL, and no revocation",()=>{
 const params={actor:agent,subject:person,delegation,scope:"builder:read",projectId,now};
 assert.equal(authorizeDelegation(params),true);
 assert.equal(authorizeDelegation({...params,scope:"proof:write"}),false);
 assert.equal(authorizeDelegation({...params,now:now+301}),false);
 assert.equal(authorizeDelegation({...params,delegation:{...delegation,revoked:true}}),false);
 assert.equal(authorizeDelegation({...params,delegation:{...delegation,consentGranted:false}}),false);
 assert.equal(authorizeDelegation({...params,projectId:"OtherProject0001"}),false);
});
const keys=labKeys();
const review={type:"builder.reviewed",schemaVersion:1,eventId:"review_event_0001",projectId,
 ownerId:person.id,reviewerId:"gflo:person:reviewer",issuerId:"octopush:review-issuer",
 decision:"APPROVED",evidenceDigest:digest({projectId,version:1}),issuedAt:now};
const reviewerSet=new Set([review.reviewerId]);
test("server signed proof independently verifiable using pinned issuer public key",()=>{
 const envelope=issueLabReview({review,authorizedReviewers:reviewerSet,privateKey:keys.privateKey});
 assert.equal(verifyLabReview({envelope,pinnedIssuerId:review.issuerId,publicKey:keys.publicKey,alreadySeen:new Set()}),true);
 assert.equal(verifyLabReview({envelope,pinnedIssuerId:"fake:issuer",publicKey:keys.publicKey,alreadySeen:new Set()}),false);
 assert.equal(verifyLabReview({envelope:{...envelope,body:{...review,projectId:"EvilProject0001"}},pinnedIssuerId:review.issuerId,publicKey:keys.publicKey,alreadySeen:new Set()}),false);
 assert.equal(verifyLabReview({envelope,pinnedIssuerId:review.issuerId,publicKey:keys.publicKey,alreadySeen:new Set([review.eventId])}),false);
});
test("reviewer cannot self-approve or claim untrusted authorization",()=>{
 assert.throws(()=>issueLabReview({review:{...review,reviewerId:review.ownerId},authorizedReviewers:reviewerSet,privateKey:keys.privateKey}),/REVIEW_INVALID/);
 assert.throws(()=>issueLabReview({review:{...review,reviewerId:"gflo:person:intruder"},authorizedReviewers:reviewerSet,privateKey:keys.privateKey}),/REVIEWER_UNAUTHORIZED/);
});
test("unrecognized witness key cannot verify the proof",()=>{
 const other=labKeys();
 const env=issueLabReview({review,authorizedReviewers:reviewerSet,privateKey:keys.privateKey});
 assert.equal(verifyLabReview({envelope:env,pinnedIssuerId:review.issuerId,publicKey:other.publicKey,alreadySeen:new Set()}),false);
});
console.log("E1A_ID_ENTITY_GATEWAY_CONTRACT_LAB_PASS production=BLOCK");

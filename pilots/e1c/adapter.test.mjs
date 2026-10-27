import assert from "node:assert/strict";
import {test} from "node:test";
import {readFileSync} from "node:fs";
import {createAuthenticatedReviewHandler,serverEventToProof,verifyForOctoPass} from "./adapter.mjs";
import {labKeys} from "../e1a/gateway.mjs";
const user="supabase-auth-verified-uid",principal="gflo:person:reviewer";
const evidenceDigest="a".repeat(64),projectId="GFLOProject0001";
const input={decision:"APPROVED",evidenceDigest,projectId,revision:1};
let invocations=[];
let roles={userId:user,principalId:principal,role:"reviewer",active:true};
const handler=createAuthenticatedReviewHandler({
 verifySession:async token=>token==="session:verified"?{userId:user,active:true}:null,
 resolveReviewer:async uid=>uid===user?roles:null,
 issueReview:async payload=>{invocations.push(payload);return {accepted:true,...payload}}
});
test("reviewer derives from trusted authenticated session, not request",async()=>{
 const result=await handler({bearerToken:"session:verified",input});
 assert.equal(result.accepted,true);
 assert.equal(result.reviewerId,principal);
 assert.equal(result.authenticatedUserId,user);
 assert.equal(invocations.length,1);
});
test("forged reviewer and arbitrary session denied before DB action",async()=>{
 for(const extra of [{reviewerId:"gflo:person:admin"},{ownerId:"gflo:person:alpha"},{issuerId:"bad:issuer"},{role:"admin"}]){
  await assert.rejects(handler({bearerToken:"session:verified",input:{...input,...extra}}),/INPUT_NOT_ALLOWED/);
 }
 await assert.rejects(handler({bearerToken:"session:forged",input}),/UNAUTHENTICATED/);
 assert.equal(invocations.length,1);
});
test("server role and disabled reviewer fail closed",async()=>{
 roles={...roles,role:"user"};
 await assert.rejects(handler({bearerToken:"session:verified",input}),/REVIEWER_UNAUTHORIZED/);
 roles={...roles,role:"reviewer",active:false};
 await assert.rejects(handler({bearerToken:"session:verified",input}),/REVIEWER_UNAUTHORIZED/);
 roles={...roles,active:true};
});
test("E1-B actual persisted DB row flows to E1-A signed proof and OctoPass read consent",()=>{
 const path=process.env.E1C_DB_EVENT_PATH;
 assert.ok(path,"MISSING_DB_EVENT");
 const row=JSON.parse(readFileSync(path,"utf8").trim());
 assert.equal(row.type,"builder.reviewed");
 assert.equal(row.project_id,projectId);
 const {privateKey,publicKey}=labKeys();
 const envelope=serverEventToProof({row,privateKey,authorizedReviewers:new Set([principal])});
 const params={envelope,pinnedIssuerId:row.issuer_id,publicKey,alreadySeen:new Set(),
  profileId:row.owner_id,consent:{granted:true,revoked:false,scope:"builder:reviewed:read",profileId:row.owner_id}};
 assert.equal(verifyForOctoPass(params),true);
 assert.equal(verifyForOctoPass({...params,consent:{...params.consent,scope:"builder:reviewed:write"}}),false);
 assert.equal(verifyForOctoPass({...params,consent:{...params.consent,revoked:true}}),false);
 assert.equal(verifyForOctoPass({...params,alreadySeen:new Set([row.event_id])}),false);
 assert.equal(verifyForOctoPass({...params,profileId:"gflo:person:wrong"}),false);
 assert.equal(verifyForOctoPass({...params,envelope:{...envelope,body:{...envelope.body,evidenceDigest:"b".repeat(64)}}}),false);
});
console.log("E1C_AUTH_REVIEW_DB_EVENT_OCTOPASS_BRIDGE_LAB_PASS production=BLOCK");

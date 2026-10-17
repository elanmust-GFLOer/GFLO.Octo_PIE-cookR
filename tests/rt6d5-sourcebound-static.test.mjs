import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const code=readFileSync(new URL("../contracts/GFLOSourceBoundAttestorV01.sol",import.meta.url),"utf8");
test("no private-key signing or arbitrary proof signing function",()=>{
 assert.doesNotMatch(code,/function\\s+(sign|signDigest|approveAnyProof)\\s*\\(/);
 assert.match(code,/function isValidSignature\\(/);
});
test("EIP712 source authorization domain binds exact proof digest, event key and TTL",()=>{
 assert.match(code,/SourceAuthorization\\(bytes32 proofDigest,bytes32 sourceEventKey,uint64 validUntil\\)/);
 assert.match(code,/ECDSA\\.recover\\(authDigest,sourceSignature\\)/);
});
test("replay keys and proof approvals are unique",()=>{
 assert.match(code,/consumedEventKeys\\[sourceEventKey\\]/);
 assert.match(code,/approvals\\[proofDigest\\]\\.issuer/);
});
test("ERC1271 validation fails closed on pause, revocation, expiry and disabled issuer",()=>{
 for(const expected of ["!paused","sourceIssuers[a.issuer]","!a.revoked","a.validUntil>block.timestamp","signature.length==0"])
  assert.ok(code.includes(expected),expected);
});
test("governance may authorize issuer, so this is not a complete collusion defense",()=>{
 assert.match(code,/function setIssuer\\(address issuer,bool enabled\\) external onlyGovernance/);
});

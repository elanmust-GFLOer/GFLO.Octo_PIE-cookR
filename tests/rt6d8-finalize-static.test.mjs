// Dependency-free source-level RT6D.8 regression guard.
// This is NOT an EVM execution test. It guards against accidental removal of the gate.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const xp=readFileSync(new URL("../contracts/XPPolicyV04.sol",import.meta.url),"utf8");
const attestor=readFileSync(new URL("../contracts/GFLOSourceBoundAttestorV01.sol",import.meta.url),"utf8");
const evm=readFileSync(new URL("../scripts/rt6d7-issuer-rotation-evm.mjs",import.meta.url),"utf8");
const finalize=xp.slice(xp.indexOf("function finalize("),xp.indexOf("function revoke("));
assert.match(xp,/bytes32 proofDigest;\s*Status status;/,"Grant must persist digest");
assert.match(xp,/msg\.sender,attestor,digest,Status\.PENDING/,"submit must bind digest");
assert.match(finalize,/SignatureChecker\.isValidSignatureNow\(grant\.attestor,\s*grant\.proofDigest/);
assert.match(finalize,/sourceBoundRuntimeHash/);
assert.ok(finalize.indexOf("isValidSignatureNow")<finalize.indexOf("grant.status=Status.VALID"),"verify before credit");
for(const key of ["!paused","sourceIssuers[a.issuer]","!a.revoked","a.validUntil>block.timestamp"])
 assert.ok(attestor.includes(key),"missing source lifecycle condition: "+key);
for(const key of ["RT6D8-01","RT6D8-02","RT6D8-03","RT6D8-04"])
 assert.ok(evm.includes(key),"missing EVM regression case: "+key);
console.log("RT6D.8 source guard PASS (static only; EVM test execution still required).");

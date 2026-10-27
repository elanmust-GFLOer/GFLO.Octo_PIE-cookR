// IB-03D.4 immutable lab evidence manifest validator. No network calls, deployment or session issuance.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {execFileSync} from "node:child_process";
import {fileURLToPath} from "node:url";
import path from "node:path";
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"../..");
const evidence=JSON.parse(readFileSync(path.join(root,"pilots/ib03d/evidence-manifest.json"),"utf8"));
assert.equal(evidence.schema,"gflo.ib03d4.identity-evidence.v1");
assert.equal(evidence.productionRelease,"BLOCK");
assert.equal(evidence.gateStatus,"LAB_EVIDENCE_CLOSED");
assert.equal(evidence.pr,20);
assert.equal(evidence.inputs.length,6);
assert.equal(evidence.evidence.length,3);
assert.deepEqual(evidence.evidence.map(x=>x.gate),["D1","D2","D3"]);
const sha=/^[0-9a-f]{40}$/;
for(const i of evidence.inputs){
 assert.match(i.blob,sha);
 assert.ok(/^(D1|D2|D3)$/.test(i.gate));
 assert.ok(i.path.startsWith("pilots/ib03d/")&&!i.path.includes(".."));
 const actual=execFileSync("git",["hash-object",i.path],{cwd:root,encoding:"utf8"}).trim();
 assert.equal(actual,i.blob,"blob drift: "+i.path);
}
for(const g of evidence.evidence){
 assert.ok(Number.isInteger(g.run));
 assert.match(g.head,sha);
 assert.equal(g.conclusion,"success");
 assert.ok(g.limitations.length>=12);
}
assert.ok(evidence.blockers.length>=8);
console.log("IB03D4_EVIDENCE_MANIFEST_PASS inputs=6 historical_gate_refs=3 production=BLOCK");

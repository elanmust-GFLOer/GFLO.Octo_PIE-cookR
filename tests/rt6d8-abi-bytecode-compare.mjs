import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {createRequire} from "node:module";
const here=path.dirname(fileURLToPath(import.meta.url));
const root=path.resolve(here,"..");
const require=createRequire(import.meta.url);
const solc=require("solc");
const ozRoot=path.dirname(require.resolve("@openzeppelin/contracts/package.json"));
const baseline=fs.readFileSync(path.join(here,"baselines/XPPolicyV04.rt6d7.sol"),"utf8");
const patched=fs.readFileSync(path.join(root,"contracts/XPPolicyV04.sol"),"utf8");
function compile(source){
 const input={language:"Solidity",sources:{"XPPolicyV04.sol":{content:source}},settings:{optimizer:{enabled:true,runs:200},evmVersion:"cancun",outputSelection:{"*":{"*":["abi","evm.bytecode.object","evm.deployedBytecode.object","storageLayout"]}}}};
 const result=JSON.parse(solc.compile(JSON.stringify(input),{import:(name)=>{
   if(!name.startsWith("@openzeppelin/contracts/"))return {error:"Unexpected import "+name};
   const full=path.resolve(ozRoot,name.slice("@openzeppelin/contracts/".length));
   if(!full.startsWith(ozRoot+path.sep))return {error:"Unsafe import "+name};
   return {contents:fs.readFileSync(full,"utf8")};
 }}));
 for(const error of result.errors||[])if(error.severity==="error")throw Error(error.formattedMessage);
 return result.contracts["XPPolicyV04.sol"].XPPolicyV04;
}
const old=compile(baseline),now=compile(patched);
const getter=c=>c.abi.find(x=>x.type==="function"&&x.name==="grants");
assert.equal(getter(old).outputs.length,7);
assert.equal(getter(now).outputs.length,8);
assert.equal(getter(now).outputs[6].name,"proofDigest");
assert.equal(getter(now).outputs[7].name,"status");
const size=c=>({creation:c.evm.bytecode.object.length/2,runtime:c.evm.deployedBytecode.object.length/2});
const fields=c=>c.storageLayout.storage.map(x=>({label:x.label,slot:x.slot,offset:x.offset,type:x.type}));
const oldStorage=fields(old),newStorage=fields(now);
const oldGrant=old.storageLayout.types[old.storageLayout.storage.find(x=>x.label==="grants").type];
const newGrant=now.storageLayout.types[now.storageLayout.storage.find(x=>x.label==="grants").type];
const report={compiler:solc.version(),baseline:size(old),patched:size(now),getterBaseline:getter(old).outputs.map(x=>({name:x.name,type:x.type})),getterPatched:getter(now).outputs.map(x=>({name:x.name,type:x.type})),storageRootBaseline:oldStorage,storageRootPatched:newStorage,grantStorageBaseline:oldGrant,grantStoragePatched:newGrant};
console.log("RT6D8 ABI BYTECODE STORAGE COMPARISON:",JSON.stringify(report));
console.log("RT6D8 baseline-vs-patch compile PASS (NOT gas equivalence / NOT upgrade-safe assertion)");

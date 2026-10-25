// IB-02F: compiler-derived ABI and FULL storage member layout gate.
// It does not establish proxy upgrade safety, deployment compatibility or app consumer coverage.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {createHash} from "node:crypto";
import {createRequire} from "node:module";
const require=createRequire(import.meta.url);
const solc=require("solc"), {Interface}=require("ethers");
const here=path.dirname(fileURLToPath(import.meta.url));
const root=path.resolve(here,"..");
const baseline=readFileSync(path.join(here,"baselines/XPPolicyV04.ib02f-original.sol"),"utf8");
const candidate=readFileSync(path.join(root,"contracts/XPPolicyV04.sol"),"utf8");
const digest=s=>createHash("sha256").update(s).digest("hex");
assert.equal(digest(baseline),"d38215cfab66af182ca633432ed16686ebaf4fa47af0d8d9402638e08734b76c","baseline sha256 drift");
assert.equal(solc.version(),"0.8.34+commit.80d5c536.Emscripten.clang","compiler drift");
const ozRoot=path.dirname(require.resolve("@openzeppelin/contracts/package.json"));
const load=(file,body)=>{
 const input={language:"Solidity",sources:{[file]:{content:body}},settings:{
 optimizer:{enabled:true,runs:200},evmVersion:"cancun",
 outputSelection:{"*":{"*":["abi","evm.bytecode.object","evm.deployedBytecode.object","storageLayout"]}}
 }};
 const out=JSON.parse(solc.compile(JSON.stringify(input),{import:name=>{
  if(!name.startsWith("@openzeppelin/contracts/"))return {error:"Unexpected import "+name};
  const full=path.resolve(ozRoot,name.slice("@openzeppelin/contracts/".length));
  if(!full.startsWith(ozRoot+path.sep))return {error:"Unsafe import "+name};
  return {contents:readFileSync(full,"utf8")};
 }}));
 const errors=(out.errors??[]).filter(e=>e.severity==="error");
 assert.equal(errors.length,0,errors.map(e=>e.formattedMessage).join("\n"));
 return out.contracts[file];
};
const base=load("XPPolicyV04.sol",baseline).XPPolicyV04;
const next=load("XPPolicyV04.sol",candidate).XPPolicyV04;
const fn=(abi,name)=>{const f=abi.find(x=>x.type==="function"&&x.name===name);assert.ok(f,"missing "+name);return f};
const sig=f=>f.name+"("+f.inputs.map(i=>i.type).join(",")+")";
const oldFns=base.abi.filter(x=>x.type==="function");
const newFnNames=new Set(next.abi.filter(x=>x.type==="function").map(sig));
for(const f of oldFns)assert.ok(newFnNames.has(sig(f)),"removed function "+sig(f));
for(const f of oldFns){
 const now=next.abi.find(x=>x.type==="function"&&sig(x)===sig(f));
 assert.deepEqual(now.outputs.map(x=>x.type),f.outputs.map(x=>x.type),"return tuple changed "+sig(f));
}
for(const event of base.abi.filter(x=>x.type==="event")){
 const match=next.abi.find(x=>x.type==="event"&&sig(x)===sig(event));
 assert.ok(match,"event removed: "+sig(event));
 assert.deepEqual(match.inputs.map(x=>[x.type,!!x.indexed]),event.inputs.map(x=>[x.type,!!x.indexed]),"event shape drift "+sig(event));
}
assert.deepEqual(fn(next.abi,"grants").outputs.map(x=>x.type),["address","bytes32","uint16","uint64","address","address","bytes32","uint8"]);
assert.deepEqual(fn(next.abi,"totalXP").outputs.map(x=>x.type),["uint64"]);
assert.ok(next.abi.some(x=>x.type==="event"&&x.name==="GrantExpired"));
assert.ok(next.abi.some(x=>x.type==="function"&&x.name==="expirePending"));
const normalizer=layout=>{
 const ts=layout.types;
 const type=(key,seen=[])=>{
  if(seen.includes(key))throw Error("recursive storage layout type");
  const x=ts[key];assert.ok(x,"unknown storage layout type "+key);
  const result={encoding:x.encoding,label:x.label,numberOfBytes:x.numberOfBytes};
  if(x.key)result.key=type(x.key,[...seen,key]);
  if(x.value)result.value=type(x.value,[...seen,key]);
  if(x.base)result.base=type(x.base,[...seen,key]);
  if(x.members)result.members=x.members.map(m=>({label:m.label,slot:m.slot,offset:m.offset,type:type(m.type,[...seen,key])}));
  return result;
 };
 return layout.storage.map(m=>({label:m.label,slot:m.slot,offset:m.offset,type:type(m.type)}));
};
assert.deepEqual(normalizer(next.storageLayout),normalizer(base.storageLayout),"FULL storage layout drift");
const pieRoot=process.env.GFLO_PIE_ROOT;
assert.ok(pieRoot,"GFLO_PIE_ROOT required");
const fixture=[
 ["TrustedXPSourceRegistryV02.sol","TrustedXPSourceRegistryV02"],
 ["EffectiveTierGateV01.sol","EffectiveTierGateV01"],
 ["GFLOIgnitionV01.sol","GFLOIgnitionV01"],
 ["PIECoreIgnitionV01.sol","PIECoreIgnitionV01"]
];
const consumer={};
for(const [file,contract] of fixture){
 const code=readFileSync(path.join(pieRoot,"contracts",file),"utf8");
 consumer[contract]=load(file,code)[contract];
}
const policyI=new Interface(next.abi);
for(const f of ["pie()","owner()","totalXP(address)"]){
 const found=policyI.getFunction(f);assert.ok(found,"missing policy ABI "+f);
}
const registryI=new Interface(consumer.TrustedXPSourceRegistryV02.abi);
for(const f of ["pieCore()","activeSource()","paused()","totalXP(address)"]){
 assert.ok(registryI.getFunction(f),"missing registry ABI "+f);
}
const gateI=new Interface(consumer.EffectiveTierGateV01.abi);
assert.ok(gateI.getFunction("effectiveTier(address)"));
assert.ok(gateI.getFunction("requireEffectiveTier(address,uint8)"));
const ignitionI=new Interface(consumer.GFLOIgnitionV01.abi);
assert.ok(ignitionI.getFunction("ignite()"));
const sourceUnits=[["IXPPolicyTrustV02",["pie()","owner()","totalXP(address)"]],
["ICanonicalXPForIgnition",["pieCore()","totalXP(address)"]],
["IXPRegistryGate",["pieCore()","totalXP(address)"]]];
// Method signatures are checked against pinned consuming source declarations as well as compiled ABI.
const sourceTexts=Object.fromEntries(fixture.map(([file])=>[file,readFileSync(path.join(pieRoot,"contracts",file),"utf8")]));
assert.match(sourceTexts["TrustedXPSourceRegistryV02.sol"],/return IXPPolicyTrustV02\(source.policy\)\.totalXP\(user\)/);
assert.match(sourceTexts["EffectiveTierGateV01.sol"],/registry\.totalXP\(wallet\)/);
assert.match(sourceTexts["GFLOIgnitionV01.sol"],/canonicalXP\.totalXP\(msg.sender\)/);
const report={
 schemaVersion:1,scope:"IB-02F source ABI/full storage layout and pinned consumer interface only",
 compiler:solc.version(),baselineSHA256:digest(baseline),candidateSHA256:digest(candidate),
 baselineCreationBytes:base.evm.bytecode.object.length/2,candidateCreationBytes:next.evm.bytecode.object.length/2,
 candidateRuntimeBytes:next.evm.deployedBytecode.object.length/2,
 oldFunctionCount:oldFns.length,newFunctionCount:next.abi.filter(x=>x.type==="function").length,
 storageRootEntries:next.storageLayout.storage.length,
 grantsMembers:normalizer(next.storageLayout).find(x=>x.label==="grants")?.type?.value?.members?.map(x=>({label:x.label,slot:x.slot,offset:x.offset}))??[],
 compatibleConsumers:fixture.map(([_,c])=>c),selectors:{
 policyTotalXP:policyI.getFunction("totalXP(address)").selector,
 registryTotalXP:registryI.getFunction("totalXP(address)").selector
 },
 release:"BLOCK: deployment and all actual consumer decoders remain unverified"
};
assert.equal(report.selectors.policyTotalXP,report.selectors.registryTotalXP);
console.log("IB02F_COMPATIBILITY_PASS "+JSON.stringify(report));

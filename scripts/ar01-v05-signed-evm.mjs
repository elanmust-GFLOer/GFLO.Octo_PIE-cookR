// GFLO AR01-03 V04: REAL Safe v1.5 signed outer transactions + receipts.
// Local EthereumJS v10, synthetic private keys only. Not an external network/audit.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {execFileSync} from "node:child_process";
import {createRequire} from "node:module";
import {homedir} from "node:os";
import {join} from "node:path";
import {createVM,runTx} from "@ethereumjs/vm";
import {createLegacyTx} from "@ethereumjs/tx";
import {createBlock} from "@ethereumjs/block";
import {Common,Mainnet,Hardfork} from "@ethereumjs/common";
import {createAccount,createAddressFromPrivateKey,createAddressFromString,hexToBytes,bytesToHex} from "@ethereumjs/util";

const repo=join(homedir(),"gflo-pie"),req=createRequire(join(repo,"package.json"));
const localReq=createRequire(import.meta.url);
const solc=req("solc"),{Interface,Wallet,getCreateAddress,ZeroAddress,parseUnits,id,keccak256}=req("ethers");
const root=join(process.cwd(),"node_modules/@safe-global/safe-smart-account/build/artifacts/contracts");
const artifacts={
 safe:JSON.parse(fs.readFileSync(join(root,"Safe.sol/Safe.json"),"utf8")),
 factory:JSON.parse(fs.readFileSync(join(root,"proxies/SafeProxyFactory.sol/SafeProxyFactory.json"),"utf8"))
};
const files={"XPPolicyV05MultiSource.sol":"XPPolicyV05MultiSource","PIECoreIgnitionV01.sol":"PIECoreIgnitionV01","TrustedXPSourceRegistryV02.sol":"TrustedXPSourceRegistryV02","GFLOIgnitionV01.sol":"GFLOIgnitionV01","GFLOFixedSupplyV01.sol":"GFLOFixedSupplyV01","EffectiveTierGateV01.sol":"EffectiveTierGateV01"};
const sources=Object.fromEntries(Object.keys(files).filter(f=>f!=="XPPolicyV05MultiSource.sol").map(f=>[f,{content:execFileSync("git",["show","origin/feature/pie-core-v0.2:contracts/"+f],{cwd:repo,encoding:"utf8"})}]));
sources["XPPolicyV05MultiSource.sol"]={content:fs.readFileSync(join(process.cwd(),"contracts/XPPolicyV05MultiSource.sol"),"utf8")};
sources["GasFeeLoop.sol"]={content:fs.readFileSync(join(homedir(),"GasFeeLoop-/contracts/GasFeeLoop.sol"),"utf8")};
const ozRoot=path.dirname(localReq.resolve("@openzeppelin/contracts/package.json"));
const compiled=JSON.parse(solc.compile(JSON.stringify({language:"Solidity",sources,settings:{optimizer:{enabled:true,runs:200},evmVersion:"cancun",outputSelection:{"*":{"*":["abi","evm.bytecode.object"]}}}}),{import:(name)=>{
 try{
  if(!name.startsWith("@openzeppelin/contracts/"))return {error:"unexpected import "+name};
  const target=path.resolve(ozRoot,name.slice("@openzeppelin/contracts/".length));
  if(!target.startsWith(ozRoot+path.sep))return {error:"unsafe import"};
  return {contents:fs.readFileSync(target,"utf8")};
 }catch(e){return {error:String(e)};}
}}));
for(const e of compiled.errors??[])if(e.severity==="error")throw Error(e.formattedMessage);
for(const [f,n] of Object.entries(files))artifacts[({XPPolicyV05MultiSource:"xp",EffectiveTierGateV01:"gate",PIECoreIgnitionV01:"core",TrustedXPSourceRegistryV02:"registry",GFLOIgnitionV01:"ignition",GFLOFixedSupplyV01:"token"})[n]]=compiled.contracts[f][n];
artifacts.gas=compiled.contracts["GasFeeLoop.sol"].GasFeeLoop;
const abi=Object.fromEntries(Object.entries(artifacts).map(([k,v])=>[k,new Interface(v.abi)]));
const bytecode=k=>{const b=artifacts[k].bytecode?.object??artifacts[k].bytecode??artifacts[k].evm.bytecode.object;return b.startsWith("0x")?b:"0x"+b;};
const common=new Common({chain:Mainnet,hardfork:Hardfork.Cancun}),vm=await createVM({common});
const secret=c=>hexToBytes("0x"+c.repeat(32));
const keys={deployer:secret("a1"),relayer:secret("a2"),outsider:secret("a3"),alice:secret("a4"),verifier:secret("a5"),attestor:secret("a6"),issuer:secret("a8")};
const senders={};
for(const [name,key] of Object.entries(keys)){
 const address=createAddressFromPrivateKey(key);
 senders[name]={key,address,nonce:0n};
 await vm.stateManager.putAccount(address,createAccount({balance:10n**23n}));
}
const owners=["11","22","33"].map(c=>new Wallet("0x"+c.repeat(32)));
const TEST_GAS=22000000n,GAS_PRICE=2000000000n;
let activeTimestamp=1000n;
const atDay=day=>{ activeTimestamp=BigInt(day)*86400n+1000n; };
async function tx(name,to,data,status=1){
 const s=senders[name],before=s.nonce;
 const signed=createLegacyTx({nonce:before,gasLimit:TEST_GAS,gasPrice:GAS_PRICE,
   ...(to?{to:to.toString()}:{}),data:hexToBytes(data)},{common}).sign(s.key);
 const block=createBlock({header:{timestamp:activeTimestamp,gasLimit:30000000n}},{common});
 const out=await runTx(vm,{tx:signed,block});
 assert.equal(Number(out.receipt.status),status,"tx receipt status for "+name+" nonce "+before);
 assert.ok(out.totalGasSpent>21000n,"gas must be accounted");
 s.nonce++;
 assert.equal((await vm.stateManager.getAccount(s.address)).nonce,s.nonce,"outer nonce was not consumed");
 if(status===0)assert.equal(out.receipt.logs.length,0,"failed outer transaction emitted logs");
 return out;
}
async function deploy(name,k,args=[]){
 const s=senders[name],address=getCreateAddress({from:s.address.toString(),nonce:s.nonce});
 const receipt=await tx(name,null,bytecode(k)+abi[k].encodeDeploy(args).slice(2));
 assert.ok((await vm.stateManager.getCode(createAddressFromString(address))).length>0,"deployment runtime empty");
 return {address,receipt};
}
async function send(name,k,address,fn,args=[],status=1){
 return tx(name,address,abi[k].encodeFunctionData(fn,args),status);
}
async function read(k,address,fn,args=[]){
 const viewer=createAddressFromString("0x"+"fe".repeat(20));
 await vm.stateManager.checkpoint();
 try{
  const res=(await vm.evm.runCall({caller:viewer,to:createAddressFromString(address),
   isStatic:true,gasLimit:2000000n,data:hexToBytes(abi[k].encodeFunctionData(fn,args))})).execResult;
  if(res.exceptionError)throw Error("read "+k+"."+fn+": "+res.exceptionError.error);
  return abi[k].decodeFunctionResult(fn,bytesToHex(res.returnValue))[0];
 }finally{await vm.stateManager.revert();}
}
let n=0;const N=13;
async function check(title,fn){await fn();console.log("✅ "+(++n)+"/"+N+" "+title);}
console.log("=== GFLO AR01-03 — V05 MULTI-SOURCE SIGNED EVM REGRESSION ===");
console.log("Solc:",solc.version());
const singleton=(await deploy("deployer","safe")).address;
const factory=(await deploy("deployer","factory")).address;
const init=abi.safe.encodeFunctionData("setup",[owners.map(w=>w.address),2,ZeroAddress,"0x",ZeroAddress,ZeroAddress,0,ZeroAddress]);
// The SafeProxyFactory returns the deployed proxy through its ProxyCreation log;
// parse instead of assuming its CREATE2 address.
const created=await send("deployer","factory",factory,"createProxyWithNonce",[singleton,init,20261015n]);
const logs=created.receipt.logs;
let proxy;
for(const log of logs){
 try{
  const decoded=abi.factory.parseLog({topics:log[1].map(bytesToHex),data:bytesToHex(log[2])});
  if(decoded?.name==="ProxyCreation")proxy=decoded.args.proxy;
 }catch{}
}
assert.ok(proxy,"Missing official Safe ProxyCreation event");
const core=(await deploy("deployer","core",[proxy])).address;
const xp=(await deploy("deployer","xp",[core,proxy])).address;

const account=senders.alice.address.toString();
const verifierAddress=senders.verifier.address.toString();
const registry=(await deploy("deployer","registry",[core,proxy])).address;
const initialSupply=parseUnits("1000",18),tier1Fee=parseUnits("1",18);
const token=(await deploy("deployer","token",[account,initialSupply])).address;
const ignition=(await deploy("deployer","ignition",[core,registry,token,tier1Fee,2n*tier1Fee])).address;
const gate=(await deploy("deployer","gate",[core,registry])).address;
const gas=(await deploy("deployer","gas",[token,core])).address;
async function currentHash(target,data){
 return read("safe",proxy,"getTransactionHash",[target,0,data,0,0,0,0,ZeroAddress,ZeroAddress,await read("safe",proxy,"nonce")]);
}
function signatures(hash,who){
 return "0x"+who.map(w=>({addr:w.address.toLowerCase(),sig:w.signingKey.sign(hash).serialized.slice(2)}))
 .sort((a,b)=>a.addr.localeCompare(b.addr)).map(x=>x.sig).join("");
}
async function safeSubmit(target,data,who=[owners[0],owners[1]],status=1){
 const h=await currentHash(target,data);
 return send("relayer","safe",proxy,"execTransaction",[target,0,data,0,0,0,0,ZeroAddress,ZeroAddress,signatures(h,who)],status);
}
async function admin(k,target,fn,args=[]){
 const data=abi[k].encodeFunctionData(fn,args);
 const r=await safeSubmit(target,data);
 assert.ok(r.receipt.logs.some(l=>{try{return abi.safe.parseLog({topics:l[1].map(bytesToHex),data:bytesToHex(l[2])})?.name==="ExecutionSuccess"}catch{return false}}),
  "Missing Safe ExecutionSuccess event for "+k+"."+fn);
 return r;
}
async function state(){
 return {
  supply:await read("token",token,"totalSupply"),
  balance:await read("token",token,"balanceOf",[account]),
  allowance:await read("token",token,"allowance",[account,ignition]),
  tier:(await read("core",core,"getIdentity",[account])).tier,
  safeNonce:await read("safe",proxy,"nonce")
 };
}
async function rejectedIgnition(label,expected){
 const before=await state();
 const receipt=await send("alice","ignition",ignition,"ignite",[],0);
 const after=await state();
 assert.deepEqual(after,before,label+" mutated state on failed signed transaction");
 assert.equal(receipt.receipt.logs.length,0);
 if(expected)assert.equal(after.tier,expected);
}

const {Wallet: EthersWallet}=req("ethers");
const attestorWallet=new EthersWallet("0x"+"a6".repeat(32));
const attestor=senders.attestor.address.toString();
const issuerWallet=new EthersWallet("0x"+"a8".repeat(32));
const issuer=senders.issuer.address.toString();
const sourceId=id("GFLO_OCTOPUSH_SOURCE_01");
const rule=id("RT6C_UNVERIFIED_EVENT_RULE"),event=id("RT6C_FABRICATED_BUILDER_COMPLETION"),evidence=id("RT6C_FAKE_OFFCHAIN_EVIDENCE");
const proof=[account,rule,event,evidence,777n,0n,172800n];
let claimId;
async function sourceSignatureV05(p,source,wallet){const epoch=await read("xp",xp,"sources",[p[1],source]); /* epoch is second tuple element; read full result below */ return wallet.signingKey.sign(await sourceHash(p,source)).serialized;}
async function sourceHash(p,source){const viewer=createAddressFromString("0x"+"fe".repeat(20));const result=await vm.evm.runCall({caller:viewer,to:createAddressFromString(xp),isStatic:true,gasLimit:2000000n,data:hexToBytes(abi.xp.encodeFunctionData("sources",[p[1],source]))});if(result.execResult.exceptionError)throw Error("source config read");const cfg=abi.xp.decodeFunctionResult("sources",bytesToHex(result.execResult.returnValue));return read("xp",xp,"sourceDigest",[p,source,cfg[2]]);}
async function approval(p,source,wallet){const cfgCall=await vm.evm.runCall({caller:createAddressFromString("0x"+"fe".repeat(20)),to:createAddressFromString(xp),isStatic:true,gasLimit:2000000n,data:hexToBytes(abi.xp.encodeFunctionData("sources",[p[1],source]))});const cfg=abi.xp.decodeFunctionResult("sources",bytesToHex(cfgCall.execResult.returnValue));return [source,cfg[2],wallet.signingKey.sign(await read("xp",xp,"sourceDigest",[p,source,cfg[2]])).serialized];}
async function proofSignature(p=proof){const hash=await read("xp",xp,"proofDigest",[p]);return attestorWallet.signingKey.sign(hash).serialized;}
async function grantFromReceipt(receipt){
 for(const log of receipt.receipt.logs){
  try{const e=abi.xp.parseLog({topics:log[1].map(bytesToHex),data:bytesToHex(log[2])});if(e?.name==="GrantPending")return e.args.claimId;}catch{}
 }
 throw Error("Missing GrantPending receipt event");
}
async function rejected(k,address,fn,args=[],caller="outsider"){
 const before=await read("registry",registry,"totalXP",[account]);
 await send(caller,k,address,fn,args,0);
 assert.equal(await read("registry",registry,"totalXP",[account]),before);
}

const sourceB=id("GFLO_INDEPENDENT_SOURCE_02");
const groupA=id("CONTROL_GROUP_A"),groupB=id("CONTROL_GROUP_B");
const secondIssuer=new EthersWallet("0x"+"b1".repeat(32));
const p=[account,rule,id("V05_FICTIONAL_EVENT"),id("V05_FICTIONAL_EVIDENCE"),777n,0n,172800n];
await check("V05 Safe governance and identity bootstrap",async()=>{
 assert.equal(await read("safe",proxy,"getThreshold"),2n);
 assert.equal(await read("xp",xp,"owner"),proxy);
 await admin("core",core,"bindIgnition",[ignition]);
 await send("alice","core",core,"createIdentity",[3]);
 await admin("xp",xp,"setVerifierRole",[verifierAddress,2]);
 // Allow independent positive controls across the V05 adversarial scenarios; each still obeys daily/weekly caps.
 await admin("xp",xp,"registerRule",[rule,1000,6]);
 await admin("xp",xp,"setAttestor",[rule,attestor,true]);
 await admin("xp",xp,"configureSource",[rule,sourceId,issuer,groupA,true]);
 await admin("xp",xp,"configureSource",[rule,sourceB,secondIssuer.address,groupB,true]);
 assert.equal(await read("xp",xp,"validEarnedXP",[account]),0n);
});
await check("Single compromised issuer cannot mint XP or reserve quota",async()=>{
 const one=await approval(p,sourceId,issuerWallet);
 const duplicate=[one,one];
 const before=await read("xp",xp,"claimsPerRule",[account,rule]);
 await send("verifier","xp",xp,"submit",[p,attestor,await proofSignature(p),duplicate],0);
 assert.equal(await read("xp",xp,"claimsPerRule",[account,rule]),before);
 assert.equal(await read("xp",xp,"validEarnedXP",[account]),0n);
 assert.equal(await read("xp",xp,"usedEvents",[p[2]]),false);
});
await check("Different source IDs with identical issuer/control group fail closed",async()=>{
 await admin("xp",xp,"configureSource",[rule,sourceB,issuer,groupA,true]);
 const approvals=[await approval(p,sourceId,issuerWallet),await approval(p,sourceB,issuerWallet)].sort((a,b)=>a[0].localeCompare(b[0]));
 await send("verifier","xp",xp,"submit",[p,attestor,await proofSignature(p),approvals],0);
 assert.equal(await read("xp",xp,"claimsPerRule",[account,rule]),0n);
 await admin("xp",xp,"configureSource",[rule,sourceB,secondIssuer.address,groupB,true]);
});
let finalizedV05Claim;
await check("Valid independent 2-of-2 approvals finalize only after challenge",async()=>{
 const approvals=[await approval(p,sourceId,issuerWallet),await approval(p,sourceB,secondIssuer)].sort((a,b)=>a[0].localeCompare(b[0]));
 const receipt=await send("verifier","xp",xp,"submit",[p,attestor,await proofSignature(p),approvals]);
 const claim=await grantFromReceipt(receipt);
 finalizedV05Claim=claim;
 assert.equal(await read("xp",xp,"validEarnedXP",[account]),0n);
 await send("outsider","xp",xp,"finalize",[claim],0);
 atDay(4);
 await send("outsider","xp",xp,"finalize",[claim]);
 assert.equal(await read("xp",xp,"validEarnedXP",[account]),1000n);
});
await check("Rotation of second source blocks pending grant",async()=>{
 atDay(7);
 const p2=[account,rule,id("V05_PENDING_ROTATION_EVENT"),id("V05_PENDING_ROTATION_EVIDENCE"),778n,BigInt(activeTimestamp),BigInt(activeTimestamp)+86400n];
 const approvals=[await approval(p2,sourceId,issuerWallet),await approval(p2,sourceB,secondIssuer)].sort((a,b)=>a[0].localeCompare(b[0]));
 const receipt=await send("verifier","xp",xp,"submit",[p2,attestor,await proofSignature(p2),approvals]);
 const claim=await grantFromReceipt(receipt);
 await admin("xp",xp,"configureSource",[rule,sourceB,secondIssuer.address,groupB,false]);
 atDay(11);
 await send("outsider","xp",xp,"finalize",[claim],0);
 await admin("xp",xp,"configureSource",[rule,sourceB,secondIssuer.address,groupB,true]);
 await send("outsider","xp",xp,"finalize",[claim],0);
 assert.equal(await read("xp",xp,"validEarnedXP",[account]),1000n);
});
await check("AR01-05C: tampered evidence rejects both signatures without state mutation",async()=>{
 atDay(14);
 const original=[account,rule,id("V05_INTEGRITY_EVENT"),id("V05_INTEGRITY_EVIDENCE"),779n,BigInt(activeTimestamp),BigInt(activeTimestamp)+86400n];
 const mutated=[...original];
 mutated[3]=id("V05_TAMPERED_EVIDENCE");
 const signed=[await approval(original,sourceId,issuerWallet),await approval(original,sourceB,secondIssuer)].sort((a,b)=>a[0].localeCompare(b[0]));
 const beforeXP=await read("xp",xp,"validEarnedXP",[account]);
 const beforeClaims=await read("xp",xp,"claimsPerRule",[account,rule]);
 const day=activeTimestamp/86400n,week=activeTimestamp/(7n*86400n);
 const beforeDay=await read("xp",xp,"dailyXP",[account,day]);
 const beforeWeek=await read("xp",xp,"weeklyXP",[account,week]);
 await send("verifier","xp",xp,"submit",[mutated,attestor,await proofSignature(original),signed],0);
 assert.equal(await read("xp",xp,"validEarnedXP",[account]),beforeXP);
 assert.equal(await read("xp",xp,"claimsPerRule",[account,rule]),beforeClaims);
 assert.equal(await read("xp",xp,"dailyXP",[account,day]),beforeDay);
 assert.equal(await read("xp",xp,"weeklyXP",[account,week]),beforeWeek);
 assert.equal(await read("xp",xp,"usedEvents",[original[2]]),false);
 assert.equal(await read("xp",xp,"usedEvidence",[original[3]]),false);
 const receipt=await send("verifier","xp",xp,"submit",[original,attestor,await proofSignature(original),signed]);
 assert.ok(await grantFromReceipt(receipt));
 assert.equal(await read("xp",xp,"claimsPerRule",[account,rule]),beforeClaims+1n);
});
await check("AR01-05C: second source signs different evidence and cannot satisfy quorum",async()=>{
 atDay(21);
 const original=[account,rule,id("V05_SECOND_SOURCE_EVENT"),id("V05_SECOND_SOURCE_EVIDENCE"),780n,BigInt(activeTimestamp),BigInt(activeTimestamp)+86400n];
 const altered=[...original];altered[3]=id("V05_SECOND_SOURCE_DIFFERENT_EVIDENCE");
 const a=await approval(original,sourceId,issuerWallet);
 const b=await approval(altered,sourceB,secondIssuer);
 const mismatched=[a,b].sort((x,y)=>x[0].localeCompare(y[0]));
 const before=await read("xp",xp,"claimsPerRule",[account,rule]);
 await send("verifier","xp",xp,"submit",[original,attestor,await proofSignature(original),mismatched],0);
 assert.equal(await read("xp",xp,"claimsPerRule",[account,rule]),before);
 assert.equal(await read("xp",xp,"validEarnedXP",[account]),1000n);
 assert.equal(await read("xp",xp,"usedEvents",[original[2]]),false);
 const correct=[a,await approval(original,sourceB,secondIssuer)].sort((x,y)=>x[0].localeCompare(y[0]));
 const receipt=await send("verifier","xp",xp,"submit",[original,attestor,await proofSignature(original),correct]);
 assert.ok(await grantFromReceipt(receipt));
});
await check("AR01-05C: EIP-712 foreign contract domain rejects source approval",async()=>{
 atDay(28);
 const original=[account,rule,id("V05_FOREIGN_DOMAIN_EVENT"),id("V05_FOREIGN_DOMAIN_EVIDENCE"),781n,BigInt(activeTimestamp),BigInt(activeTimestamp)+86400n];
 const sourceA=await approval(original,sourceId,issuerWallet);
 const sourceCfg=await read("xp",xp,"sources",[rule,sourceB]);
 const cfgCall=await vm.evm.runCall({caller:createAddressFromString("0x"+"fe".repeat(20)),to:createAddressFromString(xp),isStatic:true,gasLimit:2000000n,data:hexToBytes(abi.xp.encodeFunctionData("sources",[rule,sourceB]))});
 const cfg=abi.xp.decodeFunctionResult("sources",bytesToHex(cfgCall.execResult.returnValue));
 const xpOther=(await deploy("deployer","xp",[core,proxy])).address;
 const foreignHash=await read("xp",xpOther,"sourceDigest",[original,sourceB,cfg[2]]);
 const foreignApproval=[sourceB,cfg[2],secondIssuer.signingKey.sign(foreignHash).serialized];
 const approvals=[sourceA,foreignApproval].sort((x,y)=>x[0].localeCompare(y[0]));
 const before=await read("xp",xp,"claimsPerRule",[account,rule]);
 await send("verifier","xp",xp,"submit",[original,attestor,await proofSignature(original),approvals],0);
 assert.equal(await read("xp",xp,"claimsPerRule",[account,rule]),before);
 assert.equal(await read("xp",xp,"usedEvents",[original[2]]),false);
 const valid=[sourceA,await approval(original,sourceB,secondIssuer)].sort((x,y)=>x[0].localeCompare(y[0]));
 assert.ok(await grantFromReceipt(await send("verifier","xp",xp,"submit",[original,attestor,await proofSignature(original),valid])));
});
await check("AR01-05D: foreign chainId source signature rejected with no quota or nullifier mutation",async()=>{
 atDay(35);
 const original=[account,rule,id("V05_FOREIGN_CHAIN_EVENT"),id("V05_FOREIGN_CHAIN_EVIDENCE"),782n,BigInt(activeTimestamp),BigInt(activeTimestamp)+86400n];
 const cfgCall=await vm.evm.runCall({caller:createAddressFromString("0x"+"fe".repeat(20)),to:createAddressFromString(xp),isStatic:true,gasLimit:2000000n,data:hexToBytes(abi.xp.encodeFunctionData("sources",[rule,sourceB]))});
 const cfg=abi.xp.decodeFunctionResult("sources",bytesToHex(cfgCall.execResult.returnValue));
 const {TypedDataEncoder}=req("ethers");
 const types={GFLOSourceApproval:[
  {name:"sourceId",type:"bytes32"},{name:"recipient",type:"address"},{name:"ruleId",type:"bytes32"},
  {name:"eventId",type:"bytes32"},{name:"evidenceDigest",type:"bytes32"},{name:"nonce",type:"uint256"},
  {name:"issuedAt",type:"uint64"},{name:"validUntil",type:"uint64"},{name:"epoch",type:"uint64"}]};
 const domain={name:"GFLO XP Evidence",version:"5",chainId:2,verifyingContract:xp};
 const value={sourceId:sourceB,recipient:original[0],ruleId:original[1],eventId:original[2],evidenceDigest:original[3],nonce:original[4],issuedAt:original[5],validUntil:original[6],epoch:cfg[2]};
 const foreignHash=TypedDataEncoder.hash(domain,types,value);
 assert.notEqual(foreignHash,await read("xp",xp,"sourceDigest",[original,sourceB,cfg[2]]));
 const foreign=[sourceB,cfg[2],secondIssuer.signingKey.sign(foreignHash).serialized];
 const approvals=[await approval(original,sourceId,issuerWallet),foreign].sort((a,b)=>a[0].localeCompare(b[0]));
 const before=await read("xp",xp,"claimsPerRule",[account,rule]);
 await send("verifier","xp",xp,"submit",[original,attestor,await proofSignature(original),approvals],0);
 assert.equal(await read("xp",xp,"claimsPerRule",[account,rule]),before);
 assert.equal(await read("xp",xp,"usedEvents",[original[2]]),false);
 assert.equal(await read("xp",xp,"usedEvidence",[original[3]]),false);
 assert.equal(await read("xp",xp,"validEarnedXP",[account]),1000n);
});
await check("AR01-05D: Safe codehash-pins V05 in Registry and TierGate reads canonical XP",async()=>{
 assert.equal(await read("registry",registry,"paused"),true);
 await send("outsider","registry",registry,"proposePolicy",[xp,id("INVALID_CODEHASH"),proxy],0);
 const code=await vm.stateManager.getCode(createAddressFromString(xp));
 const hash=keccak256(bytesToHex(code));
 await admin("registry",registry,"proposePolicy",[xp,hash,proxy]);
 await admin("registry",registry,"activatePolicy");
 await send("outsider","registry",registry,"setPaused",[false],0);
 await admin("registry",registry,"setPaused",[false]);
 assert.equal(await read("xp",xp,"totalXP",[account]),1025n);
 assert.equal(await read("registry",registry,"totalXP",[account]),1025n);
 assert.equal(await read("gate",gate,"effectiveTier",[account]),0n);
 await admin("registry",registry,"setPaused",[true]);
 await send("outsider","gate",gate,"effectiveTier",[account],0);
 await admin("registry",registry,"setPaused",[false]);
 assert.equal(await read("registry",registry,"totalXP",[account]),1025n);
});
await check("AR01-05E: real signed Tier 1 ignition burns GFLO against V05 canonical XP",async()=>{
 assert.equal(await read("registry",registry,"totalXP",[account]),1025n);
 assert.equal(await read("gate",gate,"effectiveTier",[account]),0n);
 const before=await read("token",token,"totalSupply");
 await send("alice","token",token,"approve",[ignition,tier1Fee]);
 assert.equal(await read("token",token,"allowance",[account,ignition]),tier1Fee);
 await send("alice","ignition",ignition,"ignite");
 assert.equal((await read("core",core,"getIdentity",[account])).tier,1n);
 assert.equal(await read("gate",gate,"effectiveTier",[account]),1n);
 assert.equal(await read("token",token,"totalSupply"),before-tier1Fee);
});
await check("AR01-05E: Safe revocation drops effective tier, preserves achieved tier and burn",async()=>{
 const before=await read("token",token,"totalSupply");
 await admin("xp",xp,"revoke",[finalizedV05Claim,id("V05_REVOKED_FRAUD")]);
 assert.equal(await read("xp",xp,"validEarnedXP",[account]),0n);
 assert.equal(await read("registry",registry,"totalXP",[account]),25n);
 assert.equal((await read("core",core,"getIdentity",[account])).tier,1n);
 assert.equal(await read("gate",gate,"effectiveTier",[account]),0n);
 await send("outsider","gate",gate,"requireEffectiveTier",[account,1],0);
 assert.equal(await read("token",token,"totalSupply"),before);
});
await check("AR01-05E: governance emergency pause blocks V05 submit and Registry canonical reads",async()=>{
 atDay(42);
 const p3=[account,rule,id("V05_EMERGENCY_EVENT"),id("V05_EMERGENCY_EVIDENCE"),783n,BigInt(activeTimestamp),BigInt(activeTimestamp)+86400n];
 const approvals=[await approval(p3,sourceId,issuerWallet),await approval(p3,sourceB,secondIssuer)].sort((a,b)=>a[0].localeCompare(b[0]));
 await send("outsider","xp",xp,"setPaused",[true],0);
 await admin("xp",xp,"setPaused",[true]);
 const before=await read("xp",xp,"claimsPerRule",[account,rule]);
 await send("verifier","xp",xp,"submit",[p3,attestor,await proofSignature(p3),approvals],0);
 assert.equal(await read("xp",xp,"claimsPerRule",[account,rule]),before);
 await admin("registry",registry,"setPaused",[true]);
 await assert.rejects(()=>read("registry",registry,"totalXP",[account]));
 await assert.rejects(()=>read("gate",gate,"effectiveTier",[account]));
 await admin("registry",registry,"setPaused",[false]);
 await admin("xp",xp,"setPaused",[false]);
 assert.equal(await read("registry",registry,"totalXP",[account]),25n);
 assert.equal(await read("gate",gate,"effectiveTier",[account]),0n);
});
assert.equal(n,N);
console.log("13/13 V05 SIGNED EVM RED TEAM EXECUTED");
console.log("Scope: signer independence only; real-world evidence truth and collusion remain out of scope.");

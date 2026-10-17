// GFLO RED TEAM 2A: REAL Safe v1.5 signed outer transactions + receipts.
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
const files={"XPPolicyV03.sol":"XPPolicyV03","PIECoreIgnitionV01.sol":"PIECoreIgnitionV01","TrustedXPSourceRegistryV02.sol":"TrustedXPSourceRegistryV02","GFLOIgnitionV01.sol":"GFLOIgnitionV01","GFLOFixedSupplyV01.sol":"GFLOFixedSupplyV01","EffectiveTierGateV01.sol":"EffectiveTierGateV01"};
const sources=Object.fromEntries(Object.keys(files).map(f=>[f,{content:execFileSync("git",["show","origin/feature/pie-core-v0.2:contracts/"+f],{cwd:repo,encoding:"utf8"})}]));
sources["GFLOSourceBoundAttestorV01.sol"]={content:fs.readFileSync(join(homedir(),"GFLO.Octo_PIE-cookR/contracts/GFLOSourceBoundAttestorV01.sol"),"utf8")};
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
for(const [f,n] of Object.entries(files))artifacts[({XPPolicyV03:"xp",EffectiveTierGateV01:"gate",PIECoreIgnitionV01:"core",TrustedXPSourceRegistryV02:"registry",GFLOIgnitionV01:"ignition",GFLOFixedSupplyV01:"token"})[n]]=compiled.contracts[f][n];
artifacts.bound=compiled.contracts["GFLOSourceBoundAttestorV01.sol"].GFLOSourceBoundAttestorV01;
const abi=Object.fromEntries(Object.entries(artifacts).map(([k,v])=>[k,new Interface(v.abi)]));
const bytecode=k=>{const b=artifacts[k].bytecode?.object??artifacts[k].bytecode??artifacts[k].evm.bytecode.object;return b.startsWith("0x")?b:"0x"+b;};
const common=new Common({chain:Mainnet,hardfork:Hardfork.Cancun}),vm=await createVM({common});
const secret=c=>hexToBytes("0x"+c.repeat(32));
const keys={deployer:secret("a1"),relayer:secret("a2"),outsider:secret("a3"),alice:secret("a4"),verifier:secret("a5"),attestor:secret("a6")};
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
  const block=createBlock({header:{timestamp:activeTimestamp,gasLimit:30000000n}},{common});
  const res=(await vm.evm.runCall({caller:viewer,to:createAddressFromString(address),
   block,isStatic:true,gasLimit:2000000n,data:hexToBytes(abi[k].encodeFunctionData(fn,args))})).execResult;
  if(res.exceptionError)throw Error("read "+k+"."+fn+": "+res.exceptionError.error);
  return abi[k].decodeFunctionResult(fn,bytesToHex(res.returnValue))[0];
 }finally{await vm.stateManager.revert();}
}
let n=0;const N=9;
async function check(title,fn){await fn();console.log("✅ "+(++n)+"/"+N+" "+title);}
console.log("=== GFLO RED TEAM 6D.5 — SOURCE BOUND ERC-1271 ATTESTOR ===");
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
const bound=(await deploy("deployer","bound",[proxy])).address;
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
const rule=id("RT6D5_BUILDER_COMPLETION_1000"),event=id("RT6D5_SOURCE_ISSUED_EVENT"),evidence=id("RT6D5_SOURCE_REVIEW_EVIDENCE");
const proof=[account,rule,event,evidence,777n,0n,172800n];
let claimId;
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

const sourceIssuer=new Wallet("0x"+"a7".repeat(32));
const forgedIssuer=new Wallet("0x"+"a8".repeat(32));
const maliciousAttestor=new Wallet("0x"+"a9".repeat(32));
const sourceDomain={name:"GFLO Source Authorization",version:"1",chainId:1,verifyingContract:bound};
const sourceTypes={SourceAuthorization:[
 {name:"proofDigest",type:"bytes32"},
 {name:"sourceEventKey",type:"bytes32"},
 {name:"validUntil",type:"uint64"}
]};
async function sourceSignature(digest,key,validUntil,signer=sourceIssuer){
 return signer.signTypedData(sourceDomain,sourceTypes,{proofDigest:digest,sourceEventKey:key,validUntil});
}
async function auth(digest,key,validUntil,signer=sourceIssuer,status=1){
 const sig=await sourceSignature(digest,key,validUntil,signer);
 return send("outsider","bound",bound,"registerApproval",[digest,key,validUntil,sourceIssuer.address,sig],status);
}
async function rejectedProof(proofData,signer=bound,sig="0x",who="verifier"){
 const before=await read("registry",registry,"totalXP",[account]);
 await send(who,"xp",xp,"submit",[proofData,signer,sig],0);
 assert.equal(await read("registry",registry,"totalXP",[account]),before);
}
const sigMagic="0x1626ba7e",sigInvalid="0xffffffff";
const proofDigest=await read("xp",xp,"proofDigest",[proof]);
const eventKey=id("RT6D5_SOURCE_EVENT_ORIGIN_1");
const approvalExpiry=6000n; // claimId declared in shared fixture

await check("RT6D5-01 Safe config: 2/3, XPPolicy fresh, only source-bound attestor authorized",async()=>{
 assert.equal(await read("safe",proxy,"getThreshold"),2n);
 assert.equal(await read("xp",xp,"owner"),proxy);
 await admin("core",core,"bindIgnition",[ignition]);
 const policyCode=await vm.stateManager.getCode(createAddressFromString(xp));
 await admin("registry",registry,"proposePolicy",[xp,keccak256(bytesToHex(policyCode)),proxy]);
 await admin("registry",registry,"activatePolicy");
 await admin("registry",registry,"setPaused",[false]);
 await send("alice","core",core,"createIdentity",[3]);
 await admin("xp",xp,"registerRule",[rule,1000,4]);
 await admin("xp",xp,"setVerifierRole",[verifierAddress,2]);
 await admin("bound",bound,"setIssuer",[sourceIssuer.address,true]);
 await admin("xp",xp,"setAttestor",[rule,bound,true]);
 assert.equal(await read("xp",xp,"ruleAttestors",[rule,bound]),true);
 assert.equal(await read("xp",xp,"ruleAttestors",[rule,maliciousAttestor.address]),false);
 assert.equal(await read("registry",registry,"totalXP",[account]),25n);
});

await check("RT6D5-02 fabricated direct XP with no source authorization reverts",async()=>{
 await rejectedProof(proof);
 await rejectedProof(proof,maliciousAttestor.address,await proofSignature());
 assert.equal(await read("bound",bound,"isValidSignature",[proofDigest,"0x"]),sigInvalid);
});

await check("RT6D5-03 unauthorized source issuer cannot register a forged approval",async()=>{
 await auth(proofDigest,eventKey,approvalExpiry,forgedIssuer,0);
 assert.equal(await read("bound",bound,"consumedEventKeys",[eventKey]),false);
 assert.equal(await read("bound",bound,"isValidSignature",[proofDigest,"0x"]),sigInvalid);
});

await check("RT6D5-04 genuine issuer approval makes exact digest ERC-1271 valid; replay blocked",async()=>{
 await auth(proofDigest,eventKey,approvalExpiry);
 assert.equal(await read("bound",bound,"consumedEventKeys",[eventKey]),true);
 assert.equal(await read("bound",bound,"isValidSignature",[proofDigest,"0x"]),sigMagic);
 const other=[...proof];other[4]=999n;
 const otherDigest=await read("xp",xp,"proofDigest",[other]);
 assert.equal(await read("bound",bound,"isValidSignature",[otherDigest,"0x"]),sigInvalid);
 await auth(otherDigest,eventKey,approvalExpiry,sourceIssuer,0);
 await rejectedProof(other);
});

await check("RT6D5-05 permitted verifier submits source-approved claim PENDING; replay rejected",async()=>{
 const receipt=await send("verifier","xp",xp,"submit",[proof,bound,"0x"]);
 claimId=await grantFromReceipt(receipt);
 assert.equal(await read("xp",xp,"validEarnedXP",[account]),0n);
 assert.equal(await read("registry",registry,"totalXP",[account]),25n);
 await rejectedProof(proof);
});

await check("RT6D5-06 authorized source expiry, pause and governance revoke fail closed",async()=>{
 const second=[account,rule,id("RT6D5_NEW_SOURCE"),id("RT6D5_NEW_EVIDENCE"),778n,0n,500000n];
 const secondDigest=await read("xp",xp,"proofDigest",[second]);
 await auth(secondDigest,id("RT6D5_SECOND_KEY"),approvalExpiry);
 assert.equal(await read("bound",bound,"isValidSignature",[secondDigest,"0x"]),sigMagic);
 await admin("bound",bound,"setPaused",[true]);
 assert.equal(await read("bound",bound,"isValidSignature",[secondDigest,"0x"]),sigInvalid);
 await admin("bound",bound,"setPaused",[false]);
 await admin("bound",bound,"revoke",[secondDigest]);
 assert.equal(await read("bound",bound,"isValidSignature",[secondDigest,"0x"]),sigInvalid);
 await rejectedProof(second);
 atDay(3);
 assert.equal(await read("bound",bound,"isValidSignature",[proofDigest,"0x"]),sigInvalid);
 await send("outsider","xp",xp,"finalize",[claimId]);
 assert.equal(await read("registry",registry,"totalXP",[account]),1025n);
});

await check("RT6D5-07 after finalize authorized grant permits signed Tier 1 burn",async()=>{
 await send("alice","token",token,"approve",[ignition,tier1Fee]);
 await send("alice","ignition",ignition,"ignite");
 assert.equal((await read("core",core,"getIdentity",[account])).tier,1n);
 assert.equal(await read("gate",gate,"effectiveTier",[account]),1n);
 assert.equal(await read("token",token,"totalSupply"),initialSupply-tier1Fee);
});

await check("RT6D5-08 HIGH FINDING: Safe can authorize alternative EOA attestor bypassing source gate",async()=>{
 await admin("xp",xp,"setAttestor",[rule,maliciousAttestor.address,true]);
 const fake=[account,rule,id("RT6D5_FALSE_EVENT"),id("RT6D5_FALSE_EVIDENCE"),844n,
   BigInt(activeTimestamp),BigInt(activeTimestamp)+86400n];
 const fakeDigest=await read("xp",xp,"proofDigest",[fake]);
 const fakeSignature=maliciousAttestor.signingKey.sign(fakeDigest).serialized;
 const before=await read("registry",registry,"totalXP",[account]);
 const receipt=await send("verifier","xp",xp,"submit",[fake,maliciousAttestor.address,fakeSignature]);
 const fakeClaim=await grantFromReceipt(receipt);
 assert.ok(fakeClaim);
 assert.equal(await read("registry",registry,"totalXP",[account]),before,"pending bypass claim is not canonical yet");
 console.log("  HIGH OPEN: governance-authorized EOA attestor bypasses SourceBoundAttestor; source truth not established.");
});

await check("RT6D5-09 Safe revocation and Registry pause still fail closed",async()=>{
 await admin("xp",xp,"revoke",[claimId,id("RT6D5_GOVERNANCE_REVOCATION")]);
 assert.equal(await read("registry",registry,"totalXP",[account]),25n);
 assert.equal((await read("core",core,"getIdentity",[account])).tier,1n);
 assert.equal(await read("gate",gate,"effectiveTier",[account]),0n);
 await send("outsider","gate",gate,"requireEffectiveTier",[account,1],0);
 await admin("registry",registry,"setPaused",[true]);
 await send("outsider","gate",gate,"requireEffectiveTier",[account,1],0);
});
assert.equal(n,N);
console.log("RED TEAM 6D.5 — 9/9 local signed EVM scenarios executed.");
console.log("RT6C HIGH remains OPEN: source issuer can attest fiction and Safe can authorize alternate attestor; no audit or deployment.");

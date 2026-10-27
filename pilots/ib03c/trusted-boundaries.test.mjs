import {test} from "node:test";
import assert from "node:assert/strict";
import {createTrustedIdentityBoundary,createTrustedRpcBoundary} from "./trusted-boundaries.mjs";
const A=x=>"0x"+x.repeat(40),H=x=>"0x"+x.repeat(64);
const pins={chainId:"11155111",core:A("1"),registry:A("2"),policy:A("3"),owner:A("4"),coreHash:H("a"),registryHash:H("b"),policyHash:H("c"),abiSha256:H("d"),maxAgeSeconds:300};
function rpcFixture(){
 const p={...pins};let t=1000,network="0xaa36a7",blockHash=H("f"),blockTime=900;
 let finality={finalized:true,hash:blockHash,number:42,timestamp:blockTime},badCode=false,badPolicy=false,wrongBlock=false,wrongChain=false;
 const requests=[];
 const encode=(sig,args)=>"0x"+Buffer.from(JSON.stringify([sig,args])).toString("hex");
 const decodeRaw=hex=>JSON.parse(Buffer.from(hex.slice(2),"hex").toString());
 const transport={send:async(method,params)=>{
  requests.push({method,params});
  if(method==="eth_chainId")return wrongChain?"0x1":network;
  if(method==="eth_getBlockByHash")return {hash:wrongBlock?H("e"):blockHash,number:"0x2a",timestamp:"0x384"};
  if(method==="eth_getCode")return badCode?"0x90":"0x6080"+params[0].slice(2);
  const [sig,args]=decodeRaw(params[0].data);
  const result=Object.hasOwn({ "paused()":1,"activeSource()":1,"pieCore()":1,"pie()":1,"owner()":1,"totalXP(address)":1},sig)?
  sig==="paused()"?false:sig==="activeSource()"?{policy:badPolicy?A("7"):p.policy,runtimeCodehash:p.policyHash,policyOwner:p.owner}:
  sig==="pieCore()"||sig==="pie()"?p.core:sig==="owner()"?p.owner:"123":null;
  return "0x"+Buffer.from(JSON.stringify(result)).toString("hex");
 }};
 const codec={encode,decode:(sig,value)=>decodeRaw(value),abiSha256:async()=>p.abiSha256};
 const crypto={keccak256:async code=>code==="0x90"?H("e"):code.includes(p.core.slice(2))?p.coreHash:code.includes(p.registry.slice(2))?p.registryHash:p.policyHash};
 const args={transport,finality:{checkpoint:async()=>finality},codec,crypto,pins:p,clock:()=>t};
 return {args,requests,set:{badCode:x=>badCode=x,badPolicy:x=>badPolicy=x,wrongBlock:x=>wrongBlock=x,wrongChain:x=>wrongChain=x,
 finality:x=>finality=x,time:x=>t=x}};
}
async function rejects(f,expected){await assert.rejects(f,new RegExp("IB03C_"+expected))};
test("snapshot uses EIP-1898 blockHash for every eth_getCode and eth_call",async()=>{
 const x=rpcFixture(),reader=await createTrustedRpcBoundary(x.args).read();
 assert.equal(await reader.totalXp(A("5")),"123");
 const pinned=x.requests.filter(a=>["eth_getCode","eth_call"].includes(a.method));
 assert.equal(pinned.length,10);
 for(const q of pinned)assert.deepEqual(q.params.at(-1),{blockHash:H("f"),requireCanonical:true});
});
test("chain mismatch is fatal",async()=>{const x=rpcFixture();x.set.wrongChain(true);await rejects(()=>createTrustedRpcBoundary(x.args).read(),"CHAIN")});
test("finality false is fatal",async()=>{const x=rpcFixture();x.set.finality({finalized:false,hash:H("f"),number:42,timestamp:900});await rejects(()=>createTrustedRpcBoundary(x.args).read(),"FINALITY")});
test("stale finalized block fails",async()=>{const x=rpcFixture();x.set.time(1301);await rejects(()=>createTrustedRpcBoundary(x.args).read(),"STALE_BLOCK")});
test("RPC returned other block fails",async()=>{const x=rpcFixture();x.set.wrongBlock(true);await rejects(()=>createTrustedRpcBoundary(x.args).read(),"BLOCK_INTEGRITY")});
test("runtime Keccak mismatch fails",async()=>{const x=rpcFixture();x.set.badCode(true);await rejects(()=>createTrustedRpcBoundary(x.args).read(),"CODEHASH")});
test("unauthorized policy fails",async()=>{const x=rpcFixture();x.set.badPolicy(true);await rejects(()=>createTrustedRpcBoundary(x.args).read(),"UNTRUSTED_POLICY")});
test("request allowlist rejects mutation methods",async()=>{const x=rpcFixture();await createTrustedRpcBoundary(x.args).read();assert.equal(x.requests.some(r=>["eth_sendTransaction","eth_sendRawTransaction"].includes(r.method)),false)});
function idFixture(){
 let now=1000,session={assurance:"SIWE_VERIFIED",subject:"synthetic",wallet:A("5"),domain:"example.test",chainId:"11155111",nonceConsumed:true,verifiedAt:990,expiresAt:1300,generation:1};
 let binding={wallet:A("5"),chainId:"11155111",status:"ACTIVE",bindingGeneration:1,consent:{revoked:false,scopes:["pie:xp:read"],expiresAt:1300,generation:1}};
 const args={sessions:{current:async()=>session},ledger:{bindingSnapshot:async()=>binding},clock:()=>now,policy:{domain:"example.test",chainId:"11155111",maxSessionSeconds:300}};
 return {args,set:{session:x=>session=x,binding:x=>binding=x,time:x=>now=x}};
}
test("server-attested SIWE session and consent grant read-only binding",async()=>{const x=idFixture(),b=createTrustedIdentityBoundary(x.args);assert.equal((await b.session()).authenticated,true);assert.equal((await b.binding("synthetic","11155111")).wallet,A("5"))});
test("client self-assertion without consumed SIWE nonce rejected",async()=>{const x=idFixture();x.set.session({...await x.args.sessions.current(),nonceConsumed:false});await rejects(()=>createTrustedIdentityBoundary(x.args).session(),"SIWE_SESSION")});
test("wrong SIWE origin denied",async()=>{const x=idFixture();x.set.session({...await x.args.sessions.current(),domain:"evil.test"});await rejects(()=>createTrustedIdentityBoundary(x.args).session(),"SIWE_SESSION")});
test("session expiry denied",async()=>{const x=idFixture();x.set.time(1300);await rejects(()=>createTrustedIdentityBoundary(x.args).session(),"SIWE_SESSION")});
test("wallet mismatch ledger denied",async()=>{const x=idFixture();x.set.binding({...await x.args.ledger.bindingSnapshot(),wallet:A("6")});await rejects(()=>createTrustedIdentityBoundary(x.args).binding("synthetic","11155111"),"BINDING_CONSENT")});
test("consent revocation denied",async()=>{const x=idFixture();const b=await x.args.ledger.bindingSnapshot();x.set.binding({...b,consent:{...b.consent,revoked:true}});await rejects(()=>createTrustedIdentityBoundary(x.args).binding("synthetic","11155111"),"BINDING_CONSENT")});
test("wrong user subject denied",async()=>{const x=idFixture();await rejects(()=>createTrustedIdentityBoundary(x.args).binding("another","11155111"),"IDENTITY_SCOPE")});
test("invalid injected RPC port rejected",async()=>{const x=rpcFixture();x.args.codec={};assert.throws(()=>createTrustedRpcBoundary(x.args),/IB03C_UNTRUSTED_PORT/)});

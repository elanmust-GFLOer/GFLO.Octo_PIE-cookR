import {test} from "node:test";
import assert from "node:assert/strict";
import {readOctoPassPie} from "./octopass-reader.mjs";
const A=n=>"0x"+n.repeat(40),H=n=>"0x"+n.repeat(64);
const pins={chainId:"11155111",core:A("1"),registry:A("2"),policy:A("3"),owner:A("4"),
 hashes:{core:H("a"),registry:H("b"),policy:H("c")},abiSha256:H("d"),
 sourceCommit:"1".repeat(40),maxAgeSeconds:300};
function fixture(){
 let t=1000, consent={revoked:false,scopes:["pie:xp:read"],expiresAt:2000,generation:1};
 let binding={status:"ACTIVE",wallet:A("5"),chainId:pins.chainId,bindingGeneration:1,consent};
 let session={authenticated:true,subject:"synthetic-subject"};
 let state={paused:false,core:pins.core,activePolicy:pins.policy,activePolicyHash:pins.hashes.policy,policyOwner:pins.owner};
 let policy={paused:false,core:pins.core,owner:pins.owner};
 let xp=123n,network=pins.chainId,block={number:42n,hash:H("f"),timestamp:950,finalized:true};
 let failure=false,hashGood=true,abiGood=true,afterRead=()=>{};
 const identity={session:async()=>session,binding:async()=>binding};
 const chain={chainId:async()=>network,finalized:async()=>block,
 runtime:async(a,b)=>{assert.equal(b,block.hash);return a;},
 abiHash:async()=>abiGood?pins.abiSha256:H("e"),
 registryState:async()=>state,policyState:async()=>policy,
 totalXp:async()=>{await afterRead();if(failure)throw Error("rpc");return xp;}};
 const args={pins,identity,chain,clock:()=>t,
 codehash:async runtime=>hashGood?runtime===pins.core?pins.hashes.core:runtime===pins.registry?pins.hashes.registry:pins.hashes.policy:H("e")};
 return {args,set:{clock:x=>t=x,consent:x=>{consent=x;binding={...binding,consent};},
 binding:x=>binding=x,session:x=>session=x,network:x=>network=x,
 registry:x=>state=x,policy:x=>policy=x,xp:x=>xp=x,block:x=>block=x,
 failure:x=>failure=x,codehash:x=>hashGood=x,abi:x=>abiGood=x,
 afterRead:x=>afterRead=x}};
}
const execute=async(f,mutate)=>{const q=fixture();mutate?.(q);return readOctoPassPie(q.args)};
test("happy path is explicitly MOCK_VERIFIED and read only",async()=>{
 const q=fixture();const s=await readOctoPassPie(q.args);
 assert.equal(s.status,"MOCK_VERIFIED");assert.equal(s.canonicalXp,"123");
 assert.equal(s.nonAuthoritative,true);assert.equal(s.blockHash,H("f"));
});
test("missing session denies",async()=>assert.equal((await execute(null,q=>q.set.session(null))).status,"NOT_VERIFIED"));
test("revoked consent denies",async()=>assert.equal((await execute(null,q=>q.set.consent({revoked:true,scopes:["pie:xp:read"],expiresAt:2000,generation:1}))).status,"NOT_VERIFIED"));
test("missing scope denies",async()=>assert.equal((await execute(null,q=>q.set.consent({revoked:false,scopes:[],expiresAt:2000,generation:1}))).status,"NOT_VERIFIED"));
test("expired consent denies",async()=>assert.equal((await execute(null,q=>q.set.clock(2000))).reason,"BINDING_OR_CONSENT_INVALID"));
test("wrong wallet binding chain denies",async()=>{const q=fixture();q.set.binding({...await q.args.identity.binding(),chainId:"1"});assert.equal((await readOctoPassPie(q.args)).reason,"CHAIN_MISMATCH")});
test("wrong network denies",async()=>assert.equal((await execute(null,q=>q.set.network("1"))).reason,"CHAIN_MISMATCH"));
test("unfinalized observation denies",async()=>assert.equal((await execute(null,q=>q.set.block({number:42n,hash:H("f"),timestamp:950,finalized:false}))).status,"UNAVAILABLE"));
test("stale observation denies",async()=>assert.equal((await execute(null,q=>q.set.block({number:42n,hash:H("f"),timestamp:600,finalized:true}))).status,"UNAVAILABLE"));
test("runtime hash mismatch denies",async()=>assert.equal((await execute(null,q=>q.set.codehash(false))).reason,"CODEHASH_MISMATCH"));
test("ABI mismatch denies",async()=>assert.equal((await execute(null,q=>q.set.abi(false))).reason,"ABI_MISMATCH"));
test("registry pause fails closed",async()=>{const q=fixture();q.set.registry({paused:true});assert.equal((await readOctoPassPie(q.args)).status,"UNAVAILABLE")});
test("policy pause fails closed",async()=>{const q=fixture();q.set.policy({paused:true});assert.equal((await readOctoPassPie(q.args)).status,"UNAVAILABLE")});
test("unapproved active policy denies",async()=>{const q=fixture();q.set.registry({paused:false,core:pins.core,activePolicy:A("6"),activePolicyHash:pins.hashes.policy,policyOwner:pins.owner});assert.equal((await readOctoPassPie(q.args)).reason,"UNAPPROVED_SOURCE")});
test("uint64 overflow denies",async()=>assert.equal((await execute(null,q=>q.set.xp(1n<<64n))).reason,"INVALID_XP"));
test("dependency error denies",async()=>assert.equal((await execute(null,q=>q.set.failure(true))).status,"UNAVAILABLE"));
test("binding revocation during RPC read denies",async()=>{const q=fixture();q.set.afterRead(async()=>q.set.consent({revoked:true,scopes:["pie:xp:read"],expiresAt:2000,generation:2}));assert.equal((await readOctoPassPie(q.args)).reason,"STALE_AUTHORIZATION")});
test("wallet swap during RPC read denies",async()=>{const q=fixture();q.set.afterRead(async()=>q.set.binding({...await q.args.identity.binding(),wallet:A("7"),bindingGeneration:2}));assert.equal((await readOctoPassPie(q.args)).reason,"STALE_AUTHORIZATION")});
test("session disappears during RPC read denies",async()=>{const q=fixture();let n=0;q.args.identity.session=async()=>++n===1?{authenticated:true,subject:"synthetic-subject"}:null;assert.equal((await readOctoPassPie(q.args)).reason,"STALE_AUTHORIZATION")});
test("invalid configuration denies, no fallbacks",async()=>{const q=fixture();q.args.pins={...pins,registry:"legacy"};assert.equal((await readOctoPassPie(q.args)).reason,"INVALID_CONFIGURATION")});

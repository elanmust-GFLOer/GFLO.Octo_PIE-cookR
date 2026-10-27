import {test} from "node:test";
import assert from "node:assert/strict";
import {Wallet} from "ethers";
import {createAdmissionOrchestrator,exactMessageSha256,randomChallengeNonce} from "./admission.mjs";
const wallet=new Wallet("0x"+"11".repeat(32)),now=Date.parse("2026-10-25T12:00:00Z");
const nonce="GFLOnonce1234",domain="example.test",uri="https://example.test/login";
const message=[domain+" wants you to sign in with your Ethereum account:",wallet.address,"","GFLO isolated test","",
"URI: "+uri,"Version: 1","Chain ID: 11155111","Nonce: "+nonce,"Issued At: 2026-10-25T11:59:00Z"].join("\n");
const config={domain,uri,chainId:"11155111",maxAgeSeconds:600,sessionSeconds:600};
const sessionId="SYNTHETIC_SESSION_0001";
function fixture(){
 let consumed=false,mutate=()=>{},called=0,record;
 const challenge={nonce,id:"challenge-1",subject:"alice",domain,uri,chainId:11155111,wallet:wallet.address,
 messageHash:exactMessageSha256(message),expiresAt:now+600_000,bindingGeneration:1,consentGeneration:1};
 const challenges={load:async()=>({...challenge,consumed,...mutate()})};
 const ledger={issue:async args=>{called++;record=args;
    if(consumed)return false;consumed=true;return true;}};
 const reader=createAdmissionOrchestrator({challenges,ledger,clock:()=>now,config});
 return {reader,change:f=>mutate=f,challenge,ledger,stats:()=>({called,record}),revoke:()=>{consumed=true}};
}
const request=async(extra={})=>({message,signature:await wallet.signMessage(message),subject:"alice",sessionId,...extra});
test("valid EOA signature reaches session issuance exactly once",async()=>{
 const f=fixture();assert.equal((await f.reader.admit(await request())).status,"LAB_SESSION_ISSUED");
 assert.equal(f.stats().called,1);assert.equal(f.stats().record.proofDigest,exactMessageSha256(message));
 assert.equal(f.stats().record.consentGeneration,1);
});
test("replay cannot create session",async()=>{const f=fixture(),r=await request();await f.reader.admit(r);assert.equal((await f.reader.admit(r)).status,"DENIED");assert.equal(f.stats().called,1)});
test("bad signature never reaches ledger",async()=>{const f=fixture();const bad=new Wallet("0x"+"22".repeat(32));assert.equal((await f.reader.admit(await request({signature:await bad.signMessage(message)}))).status,"DENIED");assert.equal(f.stats().called,0)});
test("tampered challenge message fingerprint denies",async()=>{const f=fixture();f.change(()=>({messageHash:"0".repeat(64)}));assert.equal((await f.reader.admit(await request())).reason,"CHALLENGE_INVALID");assert.equal(f.stats().called,0)});
test("wrong subject denies",async()=>{const f=fixture();assert.equal((await f.reader.admit(await request({subject:"bob"}))).reason,"CHALLENGE_INVALID")});
test("wrong chain challenge denies",async()=>{const f=fixture();f.change(()=>({chainId:1}));assert.equal((await f.reader.admit(await request())).reason,"CHALLENGE_INVALID")});
test("expired challenge denies",async()=>{const f=fixture();f.change(()=>({expiresAt:now-1}));assert.equal((await f.reader.admit(await request())).reason,"CHALLENGE_INVALID")});
test("DB rejects issuance fails closed",async()=>{const f=fixture();f.revoke();assert.equal((await f.reader.admit(await request())).status,"DENIED")});
test("unavailable challenge fails closed",async()=>{const r=createAdmissionOrchestrator({challenges:{load:async()=>{throw Error("db")}},ledger:{issue:async()=>true},clock:()=>now,config});assert.equal((await r.admit(await request())).status,"DENIED")});
test("no arbitrary session id",async()=>{const f=fixture();assert.equal((await f.reader.admit(await request({sessionId:"x"}))).reason,"REQUEST_INVALID")});
test("nonce generator uses 192-bit random tokens",()=>{const a=randomChallengeNonce(),b=randomChallengeNonce();assert.equal(a.length,32);assert.notEqual(a,b)});

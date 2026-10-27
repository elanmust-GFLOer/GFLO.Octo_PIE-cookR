import {test} from "node:test";
import assert from "node:assert/strict";
import {Wallet,hashMessage} from "ethers";
import {verifySiweCore,parseSiwe} from "./siwe-core.mjs";
const W=new Wallet("0x"+"11".repeat(32));const now=Date.parse("2026-10-25T12:00:00.000Z");
const nonce="GFLOnonce1234",domain="example.test",uri="https://example.test/login";
const message=(extra="",wallet=W.address,n=nonce)=>[domain+" wants you to sign in with your Ethereum account:",wallet,"",
"GFLO OctoPass read-only pilot","", "URI: "+uri,"Version: 1","Chain ID: 11155111","Nonce: "+n,
"Issued At: 2026-10-25T11:59:00Z",extra].filter((s,i,arr)=>i!==arr.length-1||s!=="").join("\n");
const options={expected:{domain,uri,nonce,chainId:"11155111",maxAgeSeconds:600},now};
const signed=async m=>W.signMessage(m);
const check=async(m=message(),overrides={})=>verifySiweCore({...options,...overrides,message:m,signature:await signed(m)});
test("EOA correct EIP-191 SIWE signature",async()=>{const r=await check();assert.equal(r.ok,true);assert.equal(r.sessionAuthorized,false);assert.equal(r.nonceConsumed,false);});
test("tampering domain rejects",async()=>assert.equal((await check(message().replace(domain,"other.test"))).ok,false));
test("tampering URI rejects",async()=>assert.equal((await check(message().replace(uri,"https://evil.test/login"))).ok,false));
test("wrong chain rejects",async()=>assert.equal((await check(message().replace("Chain ID: 11155111","Chain ID: 1"))).ok,false));
test("nonce mismatch rejects",async()=>assert.equal((await check(message("","", "DIFFERENTNONCE123"))).ok,false));
test("expired message rejects",async()=>assert.equal((await check(message("Expiration Time: 2026-10-25T11:59:30Z"))).reason,"EXPIRED"));
test("future not before denies",async()=>assert.equal((await check(message("Not Before: 2026-10-25T12:01:00Z"))).reason,"NOT_BEFORE"));
test("bad signature denies",async()=>assert.equal((await verifySiweCore({...options,message:message(),signature:"0x1234"})).ok,false));
test("duplicated URI rejected",()=>assert.throws(()=>parseSiwe(message("URI: "+uri))));
test("unknown field rejected",()=>assert.throws(()=>parseSiwe(message("Foo: hello"))));
test("short nonce rejected",()=>assert.throws(()=>parseSiwe(message("","", "123"))));
test("ERC-1271 with explicit finalized proof accepted as CRYPTO_ONLY",async()=>{const m=message();const r=await verifySiweCore({...options,message:m,signature:await signed(m),accountKind:"ERC1271",erc1271:{verifyAtBlock:async ({digest})=>({magic:"0x1626ba7e",finalized:true,blockHash:"0x"+"ab".repeat(32),proofDigest:digest})}});assert.equal(r.ok,true);assert.equal(r.sessionAuthorized,false)});
test("ERC-1271 invalid magic denied",async()=>{const m=message();const r=await verifySiweCore({...options,message:m,signature:await signed(m),accountKind:"ERC1271",erc1271:{verifyAtBlock:async ()=>({magic:"0xffffffff",finalized:true,blockHash:"0x"+"ab".repeat(32)})}});assert.equal(r.ok,false)});
test("ERC-1271 unfinalized denied",async()=>{const m=message();const r=await verifySiweCore({...options,message:m,signature:await signed(m),accountKind:"ERC1271",erc1271:{verifyAtBlock:async ()=>({magic:"0x1626ba7e",finalized:false,blockHash:"0x"+"ab".repeat(32)})}});assert.equal(r.ok,false)});
test("bad EOA signer denied",async()=>{const m=message();const other=new Wallet("0x"+"22".repeat(32));const r=await verifySiweCore({...options,message:m,signature:await other.signMessage(m)});assert.equal(r.ok,false)});

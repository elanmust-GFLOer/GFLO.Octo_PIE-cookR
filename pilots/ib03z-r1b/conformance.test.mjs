import {test} from "node:test";
import assert from "node:assert/strict";
import {Wallet} from "ethers";
import {parseSiwe,verifySiweCore} from "../ib03d/siwe-core.mjs";
const w=new Wallet("0x"+"11".repeat(32)),domain="example.test";
const origin="https://example.test/login",nonce="GFLOreg12345";
const start=[domain+" wants you to sign in with your Ethereum account:",w.address,"","GFLO reader","","URI: "+origin,"Version: 1","Chain ID: 11155111","Nonce: "+nonce,"Issued At: 2026-10-25T11:59:00Z"];
const msg=lines=>lines.join("\n");
const now=Date.parse("2026-10-25T12:00:00Z");
const verify=async(m,options={})=>verifySiweCore({message:m,signature:await w.signMessage(m),now,expected:{domain,uri:origin,nonce,chainId:"11155111",maxAgeSeconds:600,...options}});
test("baseline valid with EIP-191",async()=>assert.equal((await verify(msg(start))).ok,true));
test("strict required field sequence",async()=>{
 let m=start.slice(),x=m[6];m[6]=m[7];m[7]=x;
 assert.equal((await verify(msg(m))).ok,false);
});
test("multiline/tab statement denied",async()=>{
 assert.equal((await verify(msg([...start.slice(0,4),"second line",...start.slice(4)]))).ok,false);
 assert.equal((await verify(msg(start).replace("GFLO reader","GFLO\treader"))).ok,false);
});
test("invalid calendar timestamp denied",async()=>{
 assert.equal((await verify(msg(start).replace("2026-10-25T11:59:00Z","2026-02-30T11:59:00Z"))).ok,false);
});
test("RFC3339 explicit offsets accepted",async()=>{
 assert.equal((await verify(msg(start).replace("2026-10-25T11:59:00Z","2026-10-25T11:59:00+00:00"))).ok,true);
});
test("EIP-4361 resources and empty Request ID accepted",async()=>{
 const m=msg([...start,"Request ID: ","Resources:","- https://example.test/resource"]);
 const p=parseSiwe(m);assert.equal(p.resources.length,1);assert.equal(p.requestId,"");
 assert.equal((await verify(m)).ok,true);
});
test("explicit scheme in SIWE header accepted",async()=>{
 const m=msg(start).replace(domain+" wants","https://"+domain+" wants");
 assert.equal((await verify(m)).ok,true);
});
test("remote HTTP never eligible for loopback allowance",async()=>{
 const http=msg(start).replaceAll("https://example.test/login","http://example.test/login");
 assert.equal((await verify(http,{uri:"http://example.test/login",allowHttpLoopback:true})).ok,false);
});
test("loopback HTTP permits explicit local host only",async()=>{
 for(const local of ["localhost","127.0.0.1","[::1]"]){
  const m=msg(start).replaceAll("example.test",local).replace("https://","http://");
  const out=await verifySiweCore({message:m,signature:await w.signMessage(m),now,
   expected:{domain:local,uri:"http://"+local+"/login",nonce,chainId:"11155111",maxAgeSeconds:600,allowHttpLoopback:true}});
  assert.equal(out.ok,true,JSON.stringify(out));
 }
});
console.log("IB03Z_R1B_F02_F04_REGRESSIONS_PASS");

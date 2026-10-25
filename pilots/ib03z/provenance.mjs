// IB-03Z — read-only Sepolia two-provider provenance checker. Requires independent JSON-RPC endpoints.
// Provider agreement is NOT independently verified Ethereum consensus/finality.
import {keccak256} from "ethers";
import {writeFileSync} from "node:fs";
const endpoints=[process.env.IB03Z_RPC_A||"https://ethereum-sepolia-rpc.publicnode.com",process.env.IB03Z_RPC_B||"https://sepolia.drpc.org"];
const contracts=[
 {name:"PIECore_LEGACY_NOT_V04",address:"0x9CF55d0b9D61Dc28EF3cb10765CF4b861Cd0991e",sourceVerified:true},
 {name:"GFLOIgnition_UNVERIFIED",address:"0x414DEDcf9264614Fd087BDa58bE27a0B698CcC54",sourceVerified:false},
 {name:"GFLOToken_UNVERIFIED",address:"0x563b2e3b499818a2f84c472efb3169a2667807fe",sourceVerified:false}
];
export function createRpc(url,request=fetch){
 let id=0;
 return async(method,params=[])=>{
  const ctl=new AbortController(); const timer=setTimeout(()=>ctl.abort(),12000);
  try{
   const resp=await request(url,{method:"POST",headers:{"content-type":"application/json"},
    body:JSON.stringify({jsonrpc:"2.0",id:++id,method,params}),signal:ctl.signal});
   if(!resp.ok)throw Error("RPC_HTTP_"+resp.status);
   const d=await resp.json();
   if(d.error||!Object.hasOwn(d,"result")||d.result===null)throw Error("RPC_NO_RESULT_"+method);
   return d.result;
  }finally{clearTimeout(timer)}
 };
}
const hex=x=>typeof x==="string"&&/^0x[0-9a-fA-F]+$/.test(x);
const fail=msg=>{throw Error("IB03Z_BLOCK_"+msg)};
export async function verifySources(clients){
 if(clients.length!==2)fail("PROVIDER_COUNT");
 const chains=await Promise.all(clients.map(c=>c("eth_chainId")));
 if(!chains.every(x=>x.toLowerCase()==="0xaa36a7"))fail("CHAIN_ID");
 const finalized=await Promise.all(clients.map(c=>c("eth_getBlockByNumber",["finalized",false])));
 if(finalized.some(b=>!b||!hex(b.number)||!/^0x[0-9a-fA-F]{64}$/.test(b.hash||"")))fail("FINALITY_REFERENCE");
 const h=finalized.reduce((n,b)=>BigInt(b.number)<n?BigInt(b.number):n,BigInt(finalized[0].number));
 const height="0x"+h.toString(16);
 const blocks=await Promise.all(clients.map(c=>c("eth_getBlockByNumber",[height,false])));
 if(blocks.some(b=>!b||BigInt(b.number)!==h||!/^0x[0-9a-fA-F]{64}$/.test(b.hash||"")))fail("BLOCK_FORMAT");
 if(blocks[0].hash.toLowerCase()!==blocks[1].hash.toLowerCase())fail("BLOCK_DISAGREEMENT");
 const blockHash=blocks[0].hash.toLowerCase(),pin={blockHash,requireCanonical:true};
 const rows=[];
 for(const contract of contracts){
  const code=await Promise.all(clients.map(c=>c("eth_getCode",[contract.address,pin])));
  if(code.some(v=>!/^0x(?:[0-9a-fA-F]{2})*$/.test(v)))fail("INVALID_BYTECODE_"+contract.name);
  if(code[0].toLowerCase()!==code[1].toLowerCase())fail("BYTECODE_DISAGREEMENT_"+contract.name);
  rows.push({name:contract.name,address:contract.address,
   sourceVerifiedOnEtherscan:contract.sourceVerified,
   hasRuntime:code[0].length>2,runtimeBytes:(code[0].length-2)/2,
   codeHash:keccak256(code[0]),codeHashAgreement:true});
 }
 return {status:"TWO_RPC_AGREEMENT_NOT_CONSENSUS",chainId:11155111,blockNumber:height,blockHash,
  finalizedObservations:finalized.map(b=>({number:b.number,hash:b.hash})),contracts:rows,
  limits:["No independent consensus proof","No V04 deployment pin","No EIP1271 smart wallet pinned","No cryptographic RPC endpoint attestation"]};
}
if(process.argv[1]&&import.meta.url.endsWith(process.argv[1].split("/").at(-1))){
 const evidence={status:"BLOCK",checkedAt:new Date().toISOString(),source:"IB03Z live RPC",providers:["RPC_A","RPC_B"]};
 try{
  Object.assign(evidence,await verifySources(endpoints.map(createRpc)));
  console.log("IB03Z_TWO_PROVIDER_RPC_AGREEMENT_PASS_NON_CONSENSUS");
 }catch(e){evidence.error=String(e.message||e).slice(0,150);console.error(evidence.error);process.exitCode=1}
 writeFileSync(process.env.IB03Z_REPORT||"ib03z-evidence.json",JSON.stringify(evidence,null,2)+"\n");
}

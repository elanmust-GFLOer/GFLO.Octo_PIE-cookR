import assert from "node:assert/strict";
import {Interface,Wallet,hashMessage,keccak256} from "ethers";
import {createRpc,verifySources} from "../ib03z/provenance.mjs";
import {createSiwe1271Adapter} from "./adapter.mjs";
import {verifySiweCore} from "../ib03d/siwe-core.mjs";
const mkFetch=data=>async(_url,params)=>({ok:true,json:async()=>data});
for(const bad of [{jsonrpc:"1.0",id:1,result:"0xaa36a7"},{jsonrpc:"2.0",id:999,result:"0xaa36a7"},{jsonrpc:"2.0",id:1,result:null},{jsonrpc:"2.0",id:1,error:{code:-1,message:"no"}}]){
 await assert.rejects(()=>createRpc("https://localhost.example",mkFetch(bad))("eth_chainId"),/RPC_RESPONSE_INVALID/);
}
assert.equal(await createRpc("https://localhost.example",mkFetch({jsonrpc:"2.0",id:1,result:"0xaa36a7"}))("eth_chainId"),"0xaa36a7");
console.log("PASS F-07 JSON-RPC 2.0 response version, id, nonnull result required");
const h="0x"+"ab".repeat(32),runtime="0x6001600055";
const client=async(m,p)=>{
 if(m==="eth_chainId")return "0xaa36a7";
 if(m==="eth_getBlockByNumber")return {hash:h,number:"0x100"};
 if(m==="eth_getCode")return runtime;
 throw Error("BAD_METHOD");
};
const rep=await verifySources([client,client]);
assert(rep.contracts.every(c=>c.sourceVerification==="NOT_ESTABLISHED_BY_RPC"&&!("sourceVerifiedOnEtherscan" in c)));
const empty=async(m,p)=>m==="eth_getCode"&&p[0].toLowerCase()==="0x414dedcf9264614fd087bda58be27a0b698ccc54"?"0x":client(m,p);
await assert.rejects(()=>verifySources([client,empty]));
await assert.rejects(()=>verifySources([empty,empty]),/EMPTY_RUNTIME/);
console.log("PASS F-06 independent source verification cannot be inferred from bytecode equality; empty runtime DENY");
const owner=new Wallet("0x"+"11".repeat(32)),wallet="0x"+"ab".repeat(20);
const abi=new Interface(["function isValidSignature(bytes32,bytes) view returns(bytes4)"]);
const rpc=async(m,p)=>{
 if(m==="eth_chainId")return "0xaa36a7";
 if(m==="eth_getBlockByHash")return {hash:h,number:"0x100"};
 if(m==="eth_getBlockByNumber")return {hash:h,number:"0x100"};
 if(m==="eth_getCode")return runtime;
 if(m==="eth_call")return abi.encodeFunctionResult("isValidSignature",["0x1626ba7e"]);
 throw Error("UNEXPECTED");
};
const adapter=createSiwe1271Adapter({rpc,wallet,blockHash:h,codeHash:keccak256(runtime)});
const message=["example.test wants you to sign in with your Ethereum account:",wallet,"","GFLO proof","","URI: https://example.test/login","Version: 1","Chain ID: 11155111","Nonce: GFLOAdapter123","Issued At: 2026-10-25T12:00:00Z"].join("\n");
const payload={message,signature:await owner.signMessage(message),now:Date.parse("2026-10-25T12:01:00Z"),accountKind:"ERC1271",erc1271:adapter,expected:{domain:"example.test",uri:"https://example.test/login",chainId:"11155111",nonce:"GFLOAdapter123",maxAgeSeconds:600}};
const valid=await verifySiweCore(payload);
assert.equal(valid.ok,true);assert.equal(valid.sessionAuthorized,false);
const badAdapter=createSiwe1271Adapter({rpc:async()=>{throw Error("OUTAGE")},wallet,blockHash:h,codeHash:keccak256(runtime)});
assert.equal((await verifySiweCore({...payload,erc1271:badAdapter})).ok,false);
assert.equal((await verifySiweCore({...payload,expected:{...payload.expected,chainId:"1"}})).ok,false);
console.log("PASS F-07 boolean-to-IB03D-adapter contract; outage and chain drift deny");
console.log("IB03Z_R1D_RPC_PROVENANCE_ADAPTER_LAB_PASS production=BLOCK");

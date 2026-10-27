import assert from "node:assert/strict";
import {Interface,Wallet,keccak256,hashMessage} from "ethers";
import {pinnedVerifier} from "./pinned.mjs";
const abi=new Interface(["function isValidSignature(bytes32,bytes) view returns(bytes4)"]);
const wallet="0x"+"ab".repeat(20),blockHash="0x"+"cd".repeat(32),code="0x60006000f3",codeHash=keccak256(code);
const signature=await new Wallet("0x"+"11".repeat(32)).signMessage("GFLO IB03X");
const req={wallet,chainId:"11155111",digest:hashMessage("GFLO IB03X"),signature};
const success=abi.encodeFunctionResult("isValidSignature",["0x1626ba7e"]),seen=[];
let broken="";
const rpc=async(m,p)=>{
 seen.push([m,p]);if(broken===m)throw Error("OUTAGE");
 if(m==="eth_chainId")return "0xaa36a7";
 if(m==="eth_getBlockByHash")return {hash:blockHash,number:"0x100"};
 if(m==="eth_getBlockByNumber")return {hash:blockHash,number:"0x100"};
 if(m==="eth_getCode")return code;
 if(m==="eth_call")return success;
 throw Error("UNKNOWN");
};
const create=(r=rpc)=>pinnedVerifier({rpc:r,wallet,blockHash,codeHash});
assert.equal(await create()(req),true);
for(const [m,p] of seen.filter(x=>["eth_call","eth_getCode"].includes(x[0])))assert.deepEqual(p.at(-1),{blockHash,requireCanonical:true});
console.log("PASS pinned EIP-1898 identical blockHash for code and call");
for(const m of ["eth_chainId","eth_getBlockByHash","eth_getBlockByNumber","eth_getCode","eth_call"]){
 broken=m;assert.equal(await create()(req),false);
}
broken="";
for(const [m,v] of [["eth_chainId","0x1"],["eth_getBlockByHash",{hash:"0x"+"aa".repeat(32),number:"0x100"}],["eth_getBlockByNumber",{number:"0xff"}],["eth_getCode","0x6001"],["eth_call",abi.encodeFunctionResult("isValidSignature",["0xffffffff"])] ]){
 assert.equal(await create(async(x,p)=>x===m?v:rpc(x,p))(req),false);
}
assert.equal(await create()({...req,chainId:"1"}),false);
assert.equal(await create()({...req,wallet:"0x"+"bb".repeat(20)}),false);
console.log("PASS RPC failure / wrong chain / wrong block / finality / codehash / invalid magic");
console.log("IB03X_PINNED_RPC_LAB_PASS production=BLOCK");

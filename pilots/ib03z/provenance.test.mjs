import assert from "node:assert/strict";
import {verifySources} from "./provenance.mjs";
const h="0x"+"ab".repeat(32),code="0x6001600055";
const client=async(method,params)=>{
 if(method==="eth_chainId")return "0xaa36a7";
 if(method==="eth_getBlockByNumber")return params[0]==="finalized"?{number:"0x100",hash:h}:{number:"0x100",hash:h};
 if(method==="eth_getCode"){assert.deepEqual(params[1],{blockHash:h,requireCanonical:true});return code}
 throw Error("unexpected "+method);
};
const ok=await verifySources([client,client]);
assert.equal(ok.status,"TWO_RPC_AGREEMENT_NOT_CONSENSUS");
assert.equal(ok.contracts.length,3);
console.log("PASS two agreeing simulated RPC endpoints preserve EIP-1898 canonical block reference");
for(const modified of [
 async(m,p)=>m==="eth_chainId"?"0x1":client(m,p),
 async(m,p)=>m==="eth_getBlockByNumber"&&p[0]==="0x100"?{number:"0x100",hash:"0x"+"cd".repeat(32)}:client(m,p),
 async(m,p)=>m==="eth_getCode"?"0x6002":client(m,p),
 async(m,p)=>m==="eth_getCode"?null:client(m,p),
 async()=>{throw Error("RPC_DOWN")}
]){
 await assert.rejects(()=>verifySources([client,modified]));
}
console.log("PASS chain/block/codehash divergence, missing data and provider failure deny");
console.log("IB03Z_PROVIDER_PROVENANCE_LOGIC_LAB_PASS production=BLOCK");

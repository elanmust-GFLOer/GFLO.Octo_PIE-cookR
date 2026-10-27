// Adapter: old boolean pinnedVerifier -> IB03D object contract.
// This adapter binds a vetted pinned RPC policy; "finalized" means provider assertion only.
import {pinnedVerifier} from "../ib03x/pinned.mjs";
export function createSiwe1271Adapter({rpc,wallet,blockHash,codeHash}){
 const fn=pinnedVerifier({rpc,wallet,blockHash,codeHash});
 return Object.freeze({verifyAtBlock:async({wallet:actual,chainId,digest,signature})=>{
  const valid=await fn({wallet:actual,chainId,digest,signature});
  if(!valid)return Object.freeze({magic:"0xffffffff",finalized:false,blockHash,assurance:"DENIED"});
  return Object.freeze({magic:"0x1626ba7e",finalized:true,blockHash,assurance:"RPC_PROVIDER_ASSERTED_NOT_CONSENSUS"});
 }});
}

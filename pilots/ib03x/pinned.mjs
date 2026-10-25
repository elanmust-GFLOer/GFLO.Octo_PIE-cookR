import {Interface,getAddress,keccak256} from "ethers";
const abi=new Interface(["function isValidSignature(bytes32,bytes) view returns(bytes4)"]);
const hex32=x=>typeof x==="string"&&/^0x[0-9a-fA-F]{64}$/.test(x);
export function pinnedVerifier({rpc,wallet,blockHash,codeHash}){
 if(typeof rpc!=="function"||!hex32(blockHash)||!hex32(codeHash))throw Error("BAD_CONFIG");
 const target=getAddress(wallet);
 return async({wallet:requested,chainId,digest,signature})=>{
  try{
   if(getAddress(requested)!==target||chainId!=="11155111"||!hex32(digest)||!/^0x[0-9a-fA-F]{130}$/.test(signature))return false;
   if((await rpc("eth_chainId",[])).toLowerCase()!=="0xaa36a7")return false;
   const block=await rpc("eth_getBlockByHash",[blockHash,false]);
   const finalized=await rpc("eth_getBlockByNumber",["finalized",false]);
   if(!block||block.hash.toLowerCase()!==blockHash.toLowerCase()||
      !finalized||BigInt(finalized.number)<BigInt(block.number))return false;
   const pin={blockHash,requireCanonical:true};
   const code=await rpc("eth_getCode",[target,pin]);
   if(typeof code!=="string"||keccak256(code).toLowerCase()!==codeHash.toLowerCase())return false;
   const answer=await rpc("eth_call",[{to:target,data:abi.encodeFunctionData("isValidSignature",[digest,signature])},pin]);
   return abi.decodeFunctionResult("isValidSignature",answer)[0]==="0x1626ba7e";
  }catch{return false}
 };
}

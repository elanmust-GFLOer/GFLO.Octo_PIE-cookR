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
   if(!block||!finalized||!/^0x[0-9a-fA-F]{64}$/.test(block.hash??'')||
      block.hash.toLowerCase()!==blockHash.toLowerCase()||
      !/^0x[0-9a-fA-F]+$/.test(block.number??'')||
      !/^0x[0-9a-fA-F]{64}$/.test(finalized.hash??'')||
      !/^0x[0-9a-fA-F]+$/.test(finalized.number??''))return false;
   const targetHeight=BigInt(block.number),finalHeight=BigInt(finalized.number);
   if(finalHeight<targetHeight||finalHeight-targetHeight>128n)return false;
   let cursor=finalized.hash.toLowerCase(),height=finalHeight;
   if(height===targetHeight&&cursor!==blockHash.toLowerCase())return false;
   while(height>targetHeight){
     const step=await rpc("eth_getBlockByHash",[cursor,false]);
     if(!step||!/^0x[0-9a-fA-F]{64}$/.test(step.hash??'')||
       !/^0x[0-9a-fA-F]{64}$/.test(step.parentHash??'')||
       !/^0x[0-9a-fA-F]+$/.test(step.number??'')||
       step.hash.toLowerCase()!==cursor||BigInt(step.number)!==height)return false;
     cursor=step.parentHash.toLowerCase();height--;
   }
   if(cursor!==blockHash.toLowerCase())return false;
   const pin={blockHash,requireCanonical:true};
   const code=await rpc("eth_getCode",[target,pin]);
   if(typeof code!=="string"||keccak256(code).toLowerCase()!==codeHash.toLowerCase())return false;
   const answer=await rpc("eth_call",[{to:target,data:abi.encodeFunctionData("isValidSignature",[digest,signature])},pin]);
   return abi.decodeFunctionResult("isValidSignature",answer)[0]==="0x1626ba7e";
  }catch{return false}
 };
}

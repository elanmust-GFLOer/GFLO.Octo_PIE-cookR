import {verifyMessage,getAddress,hashMessage} from "ethers";
import {parseSiwe} from "./siwe-parser.mjs";
export {parseSiwe} from "./siwe-parser.mjs";
const MAGIC="0x1626ba7e";
const deny=reason=>Object.freeze({ok:false,reason});
export async function verifySiweCore({message,signature,expected,now,accountKind="EOA",erc1271}){
 try{
  if(typeof now!=="number"||!Number.isSafeInteger(now)||!expected||typeof expected.domain!=="string"||
  typeof expected.uri!=="string"||typeof expected.nonce!=="string"||typeof expected.chainId!=="string"||
  !Number.isSafeInteger(expected.maxAgeSeconds)||expected.maxAgeSeconds<1)return deny("INVALID_EXPECTATION");
  const p=parseSiwe(message);
  if(p.domain!==expected.domain||p.uri!==new URL(expected.uri).href||p.chainId!==expected.chainId||p.nonce!==expected.nonce)return deny("CONTEXT_MISMATCH");
  const origin=new URL(p.uri);
  if(origin.protocol!=="https:"){
   if(origin.protocol!=="http:"||expected.allowHttpLoopback!==true||
      !["localhost","127.0.0.1","[::1]"].includes(origin.hostname.toLowerCase())||
      p.domain!==origin.host)return deny("HTTPS_REQUIRED");
  }
  const issued=Date.parse(p.issuedAt);
  if(issued>now+30_000||now-issued>expected.maxAgeSeconds*1000)return deny("ISSUED_AT_INVALID");
  if(p.expirationTime&&now>=Date.parse(p.expirationTime))return deny("EXPIRED");
  if(p.notBefore&&now<Date.parse(p.notBefore))return deny("NOT_BEFORE");
  if(typeof signature!=="string"||!/^0x[0-9a-fA-F]+$/.test(signature))return deny("SIGNATURE_FORMAT");
  if(accountKind==="EOA"){
   if(getAddress(verifyMessage(message,signature))!==p.address)return deny("SIGNATURE_INVALID");
  }else if(accountKind==="ERC1271"){
   if(!erc1271||typeof erc1271.verifyAtBlock!=="function")return deny("NO_CONTRACT_VERIFIER");
   const answer=await erc1271.verifyAtBlock({wallet:p.address,chainId:p.chainId,digest:hashMessage(message),signature});
   if(answer?.magic!==MAGIC||answer.finalized!==true||typeof answer.blockHash!=="string"||!/^0x[0-9a-fA-F]{64}$/.test(answer.blockHash))return deny("ERC1271_INVALID");
  }else return deny("UNSUPPORTED_ACCOUNT_KIND");
  return Object.freeze({ok:true,status:"CRYPTO_VERIFIED_ONLY",address:p.address,chainId:p.chainId,nonce:p.nonce,
    kind:accountKind,sessionAuthorized:false,nonceConsumed:false});
 }catch{return deny("MALFORMED_OR_INVALID");}
}

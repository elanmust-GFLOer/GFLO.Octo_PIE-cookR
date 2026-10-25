// IB-03D.1 — EIP-4361 parser and EIP-191 / ERC-1271 verification.
// Deterministic lab-only verifier: no nonce consumption or session issuance.
// Uses pinned ethers v6 from cookR npm lock. NEVER use its output alone for authentication.
import { verifyMessage, getAddress, isAddress, Interface, hashMessage } from "ethers";
const HEADER=" wants you to sign in with your Ethereum account:";
const RE_NONCE=/^[A-Za-z0-9]{8,}$/;
const RE_DATE=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;
const VALID_FIELDS=new Set(["URI","Version","Chain ID","Nonce","Issued At","Expiration Time","Not Before","Request ID","Resources"]);
const deny=reason=>Object.freeze({ok:false,reason});
const MAGIC="0x1626ba7e";
function canonicalDate(s){if(!RE_DATE.test(s)||!Number.isFinite(Date.parse(s))||new Date(s).toISOString()!==new Date(s).toISOString())throw Error("BAD_TIME");return Date.parse(s);}
export function parseSiwe(message){
 if(typeof message!=="string"||message.length>8192||message.includes("\r")||message.includes("\0"))throw Error("BAD_MESSAGE");
 const lines=message.split("\n"),idx=lines[0]?.indexOf(HEADER);
 if(idx<=0||!lines[0].endsWith(HEADER)||lines[2]!==""||!isAddress(lines[1]??""))throw Error("BAD_HEADER");
 const domain=lines[0].slice(0,idx),wallet=getAddress(lines[1]);
 if(!/^[a-zA-Z0-9.-]+(?::[0-9]{1,5})?$/.test(domain))throw Error("BAD_DOMAIN");
 let k=3;const statement=[];
 while(k<lines.length&&lines[k]!==""&&!/^[A-Za-z ]+: /.test(lines[k]))statement.push(lines[k++]);
 if(lines[k]!=="")throw Error("BAD_SEPARATOR");k++;
 const fields={};let resources=[];
 for(;k<lines.length;k++){
  const line=lines[k];if(!line)throw Error("BAD_FIELD");
  if(line.startsWith("- ")){if(!("Resources" in fields))throw Error("UNEXPECTED_RESOURCE");resources.push(line.slice(2));continue;}
  const pos=line.indexOf(": ");if(pos<1)throw Error("BAD_FIELD");
  const name=line.slice(0,pos),value=line.slice(pos+2);
  if(!VALID_FIELDS.has(name)||name in fields||!value.trim())throw Error("DUPLICATE_OR_UNKNOWN");
  fields[name]=value;
 }
 for(const name of ["URI","Version","Chain ID","Nonce","Issued At"])if(!(name in fields))throw Error("MISSING_FIELD");
 if(fields.Version!=="1"||!/^[1-9][0-9]*$/.test(fields["Chain ID"])||!RE_NONCE.test(fields.Nonce))throw Error("BAD_REQUIRED");
 const uri=new URL(fields.URI);
 if(!["https:","http:"].includes(uri.protocol)||uri.username||uri.password)throw Error("BAD_URI");
 canonicalDate(fields["Issued At"]);
 if(fields["Expiration Time"])canonicalDate(fields["Expiration Time"]);
 if(fields["Not Before"])canonicalDate(fields["Not Before"]);
 for(const res of resources)new URL(res);
 return Object.freeze({domain,address:wallet,uri:uri.href,version:"1",chainId:fields["Chain ID"],nonce:fields.Nonce,
 issuedAt:fields["Issued At"],expirationTime:fields["Expiration Time"]??null,notBefore:fields["Not Before"]??null,
 requestId:fields["Request ID"]??null,statement:statement.join("\n"),resources:Object.freeze(resources)});
}
export async function verifySiweCore({message,signature,expected,now,accountKind="EOA",erc1271}){
 try{
  if(typeof now!=="number"||!Number.isSafeInteger(now)||!expected||typeof expected.domain!=="string"||
  typeof expected.uri!=="string"||typeof expected.nonce!=="string"||typeof expected.chainId!=="string"||
  !Number.isSafeInteger(expected.maxAgeSeconds)||expected.maxAgeSeconds<1)return deny("INVALID_EXPECTATION");
  const p=parseSiwe(message);
  if(p.domain!==expected.domain||p.uri!==new URL(expected.uri).href||p.chainId!==expected.chainId||p.nonce!==expected.nonce)return deny("CONTEXT_MISMATCH");
  if(!p.uri.startsWith("https://")&&!expected.allowHttpLoopback)return deny("HTTPS_REQUIRED");
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

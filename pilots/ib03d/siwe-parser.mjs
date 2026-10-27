import {getAddress,isAddress} from "ethers";
// Strict subset-compatible EIP-4361 parser: no signature/session authorization.
const HEADER=" wants you to sign in with your Ethereum account:";
const nonceRe=/^[A-Za-z0-9]{8,}$/;
const timeRe=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const strictTime=s=>{
 const m=timeRe.exec(s);
 if(!m)throw Error("BAD_TIME");
 const [_,y,mo,d,h,mi,sec,frac,zone]=m;
 const year=+y,month=+mo,day=+d;
 const leap=year%4===0&&(year%100!==0||year%400===0);
 const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
 if(month<1||month>12||day<1||day>days[month-1]||+h>23||+mi>59||+sec>59)throw Error("BAD_TIME");
 if(zone!=="Z"&&(+(zone.slice(1,3))>23||+(zone.slice(4,6))>59))throw Error("BAD_TIME");
 const value=Date.parse(s);
 if(!Number.isFinite(value))throw Error("BAD_TIME");
 return value;
};
const uriCheck=s=>{
 if(typeof s!=="string"||!s||/[\s\\]/.test(s))throw Error("BAD_URI");
 const u=new URL(s);
 if(!u.protocol||!u.hostname||u.username||u.password||!["https:","http:"].includes(u.protocol))throw Error("BAD_URI");
 return u.href;
};
export function parseSiwe(message){
 if(typeof message!=="string"||message.length>8192||/[\r\u0000-\u0008\u000b-\u001f\u007f]/.test(message))throw Error("BAD_MESSAGE");
 const lines=message.split("\n");
 const h=lines[0]??"";
 if(!h.endsWith(HEADER)||lines[2]!==""||!isAddress(lines[1]??""))throw Error("BAD_HEADER");
 const authority=h.slice(0,-HEADER.length);
 // Optional explicit scheme in first line; reject arbitrary credentials/fragments/paths.
 const matched=/^(?:(https?):\/\/)?((?:[A-Za-z0-9.-]+|\[::1\])(?::[0-9]{1,5})?)$/.exec(authority);
 if(!matched)throw Error("BAD_DOMAIN");
 const scheme=matched[1]??null,domain=matched[2];
 if(domain.includes("..")||domain.startsWith(".")||domain.endsWith("."))throw Error("BAD_DOMAIN");
 let i=3,statement="";
 if(lines[i]!==""){
  statement=lines[i]??"";
  if(!statement||/[\t\n\r]/.test(statement)||/[^A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=% ]/.test(statement))throw Error("BAD_STATEMENT");
  i++;
 }
 if(lines[i]!=="")throw Error("BAD_SEPARATOR");
 i++;
 const required=["URI","Version","Chain ID","Nonce","Issued At"],optional=["Expiration Time","Not Before","Request ID","Resources"];
 const fields={};
 for(const name of required){
  const prefix=name+": ";
  if(!lines[i]?.startsWith(prefix))throw Error("ORDER_OR_MISSING");
  fields[name]=lines[i++].slice(prefix.length);
  if(!fields[name])throw Error("EMPTY_REQUIRED");
 }
 let last=-1;const resources=[];
 while(i<lines.length){
  const line=lines[i++];
  const pos=optional.findIndex(n=>line===n+":"||line.startsWith(n+": "));
  if(pos<0||pos<=last)throw Error("BAD_OPTIONAL_ORDER");
  last=pos;
  const name=optional[pos],value=line.slice(name.length+1);
  if(name==="Resources"){
   if(value!=="")throw Error("BAD_RESOURCES_HEADER");
   if(i===lines.length)throw Error("EMPTY_RESOURCES");
   while(i<lines.length){
    const item=lines[i++];
    if(!item.startsWith("- ")||item.length<3)throw Error("BAD_RESOURCE");
    resources.push(uriCheck(item.slice(2)));
   }
  }else{
   if(!line.startsWith(name+": "))throw Error("BAD_OPTIONAL");
   if(name!=="Request ID"&&!value.trim())throw Error("EMPTY_OPTIONAL");
   fields[name]=value.slice(1);
  }
 }
 if(fields.Version!=="1"||!/^[1-9][0-9]*$/.test(fields["Chain ID"])||!nonceRe.test(fields.Nonce))throw Error("BAD_REQUIRED");
 const uri=uriCheck(fields.URI);
 strictTime(fields["Issued At"]);
 if(fields["Expiration Time"]!==undefined)strictTime(fields["Expiration Time"]);
 if(fields["Not Before"]!==undefined)strictTime(fields["Not Before"]);
 if(scheme&&new URL(uri).protocol!==scheme+":")throw Error("SCHEME_URI_MISMATCH");
 return Object.freeze({domain,address:getAddress(lines[1]),scheme,uri,version:"1",
  chainId:fields["Chain ID"],nonce:fields.Nonce,issuedAt:fields["Issued At"],
  expirationTime:fields["Expiration Time"]??null,notBefore:fields["Not Before"]??null,
  requestId:fields["Request ID"]??null,statement,resources:Object.freeze(resources)});
}
export {strictTime};

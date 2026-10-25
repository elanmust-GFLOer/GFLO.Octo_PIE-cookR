// IB-03I isolated asymmetric key custody pilot. Node Ed25519, no private key in DB.
// Trust boundary: verifier signs verified evidence; admission can only verify public key.
import {generateKeyPairSync, sign as edSign, verify as edVerify, randomBytes} from "node:crypto";
const invalid=(reason)=>Object.freeze({ok:false,reason});
export function createCustodyLab(){
 const store=new Map();
 const create=(id)=>{if(!/^[A-Za-z0-9_-]{1,64}$/.test(id)||store.has(id))throw Error("KEY_ID");
  const pair=generateKeyPairSync("ed25519");store.set(id,{pair,active:true});
  return {keyId:id,publicKey:pair.publicKey.export({type:"spki",format:"pem"})};};
 const revoke=id=>{const x=store.get(id);if(!x)throw Error("KEY_MISSING");x.active=false;};
 const sign=({keyId,payload})=>{const x=store.get(keyId);if(!x?.active)throw Error("KEY_REVOKED");return edSign(null,Buffer.from(payload),x.pair.privateKey).toString("base64url");};
 const publicKeys=()=>[...store.entries()].map(([keyId,v])=>({keyId,publicKey:v.pair.publicKey.export({type:"spki",format:"pem"}),active:v.active}));
 return Object.freeze({create,revoke,sign,publicKeys});
}
function canonical(v){if(!v||typeof v!=="object"||Array.isArray(v))throw Error("BAD_PAYLOAD");
 const keys=["challengeId","subject","chainId","wallet","digest","sessionId","bindingGeneration","consentGeneration","expiresAt","audience"];
 if(Object.keys(v).sort().join(",")!==keys.slice().sort().join(","))throw Error("FIELDS");
 for(const k of keys){if(typeof v[k]!=="string"||!v[k]||v[k].includes("|")||v[k].includes("\n"))throw Error("FIELDS");}
 if(!/^[0-9a-f]{64}$/.test(v.digest)||!/^0x[0-9a-fA-F]{40}$/.test(v.wallet))throw Error("FORMAT");
 if(!["bindingGeneration","consentGeneration","expiresAt","chainId"].every(k=>/^[1-9][0-9]*$/.test(v[k])))throw Error("FORMAT");
 return "GFLO-IB03I-ED25519-V1|"+keys.map(k=>v[k]).join("|");
}
export function createPublicOnlyAdmission({trustedKeys,clock,audience}){
 if(typeof clock!=="function"||!Array.isArray(trustedKeys)||typeof audience!=="string")throw Error("CONFIG");
 const map=new Map(trustedKeys.map(x=>[x.keyId,x]));
 return Object.freeze({async validate(att){
  try{
   if(!att||typeof att.keyId!=="string"||!map.has(att.keyId))return invalid("UNKNOWN_KEY");
   const key=map.get(att.keyId);if(!key.active)return invalid("REVOKED_KEY");
   const payload=canonical(att.payload);if(att.payload.audience!==audience)return invalid("AUDIENCE");
   const t=BigInt(clock());if(BigInt(att.payload.expiresAt)<=t||BigInt(att.payload.expiresAt)>t+120n)return invalid("EXPIRED");
   const sig=Buffer.from(att.signature,"base64url");if(sig.length!==64)return invalid("SIGNATURE_FORMAT");
   if(!edVerify(null,Buffer.from(payload),key.publicKey,sig))return invalid("SIGNATURE");
   return Object.freeze({ok:true,status:"LAB_CRYPTO_ATTESTED",payload:att.payload});
  }catch{return invalid("INVALID");}
 }});
}
export function canonicalAttestationPayload(payload){return canonical(payload)}

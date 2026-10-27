// GFLO IB-03U DRAFT: versioned binary canonical preimages; NOT a SIWE verifier.
// Schema order, big-endian integers, exact UTF-8 and fixed-width hex fields.
import {createHash,createHmac,sign,verify} from 'node:crypto';
export const ADMISSION_TAG='GFLO:IB03U:ADMISSION:V1\0';
export const ATTESTATION_TAG='GFLO:IB03U:ATTESTATION:V1\0';
export const ADMISSION_FIELDS=Object.freeze([
 ['kid','id'],['keyEpoch','u64'],['nonce','hex16'],['issuedAt','u64'],
 ['expiresAt','u64'],['audience','audience'],['message','utf8'],['signature','hex65'],
 ['subject','id'],['sessionId','id'],['expectedDomain','domain'],['expectedUri','uri'],
 ['expectedChain','u64'],['issuerKeyId','id'],['issuerKeyEpoch','u64'],['sessionSeconds','u32']
]);
export const ATTESTATION_FIELDS=Object.freeze([
 ['kid','id'],['keyEpoch','u64'],['challengeId','nonce'],['subject','id'],['chainId','u64'],
 ['wallet','hex20'],['messageDigest','hex32'],['sessionId','id'],
 ['bindingGeneration','u64'],['consentGeneration','u64'],['sessionSeconds','u32'],
 ['expiresAt','u64'],['domain','domain'],['uri','uri'],['scope','scope'],
 ['issuedAt','u64'],['contextExpiresAt','u64']
]);
const U64_MAX=(1n<<64n)-1n;
const unsigned=(v,max)=>{
 if(typeof v!=='string'||!/^(0|[1-9][0-9]*)$/.test(v))throw Error('NONCANONICAL_UNSIGNED_INTEGER');
 const n=BigInt(v);if(n>max)throw Error('INTEGER_RANGE');return n;
};
const frame=b=>{
 if(b.length>0xffffffff)throw Error('LENGTH_RANGE');
 const h=Buffer.alloc(4);h.writeUInt32BE(b.length);
 return Buffer.concat([h,b]);
};
function bytes(v,kind){
 if(typeof v!=='string')throw Error('NON_STRING');
 if(kind.startsWith('hex')){
  const n=Number(kind.slice(3)),prefix=(n===20||n===65)?'0x':'';
  if(!new RegExp('^'+prefix+'[0-9a-f]{'+2*n+'}$').test(v))throw Error('NONCANONICAL_HEX');
  return Buffer.from(v.slice(prefix.length),'hex');
 }
 if(kind==='id'&&!/^[A-Za-z0-9_-]{1,128}$/.test(v))throw Error('INVALID_IDENTIFIER');
 if(kind==='nonce'&&!/^[A-Za-z0-9]{8,128}$/.test(v))throw Error('INVALID_SIWE_NONCE');
 if(kind==='audience'&&v!=='gflo-issuer-ib03u')throw Error('INVALID_AUDIENCE');
 if(kind==='scope'&&v!=='pie:xp:read')throw Error('INVALID_SCOPE');
 if(kind==='domain'&&(!/^[a-z0-9.-]{1,255}(?::[0-9]{1,5})?$/.test(v)||v.includes('..')))throw Error('NONCANONICAL_DOMAIN');
 if(kind==='uri'&&(!/^https:\/\/[\x21-\x7e]{1,2040}$/.test(v)||v.includes('|')))throw Error('NONCANONICAL_URI');
 if(kind==='utf8'&&(v.includes('\r')||Buffer.from(v,'utf8').toString('utf8')!==v))throw Error('INVALID_UTF8_MESSAGE');
 if(!v.length)throw Error('EMPTY_TEXT');
 return frame(Buffer.from(v,'utf8'));
}
function encode(tag,fields,obj){
 if(!obj||typeof obj!=='object'||Array.isArray(obj))throw Error('INVALID_RECORD');
 if(Object.keys(obj).sort().join('\0')!==fields.map(x=>x[0]).sort().join('\0'))throw Error('SCHEMA_MISMATCH');
 const result=[Buffer.from(tag,'ascii')];
 for(const [name,type] of fields){
  if(type==='u64'||type==='u32'){
   const size=type==='u64'?8:4,n=unsigned(obj[name],size===8?U64_MAX:0xffffffffn);
   const b=Buffer.alloc(size);if(size===8)b.writeBigUInt64BE(n);else b.writeUInt32BE(Number(n));
   result.push(b);
  }else result.push(bytes(obj[name],type));
 }
 return Buffer.concat(result);
}
export const admissionPreimage=x=>encode(ADMISSION_TAG,ADMISSION_FIELDS,x);
export const attestationPreimage=x=>encode(ATTESTATION_TAG,ATTESTATION_FIELDS,x);
export const sha256=b=>createHash('sha256').update(b).digest('hex');
export const attestMac=(key,record)=>{
 if(!Buffer.isBuffer(key)||key.length!==32)throw Error('MAC_KEY_LENGTH');
 return createHmac('sha256',key).update(attestationPreimage(record)).digest('hex');
};
export const signAdmission=(privateKey,record)=>sign(null,admissionPreimage(record),privateKey).toString('hex');
export const verifyAdmission=(publicKey,record,signatureHex)=>{
 if(typeof signatureHex!=='string'||!/^[0-9a-f]{128}$/.test(signatureHex))return false;
 return verify(null,admissionPreimage(record),publicKey,Buffer.from(signatureHex,'hex'));
};

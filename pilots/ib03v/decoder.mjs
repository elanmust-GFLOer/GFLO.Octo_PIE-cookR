// GFLO IB-03V draft byte-level inverse of IB-03U canonical encoders.
// Structural decode alone NEVER grants admission: verify signature/MAC and DB fences.
import {TextDecoder} from 'node:util';
import {ADMISSION_TAG,ATTESTATION_TAG,ADMISSION_FIELDS,ATTESTATION_FIELDS,admissionPreimage,attestationPreimage} from '../ib03u/protocol.mjs';
const utf8=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true});
const deny=x=>{throw Error('DECODE_'+x)};
const equal=(a,b)=>a.length===b.length&&a.equals(b);
function decode(source,tag,fields,encoder,maxBytes=65536){
 if(!Buffer.isBuffer(source)||source.length>maxBytes)deny('INPUT');
 const prefix=Buffer.from(tag,'ascii');
 if(!source.subarray(0,prefix.length).equals(prefix))deny('VERSION_OR_KIND');
 let at=prefix.length;
 const consume=n=>{if(n<0||at+n>source.length)deny('TRUNCATED');const b=source.subarray(at,at+n);at+=n;return b};
 const result=Object.create(null);
 for(const [name,kind] of fields){
  if(kind==='u64'){result[name]=consume(8).readBigUInt64BE(0).toString();continue}
  if(kind==='u32'){result[name]=consume(4).readUInt32BE(0).toString();continue}
  if(kind.startsWith('hex')){const n=Number(kind.slice(3));result[name]=(n===20||n===65?'0x':'')+consume(n).toString('hex');continue}
  const length=consume(4).readUInt32BE(0);
  if(length>16384)deny('FRAME_TOO_LARGE');
  result[name]=utf8.decode(consume(length));
 }
 if(at!==source.length)deny('TRAILING');
 let canonical;
 try{canonical=encoder(result)}catch{deny('NONCANONICAL')}
 if(!equal(source,canonical))deny('NONCANONICAL');
 return Object.freeze(result);
}
export const decodeAdmission=b=>decode(b,ADMISSION_TAG,ADMISSION_FIELDS,admissionPreimage);
export const decodeAttestation=b=>decode(b,ATTESTATION_TAG,ATTESTATION_FIELDS,attestationPreimage);
// Enforcement entrypoint refuses legacy frames before any crypto operation.
export function classifyEnvelope(input){
 if(!Buffer.isBuffer(input))return 'INVALID';
 if(input.subarray(0,Buffer.byteLength(ADMISSION_TAG)).equals(Buffer.from(ADMISSION_TAG,'ascii')))return 'IB03U_ADMISSION';
 if(input.subarray(0,Buffer.byteLength(ATTESTATION_TAG)).equals(Buffer.from(ATTESTATION_TAG,'ascii')))return 'IB03U_ATTESTATION';
 if(input.length&&[0x7b,0x5b].includes(input[0]))return 'LEGACY_JSON_UNTRUSTED';
 return 'UNKNOWN_UNTRUSTED';
}
export function migrationDecision({preimage,keyScope,minimumVersion}){
 const type=classifyEnvelope(preimage);
 if(minimumVersion!=='IB03U_V1')return Object.freeze({accepted:false,reason:'UNPINNED_POLICY'});
 if(keyScope!=='gflo-ib03u-admission'&&keyScope!=='gflo-ib03u-attestation')return Object.freeze({accepted:false,reason:'KEY_SCOPE'});
 if((type==='IB03U_ADMISSION'&&keyScope!=='gflo-ib03u-admission')||
    (type==='IB03U_ATTESTATION'&&keyScope!=='gflo-ib03u-attestation'))
   return Object.freeze({accepted:false,reason:'KIND_SCOPE'});
 try{
  if(type==='IB03U_ADMISSION')decodeAdmission(preimage);
  else if(type==='IB03U_ATTESTATION')decodeAttestation(preimage);
  else return Object.freeze({accepted:false,reason:'LEGACY_OR_UNKNOWN'});
  // This only authorizes handoff to cryptographic verifier, never session issuance.
  return Object.freeze({accepted:true,status:'STRUCTURAL_ONLY_NOT_AUTHENTICATED'});
 }catch{return Object.freeze({accepted:false,reason:'NONCANONICAL'});}
}

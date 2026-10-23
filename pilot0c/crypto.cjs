'use strict';
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const manifest=require('./dependency-manifest.json');
const artifact=fs.readFileSync(path.join(__dirname,'vendor/ethers.umd.min.cjs'));
if(createHash('sha256').update(artifact).digest('hex')!==manifest.sha256) throw Error('DEPENDENCY_UNVERIFIED');
const e=require('./vendor/ethers.umd.min.cjs');
if(e.version!=='6.15.0') throw Error('DEPENDENCY_UNVERIFIED');
const HALF_N=0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;
function canonicalSignature(signature){
  if(typeof signature!=='string'||!/^0x[0-9a-fA-F]{130}$/.test(signature)) throw Error('SIGNATURE_INVALID');
  const s=BigInt('0x'+signature.slice(66,130));
  if(s===0n||s>HALF_N||!['1b','1c'].includes(signature.slice(130).toLowerCase())) throw Error('SIGNATURE_INVALID');
  return signature;
}
module.exports=Object.freeze({
  address:e.getAddress,
  messageHash:e.hashMessage,
  typedHash:e.TypedDataEncoder.hash,
  keccakText:text=>e.keccak256(e.toUtf8Bytes(text)),
  recoverMessage:(message,signature)=>e.verifyMessage(message,canonicalSignature(signature)),
  recoverConsent:(domain,types,value,signature)=>e.verifyTypedData(domain,types,value,canonicalSignature(signature))
});

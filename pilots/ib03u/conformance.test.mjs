import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createPrivateKey} from 'node:crypto';
import {admissionPreimage,attestationPreimage,sha256,attestMac,verifyAdmission,signAdmission} from './protocol.mjs';
const f=JSON.parse(readFileSync(new URL('./vectors.json',import.meta.url),'utf8'));
assert.equal(f.testOnly,true);
const privateKey=createPrivateKey({key:Buffer.from('302e020100300506032b657004220420'+f.testOnlySeedHex,'hex'),format:'der',type:'pkcs8'});
for(const v of f.vectors){
 const a=admissionPreimage(v.admission),t=attestationPreimage(v.attestation);
 assert.equal(a.length,v.admissionLength);assert.equal(t.length,v.attestationLength);
 assert.equal(sha256(a),v.admissionSha256);assert.equal(sha256(t),v.attestationSha256);
 assert.equal(signAdmission(privateKey,v.admission),v.ed25519SignatureHex);
 assert.equal(verifyAdmission(f.publicSpkiPem,v.admission,v.ed25519SignatureHex),true);
 assert.equal(attestMac(Buffer.from(f.testOnlyMacKeyHex,'hex'),v.attestation),v.hmacSha256);
 for(const mutation of [{keyEpoch:'8'},{issuerKeyEpoch:'4'},{expectedChain:'1'},{message:v.admission.message+'!'}])
  assert.equal(verifyAdmission(f.publicSpkiPem,{...v.admission,...mutation},v.ed25519SignatureHex),false);
 assert.throws(()=>admissionPreimage({...v.admission,forged:true}),/SCHEMA_MISMATCH/);
 assert.throws(()=>admissionPreimage({...v.admission,nonce:'bad_underscore'}),/NONCANONICAL_HEX/);
 assert.throws(()=>admissionPreimage({...v.admission,keyEpoch:'07'}),/NONCANONICAL_UNSIGNED_INTEGER/);
 assert.throws(()=>admissionPreimage({...v.admission,expectedUri:'https://example.test/x|evil'}),/NONCANONICAL_URI/);
 assert.throws(()=>admissionPreimage({...v.admission,message:'bad\ud800'}),/INVALID_UTF8_MESSAGE/);
 for(const mutation of [{consentGeneration:'10'},{uri:'https://example.test/other'},{keyEpoch:'4'}])
  assert.notEqual(attestMac(Buffer.from(f.testOnlyMacKeyHex,'hex'),{...v.attestation,...mutation}),v.hmacSha256);
 console.log('PASS node canonical positive+negative:',v.label);
}
console.log('IB03U_NODE_GOLDEN_VECTORS_PASS');

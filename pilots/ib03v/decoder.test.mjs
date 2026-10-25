import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {admissionPreimage,attestationPreimage,verifyAdmission,attestMac} from '../ib03u/protocol.mjs';
import {decodeAdmission,decodeAttestation,migrationDecision,classifyEnvelope} from './decoder.mjs';
const fixture=JSON.parse(readFileSync(new URL('../ib03u/vectors.json',import.meta.url),'utf8'));
const k=Buffer.from(fixture.testOnlyMacKeyHex,'hex');
const policy=(preimage,keyScope,minimumVersion='IB03U_V1')=>migrationDecision({preimage,keyScope,minimumVersion});
for(const v of fixture.vectors){
 const admission=admissionPreimage(v.admission),attestation=attestationPreimage(v.attestation);
 assert.deepEqual({...decodeAdmission(admission)},v.admission);
 assert.deepEqual({...decodeAttestation(attestation)},v.attestation);
 assert.equal(policy(admission,'gflo-ib03u-admission').accepted,true);
 assert.equal(policy(attestation,'gflo-ib03u-attestation').accepted,true);
 assert.equal(verifyAdmission(fixture.publicSpkiPem,decodeAdmission(admission),v.ed25519SignatureHex),true);
 assert.equal(attestMac(k,decodeAttestation(attestation)),v.hmacSha256);
 for(const b of [admission.subarray(0,-1),Buffer.concat([admission,Buffer.from([0])]),attestation.subarray(0,-1),Buffer.concat([attestation,Buffer.from([0])])]){
  assert.equal(policy(b,'gflo-ib03u-'+(b[0]===0?'admission':'admission')).accepted,false);
 }
 assert.equal(policy(admission,'gflo-ib03u-attestation').accepted,false);
 assert.equal(policy(attestation,'gflo-ib03u-admission').accepted,false);
 assert.equal(policy(admission,'gflo-ib03u-admission','IB03T').accepted,false);
 assert.equal(policy(Buffer.from(JSON.stringify(v.admission)),'gflo-ib03u-admission').accepted,false);
 assert.equal(policy(Buffer.from('GFLO_IB03T_EPOCH_V1'),'gflo-ib03u-admission').accepted,false);
 const changed=Buffer.from(admission);changed[changed.length-1]^=1;
 assert.equal(verifyAdmission(fixture.publicSpkiPem,decodeAdmission(changed),v.ed25519SignatureHex),false);
 console.log('PASS IB03V strict roundtrip, signatures, MAC and legacy deny:',v.label);
}
const v=fixture.vectors[0],original=admissionPreimage(v.admission);
// Overwrite four-byte length of first framed 'kid' beyond buffer boundary.
const oversized=Buffer.from(original);
const kidStart=Buffer.byteLength('GFLO:IB03U:ADMISSION:V1\0');
oversized.writeUInt32BE(0xffffffff,kidStart);
assert.throws(()=>decodeAdmission(oversized),/DECODE_FRAME_TOO_LARGE/);
assert.equal(classifyEnvelope(Buffer.from('{"legacy":true}')),'LEGACY_JSON_UNTRUSTED');
assert.equal(policy(Buffer.from('{"legacy":true}'),'gflo-ib03u-admission').reason,'LEGACY_OR_UNKNOWN');
assert.throws(()=>decodeAttestation(original),/DECODE_VERSION_OR_KIND/);
console.log('IB03V_STRICT_DECODER_DOWNGRADE_LAB_PASS production=BLOCK');

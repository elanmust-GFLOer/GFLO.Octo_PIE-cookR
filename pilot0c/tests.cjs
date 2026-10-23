'use strict';
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const fs=require('node:fs'),path=require('node:path');
const p=require('./proof.cjs'),c=require('./crypto.cjs');
const e=require('./vendor/ethers.umd.min.cjs');
const tests=[];function test(name,run){tests.push({name,run});}
const A='11111111-1111-4111-8111-111111111111',B='22222222-2222-4222-8222-222222222222';
const PA='33333333-3333-4333-8333-333333333333',PB='44444444-4444-4444-8444-444444444444';
function wallet(){
 // Key-bearing object never leaves this closure; never inspected/serialized.
 const secret=e.Wallet.createRandom();
 return Object.freeze({address:secret.address,signMessage:m=>secret.signMessage(m),
  signConsent:(d,t,v)=>secret.signTypedData(d,t,v),
  signRaw:m=>secret.signingKey.sign(e.keccak256(e.toUtf8Bytes(m))).serialized});
}
function fixture(options={}){
 const clock={wall:1800000000,mono:0};const now=()=>clock.wall;
 const authority=new p.SyntheticAuthority([[A,PA],[B,PB]],now),ha=authority.issue(A),hb=authority.issue(B);
 const fence=new p.SyntheticFence([A,B]),audit=new p.SyntheticAudit(),wa=wallet(),wb=wallet();
 const source={chainId:p.CHAIN,contract:options.legacy?'0x9cf55d0b9d61dc28ef3cb10765cf4b861cd0991e':'0x1111111111111111111111111111111111111111',
  reference:'https://pilot0c.invalid/protocol/'+(options.legacy?'legacy-sepolia':'demo'),
  manifestDigest:options.legacy?p.digest(fs.readFileSync(path.join(__dirname,'../pilot0b/legacy-sepolia.incomplete.json'))):p.digest('explicit synthetic source fixture'),classification:'DEMO_FIXTURE'};
 const selectedAudit=options.audit?{approve:event=>options.audit({event,authority,ha,hb,fence,audit,clock})}:audit;
 const proof=new p.OfflineProof({authority,fence,audit:selectedAudit,wallets:[{address:wa.address,kind:options.kind||'EOA'},{address:wb.address,kind:'EOA'}],
  sources:[source],clock:now,monotonic:()=>clock.mono});
 const issue=(handle=ha,w=wa,requestId=randomUUID())=>proof.issue(handle,{wallet:w.address,source:source.reference,requestId});
 return {clock,authority,ha,hb,fence,audit,wa,wb,source,proof,issue};
}
async function signed(ch,w){return {challengeId:ch.challengeId,message:ch.message,siweSignature:await w.signMessage(ch.message),
 consent:JSON.stringify(ch.consent),consentSignature:await w.signConsent(ch.consentDomain,ch.consentTypes,ch.consent)};}
function denied(r,reason){assert.equal(r.kind,'DENIED');if(reason)assert.equal(r.reason,reason);assert.equal(r.productionAuthorized,false);assert.equal(r.canonicalXpAuthorized,false);assert.equal(r.mutationCapabilities.length,0);}
async function valid(f,handle=f.ha,w=f.wa){const ch=f.issue(handle,w);return {ch,input:await signed(ch,w)};}
async function siweChange(transform){const f=fixture(),{input}=await valid(f);input.message=transform(input.message,f);input.siweSignature=await f.wa.signMessage(input.message);
 assert.equal(c.recoverMessage(input.message,input.siweSignature),f.wa.address);denied(await f.proof.verify(f.ha,input));}
async function consentChange(key,value){const f=fixture(),{ch,input}=await valid(f);const v={...ch.consent,[key]:typeof value==='function'?value(f):value};
 input.consent=JSON.stringify(v);input.consentSignature=await f.wa.signConsent(ch.consentDomain,ch.consentTypes,v);
 assert.equal(c.recoverConsent(ch.consentDomain,ch.consentTypes,v,input.consentSignature),f.wa.address);
 denied(await f.proof.verify(f.ha,input),'CONSENT_CONTEXT_MISMATCH');}

test('crypto.public_eip712_mail_vector',()=>{
 const domain={name:'Ether Mail',version:'1',chainId:1,verifyingContract:'0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC'};
 const types={Person:[{name:'name',type:'string'},{name:'wallet',type:'address'}],Mail:[{name:'from',type:'Person'},{name:'to',type:'Person'},{name:'contents',type:'string'}]};
 const value={from:{name:'Cow',wallet:'0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826'},to:{name:'Bob',wallet:'0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB'},contents:'Hello, Bob!'};
 const signature='0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c';
 assert.equal(c.recoverConsent(domain,types,value,signature),value.from.wallet);
 assert.equal(c.typedHash(domain,types,value),'0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2');
});
test('crypto.real_eoa_siwe_and_separate_consent',async()=>{const f=fixture(),{ch,input}=await valid(f);assert.equal(c.recoverMessage(ch.message,input.siweSignature),f.wa.address);
 assert.equal(c.recoverConsent(ch.consentDomain,ch.consentTypes,ch.consent,input.consentSignature),f.wa.address);const r=await f.proof.verify(f.ha,input);assert.equal(r.kind,'OFFLINE_READ_ONLY_OBSERVATION');assert.equal(r.profile,PA);});
test('crypto.second_profile_independent_success',async()=>{const f=fixture(),{input}=await valid(f,f.hb,f.wb);const r=await f.proof.verify(f.hb,input);assert.equal(r.kind,'OFFLINE_READ_ONLY_OBSERVATION');assert.equal(r.profile,PB);});
test('crypto.raw_digest_is_not_personal_sign',async()=>{const f=fixture(),{input}=await valid(f);input.siweSignature=f.wa.signRaw(input.message);denied(await f.proof.verify(f.ha,input),'SIWE_SIGNER_MISMATCH');});
test('crypto.siwe_cannot_substitute_for_consent',async()=>{const f=fixture(),{input}=await valid(f);input.consentSignature=input.siweSignature;denied(await f.proof.verify(f.ha,input));});
test('crypto.missing_consent_signature',async()=>{const f=fixture(),{input}=await valid(f);input.consentSignature='';denied(await f.proof.verify(f.ha,input));});
test('crypto.wrong_siwe_signer',async()=>{const f=fixture(),{input}=await valid(f);input.siweSignature=await f.wb.signMessage(input.message);denied(await f.proof.verify(f.ha,input),'SIWE_SIGNER_MISMATCH');});
test('crypto.wrong_consent_signer',async()=>{const f=fixture(),{ch,input}=await valid(f);input.consentSignature=await f.wb.signConsent(ch.consentDomain,ch.consentTypes,ch.consent);denied(await f.proof.verify(f.ha,input),'CONSENT_SIGNER_MISMATCH');});
test('crypto.signature_tampering',async()=>{const f=fixture(),{input}=await valid(f);input.siweSignature=input.siweSignature.slice(0,10)+(input.siweSignature[10]==='a'?'b':'a')+input.siweSignature.slice(11);denied(await f.proof.verify(f.ha,input));});
test('crypto.zero_signature',async()=>{const f=fixture(),{input}=await valid(f);input.siweSignature='0x'+'00'.repeat(64)+'1b';denied(await f.proof.verify(f.ha,input));});
test('crypto.high_s_malleability_rejected',async()=>{const f=fixture(),{input}=await valid(f);const n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
 const high=(n-BigInt('0x'+input.siweSignature.slice(66,130))).toString(16).padStart(64,'0');input.siweSignature=input.siweSignature.slice(0,66)+high+(input.siweSignature.slice(130)==='1b'?'1c':'1b');denied(await f.proof.verify(f.ha,input));});
test('crypto.compact_signature_not_supported',async()=>{const f=fixture(),{input}=await valid(f);input.siweSignature=e.Signature.from(input.siweSignature).compactSerialized;denied(await f.proof.verify(f.ha,input));});
test('crypto.foreign_typed_domain',async()=>{const f=fixture(),{ch,input}=await valid(f);input.consentSignature=await f.wa.signConsent({...ch.consentDomain,name:'foreign'},ch.consentTypes,ch.consent);denied(await f.proof.verify(f.ha,input));});
test('crypto.foreign_typed_chain',async()=>{const f=fixture(),{ch,input}=await valid(f);input.consentSignature=await f.wa.signConsent({...ch.consentDomain,chainId:1},ch.consentTypes,ch.consent);denied(await f.proof.verify(f.ha,input));});
test('siwe.canonical_abnf_subset_parses',async()=>{const f=fixture(),ch=f.issue();const r=p.parseSiwe(ch.message);assert.equal(r.wallet,f.wa.address);assert.equal(r.resources.length,4);assert.equal(r.domain,p.DOMAIN);});
test('siwe.foreign_domain_with_valid_signature',()=>siweChange(m=>m.replace(p.DOMAIN,'foreign.invalid')));
test('siwe.foreign_uri_with_valid_signature',()=>siweChange(m=>m.replace(p.URI,'https://foreign.invalid/id-entity')));
test('siwe.foreign_chain_with_valid_signature',()=>siweChange(m=>m.replace('Chain ID: 11155111','Chain ID: 1')));
test('siwe.foreign_wallet_with_valid_signature',()=>siweChange((m,f)=>m.replace(f.wa.address,f.wb.address)));
test('siwe.foreign_nonce_with_valid_signature',()=>siweChange(m=>m.replace(/Nonce: [a-f0-9]+/,'Nonce: '+'a'.repeat(64))));
test('siwe.foreign_request_with_valid_signature',()=>siweChange(m=>m.replace(/Request ID: [a-f0-9-]+/,'Request ID: '+randomUUID())));
test('siwe.foreign_profile_resource',()=>siweChange(m=>m.replace(PA,PB)));
test('siwe.modified_issued_at',()=>siweChange(m=>m.replace(/Issued At: [^\n]+/,'Issued At: 2025-01-01T00:00:00Z')));
test('siwe.modified_expiration',()=>siweChange(m=>m.replace(/Expiration Time: [^\n]+/,'Expiration Time: 2099-01-01T00:00:00Z')));
test('siwe.crlf_is_rejected',()=>siweChange(m=>m.replaceAll('\n','\r\n')));
test('siwe.control_character_rejected',()=>siweChange(m=>m+'\u0000'));
test('siwe.oversized_message_rejected',()=>siweChange(m=>m+'a'.repeat(5000)));
test('siwe.duplicate_field_rejected',()=>siweChange(m=>m+'\nNonce: abcdefgh'));
test('siwe.unsupported_version_rejected',()=>siweChange(m=>m.replace('Version: 1','Version: 2')));
test('siwe.invalid_calendar_date_rejected',()=>siweChange(m=>m.replace(/Issued At: [^\n]+/,'Issued At: 2025-02-30T00:00:00Z')));
test('consent.principal_substitution',()=>consentChange('principal',B));
test('consent.profile_substitution',()=>consentChange('profile',PB));
test('consent.wallet_substitution',()=>consentChange('wallet',f=>f.wb.address));
test('consent.chain_substitution',()=>consentChange('chainId',1));
test('consent.source_substitution',()=>consentChange('protocolSource','https://foreign.invalid/protocol'));
test('consent.manifest_digest_substitution',()=>consentChange('protocolManifestDigest',p.digest('wrong')));
test('consent.scope_escalation',()=>consentChange('scopes',['wallet.binding.activate']));
test('consent.duplicate_scope_rejected',()=>consentChange('scopes',[p.SCOPE,p.SCOPE]));
test('consent.empty_scope_rejected',()=>consentChange('scopes',[]));
test('consent.generation_substitution',()=>consentChange('generation',1));
test('consent.nonce_substitution',()=>consentChange('nonce','0x'+'11'.repeat(32)));
test('consent.expiration_substitution',()=>consentChange('expiresAt',1900000000));
test('consent.version_substitution',()=>consentChange('consentVersion','production/1'));
test('consent.text_digest_substitution',()=>consentChange('consentTextDigest',p.digest('binding activation')));
test('consent.siwe_digest_substitution',()=>consentChange('siweMessageHash',p.digest('other proof')));
test('consent.expired_at_exact_boundary',async()=>{const f=fixture(),{ch,input}=await valid(f);f.clock.wall=ch.expiresAt;denied(await f.proof.verify(f.ha,input),'CONSENT_EXPIRED');});
test('consent.revoked_before_verification',async()=>{const f=fixture(),{ch,input}=await valid(f);f.proof.revokeConsent(f.ha,ch.challengeId);denied(await f.proof.verify(f.ha,input),'CONSENT_REVOKED');});
test('consent.revocation_during_verification',async()=>{const f=fixture(),{ch,input}=await valid(f);const pending=f.proof.verify(f.ha,input);f.proof.revokeConsent(f.ha,ch.challengeId);denied(await pending,'CONSENT_REVOKED');});
test('auth.forged_principal_context',()=>{const f=fixture();assert.throws(()=>f.issue({principal:A,profile:PA}),x=>x.code==='AUTH_UNVERIFIED');});
test('auth.caller_profile_input_rejected',()=>{const f=fixture();assert.throws(()=>f.proof.issue(f.ha,{wallet:f.wa.address,source:f.source.reference,requestId:randomUUID(),profile:PB}),x=>x.code==='INPUT_INVALID');});
test('auth.a_cannot_redeem_b_proof',async()=>{const f=fixture(),{input}=await valid(f,f.hb,f.wb);denied(await f.proof.verify(f.ha,input),'PROOF_DENIED');assert.equal((await f.proof.verify(f.hb,input)).kind,'OFFLINE_READ_ONLY_OBSERVATION');});
test('auth.b_cannot_redeem_a_proof',async()=>{const f=fixture(),{input}=await valid(f);denied(await f.proof.verify(f.hb,input),'PROOF_DENIED');});
test('auth.same_user_different_session_cannot_redeem',async()=>{const f=fixture(),{input}=await valid(f);denied(await f.proof.verify(f.authority.issue(A),input),'PROOF_DENIED');});
test('auth.revoked_session',async()=>{const f=fixture(),{input}=await valid(f);f.authority.setState(f.ha,'REVOKED');denied(await f.proof.verify(f.ha,input),'SESSION_REVOKED');});
test('auth.unknown_session',async()=>{const f=fixture(),{input}=await valid(f);f.authority.setState(f.ha,'UNKNOWN');denied(await f.proof.verify(f.ha,input),'SESSION_UNKNOWN');});
test('auth.expired_session',async()=>{const f=fixture(),{input}=await valid(f);f.clock.wall+=301;denied(await f.proof.verify(f.ha,input),'SESSION_EXPIRED');});
test('auth.revoke_between_crypto_and_commit',async()=>{const f=fixture(),{input}=await valid(f);const pending=f.proof.verify(f.ha,input);f.authority.setState(f.ha,'REVOKED');denied(await pending,'SESSION_REVOKED');});
test('auth.unknown_between_crypto_and_commit',async()=>{const f=fixture(),{input}=await valid(f);const pending=f.proof.verify(f.ha,input);f.authority.setState(f.ha,'UNKNOWN');denied(await pending,'SESSION_UNKNOWN');});
test('auth.stale_local_generation',async()=>{const f=fixture(),{input}=await valid(f);f.fence.advance(A);denied(await f.proof.verify(f.ha,input),'GENERATION_STALE');});
test('auth.generation_race',async()=>{const f=fixture(),{input}=await valid(f);const pending=f.proof.verify(f.ha,input);f.fence.advance(A);denied(await pending,'GENERATION_STALE');});
test('auth.suspension_race',async()=>{const f=fixture(),{input}=await valid(f);const pending=f.proof.verify(f.ha,input);f.fence.suspend(A);denied(await pending,'LOCAL_SUSPENDED');});
test('auth.session_generation_changed',async()=>{const f=fixture(),{input}=await valid(f);f.authority.advance(f.ha);denied(await f.proof.verify(f.ha,input),'GENERATION_STALE');});
test('auth.outstanding_signed_proofs_after_suspension',async()=>{const f=fixture(),a=await valid(f),b=await valid(f);assert.equal((await f.proof.verify(f.ha,a.input)).kind,'OFFLINE_READ_ONLY_OBSERVATION');f.fence.suspend(A);denied(await f.proof.verify(f.ha,b.input),'LOCAL_SUSPENDED');});
test('auth.old_proof_denied_after_authority_and_local_epoch_advance',async()=>{const f=fixture(),{input}=await valid(f);f.fence.advance(A);f.authority.advance(f.ha);denied(await f.proof.verify(f.ha,input),'GENERATION_STALE');});
test('auth.suspended_profile_cannot_issue',()=>{const f=fixture();f.fence.suspend(A);assert.throws(()=>f.issue(),x=>x.code==='LOCAL_SUSPENDED');});
test('consent.foreign_profile_cannot_revoke',async()=>{const f=fixture(),{ch,input}=await valid(f);assert.throws(()=>f.proof.revokeConsent(f.hb,ch.challengeId),x=>x.code==='PROOF_DENIED');assert.equal((await f.proof.verify(f.ha,input)).kind,'OFFLINE_READ_ONLY_OBSERVATION');});
test('replay.consumed_proof_rejected',async()=>{const f=fixture(),{input}=await valid(f);await f.proof.verify(f.ha,input);denied(await f.proof.verify(f.ha,input),'PROOF_REPLAY');});
test('replay.concurrent_identical_proof_exactly_once',async()=>{const f=fixture(),{input}=await valid(f);const r=await Promise.all([f.proof.verify(f.ha,input),f.proof.verify(f.ha,input)]);
 assert.equal(r.filter(x=>x.kind==='OFFLINE_READ_ONLY_OBSERVATION').length,1);denied(r.find(x=>x.kind==='DENIED'),'PROOF_REPLAY');assert.equal(f.audit.snapshot().filter(x=>x.code==='PROOF_APPROVAL').length,1);});
test('replay.cross_request_proof_rejected',async()=>{const f=fixture(),a=await valid(f),b=f.issue();denied(await f.proof.verify(f.ha,{...a.input,challengeId:b.challengeId}),'SIWE_CONTEXT_MISMATCH');assert.equal((await f.proof.verify(f.ha,a.input)).kind,'OFFLINE_READ_ONLY_OBSERVATION');});
test('replay.siwe_from_other_request_rejected',async()=>{const f=fixture(),a=await valid(f),b=await valid(f);b.input.siweSignature=a.input.siweSignature;denied(await f.proof.verify(f.ha,b.input));});
test('replay.consent_from_other_request_rejected',async()=>{const f=fixture(),a=await valid(f),b=await valid(f);b.input.consentSignature=a.input.consentSignature;denied(await f.proof.verify(f.ha,b.input));});
test('replay.duplicate_request_id_rejected',()=>{const f=fixture(),rid=randomUUID();f.issue(f.ha,f.wa,rid);assert.throws(()=>f.issue(f.ha,f.wa,rid),x=>x.code==='REQUEST_REPLAY');});
test('replay.conflicting_request_payload_rejected',()=>{const f=fixture(),rid=randomUUID();f.issue(f.ha,f.wa,rid);assert.throws(()=>f.issue(f.ha,f.wb,rid),x=>x.code==='REQUEST_DIGEST_CONFLICT');});
test('replay.concurrent_distinct_requests_do_not_conflict',async()=>{const f=fixture(),a=await valid(f),b=await valid(f);const r=await Promise.all([f.proof.verify(f.ha,a.input),f.proof.verify(f.ha,b.input)]);assert.equal(r.filter(x=>x.kind==='OFFLINE_READ_ONLY_OBSERVATION').length,2);});
test('replay.failed_signature_does_not_consume_victim_challenge',async()=>{const f=fixture(),{input}=await valid(f);denied(await f.proof.verify(f.ha,{...input,consentSignature:''}));assert.equal((await f.proof.verify(f.ha,input)).kind,'OFFLINE_READ_ONLY_OBSERVATION');});
test('replay.lost_response_retry_never_reissues_result',async()=>{const f=fixture(),{input}=await valid(f);await f.proof.verify(f.ha,input);denied(await f.proof.verify(f.ha,input),'PROOF_REPLAY');});
test('audit.unavailable_sink_denies',async()=>{const f=fixture(),{input}=await valid(f);f.audit.available=false;denied(await f.proof.verify(f.ha,input),'AUDIT_UNAVAILABLE');});
test('audit.authority_failure_during_approval',async()=>{const f=fixture({audit:({event,authority,ha,audit})=>{audit.approve(event);if(event.code==='PROOF_APPROVAL')authority.setState(ha,'UNKNOWN');return true;}}),{input}=await valid(f);denied(await f.proof.verify(f.ha,input),'SESSION_UNKNOWN');});
test('audit.generation_fence_after_approval',async()=>{const f=fixture({audit:({event,fence,audit})=>{audit.approve(event);if(event.code==='PROOF_APPROVAL')fence.advance(A);return true;}}),{input}=await valid(f);denied(await f.proof.verify(f.ha,input),'GENERATION_STALE');});
test('deadline.expiration_during_audit',async()=>{const f=fixture({audit:({event,clock,audit})=>{audit.approve(event);if(event.code==='PROOF_APPROVAL')clock.mono+=1000;return true;}}),{input}=await valid(f);denied(await f.proof.verify(f.ha,input),'AUTHORIZATION_EXPIRED');});
test('deadline.expiration_before_final_release',async()=>{const f=fixture(),{input}=await valid(f);const pending=f.proof.verify(f.ha,input);f.clock.mono=1000;denied(await pending,'AUTHORIZATION_EXPIRED');});
test('deadline.nonmonotonic_clock',async()=>{const f=fixture(),{input}=await valid(f);const pending=f.proof.verify(f.ha,input);f.clock.mono=-1;denied(await pending,'AUTHORIZATION_EXPIRED');});
test('source.legacy_xp_never_canonical',async()=>{const f=fixture({legacy:true}),{input}=await valid(f);const r=await f.proof.verify(f.ha,input);assert.equal(r.sourceClassification,'LEGACY_UNTRUSTED_XP');assert.equal(r.canonicalXpAuthorized,false);assert.equal(r.entitlements.length,0);});
test('source.unknown_reference_denied',()=>{const f=fixture();assert.throws(()=>f.proof.issue(f.ha,{wallet:f.wa.address,source:'https://unknown.invalid',requestId:randomUUID()}),x=>x.code==='SOURCE_UNKNOWN');});
test('wallet.erc1271_not_supported',()=>{const f=fixture({kind:'ERC1271'});assert.throws(()=>f.issue(),x=>x.code==='ERC1271_NOT_SUPPORTED');});
test('wallet.unverified_type_denied',()=>{const f=fixture({kind:'UNKNOWN'});assert.throws(()=>f.issue(),x=>x.code==='WALLET_TYPE_UNVERIFIED');});
test('result.immutable_non_reusable_no_privileges',async()=>{const f=fixture(),{input}=await valid(f);const r=await f.proof.verify(f.ha,input);assert.equal(Object.isFrozen(r),true);assert.equal(Object.isFrozen(r.scopes),true);assert.equal(r.reusable,false);assert.equal(r.productionAuthorized,false);assert.equal(r.entitlements.length,0);assert.equal(r.mutationCapabilities.length,0);assert.equal(typeof f.proof.activate,'undefined');assert.equal(typeof f.proof.bind,'undefined');assert.equal(uuidTest(r.traceId),true);});
function uuidTest(s){return typeof s==='string'&&s.length===36;}
test('result.no_key_or_signature_disclosure',async()=>{const f=fixture(),{input}=await valid(f);const r=await f.proof.verify(f.ha,input);const log=JSON.stringify([r,f.audit.snapshot()]);assert.equal(/privateKey|mnemonic|signingKey|consentSignature|siweSignature/.test(log),false);assert.equal(log.includes(input.siweSignature),false);assert.equal(log.includes(input.consentSignature),false);assert.equal(log.includes(input.message),false);});
test('audit.pseudonymized_without_wallet_or_profile',async()=>{const f=fixture(),{input}=await valid(f);await f.proof.verify(f.ha,input);const log=JSON.stringify(f.audit.snapshot());for(const value of [A,PA,f.wa.address,input.message,input.siweSignature])assert.equal(log.includes(value),false);});
test('offline.no_network_or_token_operations',async()=>{const f=fixture(),{input}=await valid(f);let calls=0;const targets=[[require('node:net'),'connect'],[require('node:http'),'request'],[require('node:https'),'request']];const saved=targets.map(([o,k])=>o[k]);try{for(const [o,k] of targets)o[k]=()=>{calls++;throw Error('NETWORK_FORBIDDEN');};assert.equal((await f.proof.verify(f.ha,input)).kind,'OFFLINE_READ_ONLY_OBSERVATION');assert.equal(calls,0);}finally{targets.forEach(([o,k],i)=>{o[k]=saved[i];});}});
test('offline.no_binding_xp_tier_or_token_state',async()=>{const f=fixture(),{input}=await valid(f);const domain=Object.freeze({binding:null,xp:0,tier:0,tokens:0});const before=JSON.stringify(domain);await f.proof.verify(f.ha,input);assert.equal(JSON.stringify(domain),before);assert.equal(Object.keys(f.proof).length,0);});

test('auth.authority_exception_denies_without_disclosure',async()=>{const f=fixture(),{input}=await valid(f);f.authority.observe=()=>{throw Error('untrusted-secret-message');};const r=await f.proof.verify(f.ha,input);denied(r);assert.equal(JSON.stringify(r).includes('untrusted-secret-message'),false);});
test('audit.authority_exception_after_approval',async()=>{const f=fixture({audit:({event,authority,audit})=>{audit.approve(event);if(event.code==='PROOF_APPROVAL')authority.observe=()=>{throw Error('authority unavailable');};return true;}}),{input}=await valid(f);denied(await f.proof.verify(f.ha,input));});
test('challenge.nonce_entropy_and_uniqueness',()=>{const f=fixture();const a=p.parseSiwe(f.issue().message),b=p.parseSiwe(f.issue().message);assert.match(a.nonce,/^[a-f0-9]{64}$/);assert.notEqual(a.nonce,b.nonce);assert.notEqual(f.wa.address,f.wb.address);});
test('audit.event_capacity_is_bounded',async()=>{const f=fixture();for(let i=0;i<260;i++)denied(await f.proof.verify(f.ha,{}));assert.equal(f.audit.snapshot().length,256);});
test('dependency.corrupt_artifact_fails_closed',()=>{const {spawnSync}=require('node:child_process');const script=`const fs=require('node:fs'),old=fs.readFileSync;fs.readFileSync=function(p,...a){if(String(p).endsWith('ethers.umd.min.cjs'))return Buffer.from('corrupt');return old.call(this,p,...a);};try{require('./pilot0c/crypto.cjs');process.exitCode=1;}catch(e){if(e.message!=='DEPENDENCY_UNVERIFIED')process.exitCode=1;}`;const child=spawnSync(process.execPath,['-e',script],{cwd:path.join(__dirname,'..'),encoding:'utf8',timeout:5000});assert.equal(child.status,0);assert.equal(child.stdout,'');assert.equal(child.stderr,'');});

async function main(){
 const expected=JSON.parse(fs.readFileSync(path.join(__dirname,'test-manifest.json'),'utf8'));
 const actual=tests.map(t=>t.name).sort();
 if(new Set(actual).size!==actual.length||JSON.stringify(actual)!==JSON.stringify(expected))throw Error('EXACT_TEST_MANIFEST_MISMATCH');
 const executed=[];
 for(const t of tests){try{await t.run();executed.push({test:t.name,status:'PASS'});console.log('PASS '+t.name);}catch{executed.push({test:t.name,status:'FAIL'});console.log('FAIL '+t.name);}}
 const ok=executed.every(t=>t.status==='PASS');const ledger={status:ok?'PASS':'FAIL',runtime:process.version,
  openssl:process.versions.openssl,library:e.version,executed,expected,skipped:0,production:'BLOCK',walletTypes:{EOA:'TESTED',ERC1271:'NOT SUPPORTED'}};
 fs.mkdirSync(path.join(__dirname,'../evidence'),{recursive:true});fs.writeFileSync(path.join(__dirname,'../evidence/pilot0c-ledger.json'),JSON.stringify(ledger,null,2)+'\n');
 console.log(`PILOT_0C EXACT MANIFEST ${ok?'PASS':'FAIL'} ${executed.filter(t=>t.status==='PASS').length}/${actual.length}; production BLOCK`);
 if(!ok)process.exitCode=1;
}
if(require.main===module)main().catch(()=>{console.error('PILOT_0C_RUNNER_FAILED');process.exitCode=1;});

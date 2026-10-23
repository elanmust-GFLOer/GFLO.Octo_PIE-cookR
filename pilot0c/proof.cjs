'use strict';
// Offline synthetic proof only. No connector, domain database, or mutation dispatcher.
const {randomBytes,randomUUID,createHash,createHmac}=require('node:crypto');
const {performance}=require('node:perf_hooks');
const c=require('./crypto.cjs');
const DOMAIN='pilot0c.invalid';
const URI='https://pilot0c.invalid/id-entity';
const CHAIN=11155111;
const PROJECT='GFLO-PILOT-0C-SYNTHETIC';
const STATEMENT='Prove wallet control for one synthetic ID-Entity observation.';
const CONSENT_TEXT='Authorize one offline synthetic ID-Entity proof only. No persistent binding, XP, token, governance or access privileges.';
const SCOPE='id-entity.proof.read';
const LEGACY='0x9cf55d0b9d61dc28ef3cb10765cf4b861cd0991e';
const TYPES=Object.freeze({BindingConsent:Object.freeze([
 ['principal','string'],['profile','string'],['wallet','address'],['chainId','uint256'],
 ['protocolSource','string'],['protocolManifestDigest','bytes32'],['scopes','string[]'],
 ['generation','uint256'],['nonce','bytes32'],['challengeId','string'],['requestId','string'],
 ['siweMessageHash','bytes32'],['expiresAt','uint256'],['consentVersion','string'],
 ['consentTextDigest','bytes32'],['authProject','string']
].map(([name,type])=>Object.freeze({name,type})))});
const CONSENT_DOMAIN=Object.freeze({name:'GFLO Pilot 0C ID-Entity Consent',version:'0',chainId:CHAIN,
 salt:c.keccakText('gflo:pilot0c:offline-consent:v1')});
const LOCAL_ORIGIN='http://127.0.0.1:43817';
const DEFAULT_REALM=Object.freeze({domain:DOMAIN,uri:URI,project:PROJECT,consentDomain:CONSENT_DOMAIN});
const LOCAL_REALM=Object.freeze({domain:'127.0.0.1:43817',uri:LOCAL_ORIGIN+'/id-entity',project:'GFLO-PILOT-0D1-SYNTHETIC',
 consentDomain:Object.freeze({name:'GFLO Pilot 0D-1 Localhost Consent',version:'0',chainId:CHAIN,
 salt:c.keccakText('gflo:pilot0d1:'+LOCAL_ORIGIN+':consent:v1')})});
const REALMS=new WeakSet([DEFAULT_REALM,LOCAL_REALM]);
function localhostRealm(){return LOCAL_REALM;}
class Denied extends Error{constructor(code){super(code);this.code=code;}}
function need(ok,code){if(!ok)throw new Denied(code);}
function freeze(value){if(value&&typeof value==='object'){for(const v of Object.values(value))freeze(v);Object.freeze(value);}return value;}
function plain(value,keys){
 need(value&&typeof value==='object'&&Object.getPrototypeOf(value)===Object.prototype,'INPUT_INVALID');
 need(Reflect.ownKeys(value).every(k=>typeof k==='string'&&Object.getOwnPropertyDescriptor(value,k).get===undefined),'INPUT_INVALID');
 need(Object.keys(value).sort().join('|')===[...keys].sort().join('|'),'INPUT_INVALID');
}
function uuid(value){return typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);}
function digest(value){return '0x'+createHash('sha256').update(value).digest('hex');}
function iso(seconds){return new Date(seconds*1000).toISOString().replace('.000Z','Z');}
function date(text){
 need(typeof text==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(text),'SIWE_MALFORMED');
 const seconds=Date.parse(text)/1000;need(Number.isSafeInteger(seconds)&&iso(seconds)===text,'SIWE_MALFORMED');return seconds;
}
function parseSiwe(message,realm=DEFAULT_REALM){
 need(REALMS.has(realm),'REALM_UNVERIFIED');
 need(typeof message==='string'&&Buffer.byteLength(message)<=4096&&!/[\r\x00-\x08\x0b-\x1f\x7f-\uffff]/.test(message),'SIWE_MALFORMED');
 const l=message.split('\n');
 need(l.length===18&&l[0].endsWith(' wants you to sign in with your Ethereum account:')&&l[2]===''&&l[4]===''&&l[13]==='Resources:','SIWE_MALFORMED');
 const labels=['URI: ','Version: ','Chain ID: ','Nonce: ','Issued At: ','Expiration Time: ','Not Before: ','Request ID: '];
 const values=labels.map((prefix,i)=>{need(l[i+5].startsWith(prefix),'SIWE_MALFORMED');return l[i+5].slice(prefix.length);});
 const domain=l[0].slice(0,-' wants you to sign in with your Ethereum account:'.length);
 need(/^[a-z0-9.-]+(?::[0-9]+)?$/.test(domain)&&domain.length<=253,'SIWE_MALFORMED');
 let wallet;try{wallet=c.address(l[1]);}catch{throw new Denied('SIWE_MALFORMED');}
 need(wallet===l[1]&&values[1]==='1'&&/^[1-9][0-9]{0,14}$/.test(values[2])&&/^[A-Za-z0-9]{8,128}$/.test(values[3])&&uuid(values[7]),'SIWE_MALFORMED');
 need(l[3].length>0&&l[3].length<=256,'SIWE_MALFORMED');
 let uri;try{uri=new URL(values[0]);}catch{throw new Denied('SIWE_MALFORMED');}
 need((uri.protocol==='https:'||(realm===LOCAL_REALM&&uri.origin===LOCAL_ORIGIN))&&!uri.username&&!uri.password&&!uri.hash,'SIWE_MALFORMED');
 const resources=l.slice(14).map(line=>{need(line.startsWith('- '),'SIWE_MALFORMED');const v=line.slice(2);try{new URL(v);}catch{throw new Denied('SIWE_MALFORMED');}return v;});
 need(new Set(resources).size===resources.length,'SIWE_MALFORMED');
 return freeze({domain,wallet,statement:l[3],uri:values[0],version:1,chainId:Number(values[2]),nonce:values[3],
  issuedAt:date(values[4]),expiresAt:date(values[5]),requestId:values[7],notBefore:date(values[6]),resources});
}
function siwe(context,realm=DEFAULT_REALM){
 return `${realm.domain} wants you to sign in with your Ethereum account:\n${context.wallet}\n\n${STATEMENT}\n\nURI: ${realm.uri}\nVersion: 1\nChain ID: ${CHAIN}\nNonce: ${context.nonce}\nIssued At: ${iso(context.issuedAt)}\nExpiration Time: ${iso(context.expiresAt)}\nNot Before: ${iso(context.issuedAt)}\nRequest ID: ${context.requestId}\nResources:\n- urn:gflo:pilot0c:principal:${context.principal}\n- urn:gflo:pilot0c:profile:${context.profile}\n- urn:gflo:pilot0c:challenge:${context.id}\n- ${context.source.reference}`;
}
class SyntheticAuthority{
 #handles=new WeakMap();#owners;#clock;
 constructor(owners,clock=()=>Date.now()/1000){this.#owners=new Map(owners);this.#clock=clock;}
 // Trusted fixture administration, never request input or production identity.
 issue(principal){need(this.#owners.has(principal),'PRINCIPAL_UNKNOWN');const handle=Object.freeze({});
  this.#handles.set(handle,{principal,profile:this.#owners.get(principal),sessionId:randomUUID(),state:'ACTIVE',generation:0,expiresAt:this.#clock()+300});return handle;}
 observe(handle){const v=(handle&&typeof handle==='object')?this.#handles.get(handle):null;need(v,'AUTH_UNVERIFIED');need(Number.isFinite(this.#clock()),'AUTHORITY_UNAVAILABLE');return {...v,state:this.#clock()>=v.expiresAt?'EXPIRED':v.state};}
 setState(handle,state){need(['ACTIVE','REVOKED','UNKNOWN'].includes(state),'AUTH_STATE_INVALID');const v=this.observe(handle);this.#handles.set(handle,{...v,state});}
 advance(handle){const v=this.observe(handle);this.#handles.set(handle,{...v,generation:v.generation+1});}
}
class SyntheticFence{
 #rows=new Map();
 constructor(principals){for(const p of principals)this.#rows.set(p,{generation:0,state:'READY'});}
 observe(principal){const r=this.#rows.get(principal);need(r,'LOCAL_UNKNOWN');return {...r};}
 suspend(principal){const r=this.observe(principal);this.#rows.set(principal,{generation:r.generation+1,state:'SUSPENDED'});}
 advance(principal){const r=this.observe(principal);this.#rows.set(principal,{...r,generation:r.generation+1});}
}
class SyntheticAudit{
 #events=[];#key=randomBytes(32);available=true;
 approve(event){need(this.available,'AUDIT_UNAVAILABLE');this.#events.push(freeze({traceId:event.traceId,requestId:event.requestId,
  environment:'PILOT_0C_OFFLINE',code:event.code,actor:createHmac('sha256',this.#key).update(event.principal).digest('hex').slice(0,24)}));
  if(this.#events.length>256)this.#events.shift();return true;}
 snapshot(){return freeze(this.#events.map(x=>({...x})));}
}
class OfflineProof{
 #authority;#fence;#audit;#wallets;#sources;#records=new Map();#requests=new Map();#nonces=new Set();#clock;#mono;#realm;#deliveries=new WeakMap();
 constructor({authority,fence,audit,wallets,sources,clock=()=>Date.now()/1000,monotonic=()=>performance.now(),realm=DEFAULT_REALM}){
  need(REALMS.has(realm),'REALM_UNVERIFIED');this.#realm=realm;
  this.#authority=authority;this.#fence=fence;this.#audit=audit;
  this.#wallets=new Map(wallets.map(w=>[c.address(w.address),w.kind]));
  this.#sources=new Map(sources.map(s=>{need(s.chainId===CHAIN&&typeof s.reference==='string'&&new URL(s.reference).protocol==='https:'&&/^0x[0-9a-f]{64}$/.test(s.manifestDigest),'SOURCE_INVALID');
   const classification=s.contract.toLowerCase()===LEGACY?'LEGACY_UNTRUSTED_XP':s.classification;
   need(['DEMO_FIXTURE','LEGACY_UNTRUSTED_XP'].includes(classification),'SOURCE_UNREVIEWED');
   return [s.reference,freeze({...s,classification})];}));
  need(this.#sources.size===sources.length&&this.#wallets.size===wallets.length,'CONFIG_CONFLICT');this.#clock=clock;this.#mono=monotonic;
 }
 #time(){const t=this.#clock();need(Number.isFinite(t)&&t>=0,'CLOCK_INVALID');return t;}
 #auth(handle){const a=this.#authority.observe(handle);need(a.state==='ACTIVE',a.state==='REVOKED'?'SESSION_REVOKED':a.state==='EXPIRED'?'SESSION_EXPIRED':'SESSION_UNKNOWN');
  need(uuid(a.principal)&&uuid(a.profile)&&uuid(a.sessionId)&&Number.isSafeInteger(a.generation)&&a.generation>=0,'AUTH_UNVERIFIED');
  const local=this.#fence.observe(a.principal);need(local.state==='READY','LOCAL_SUSPENDED');need(local.generation===a.generation,'GENERATION_STALE');return a;}
 issue(handle,input){
  plain(input,['wallet','source','requestId']);need(uuid(input.requestId),'REQUEST_INVALID');const a=this.#auth(handle);
  let wallet;try{wallet=c.address(input.wallet);}catch{throw new Denied('WALLET_INVALID');}
  const kind=this.#wallets.get(wallet);need(kind==='EOA',kind==='ERC1271'?'ERC1271_NOT_SUPPORTED':'WALLET_TYPE_UNVERIFIED');
  const source=this.#sources.get(input.source);need(source,'SOURCE_UNKNOWN');const key=a.principal+':'+input.requestId;
  const requestDigest=digest(JSON.stringify([wallet,source.reference,source.manifestDigest]));
  if(this.#requests.has(key))throw new Denied(this.#requests.get(key)===requestDigest?'REQUEST_REPLAY':'REQUEST_DIGEST_CONFLICT');
  need(this.#records.size<256,'CAPACITY_EXHAUSTED');const issuedAt=Math.floor(this.#time());
  const nonce=randomBytes(32).toString('hex');need(!this.#nonces.has(nonce),'NONCE_COLLISION');
  const record={id:randomUUID(),principal:a.principal,profile:a.profile,sessionId:a.sessionId,generation:a.generation,
   wallet,source,nonce,issuedAt,expiresAt:issuedAt+60,requestId:input.requestId,status:'PENDING',consentStatus:'ACTIVE'};
  record.message=siwe(record,this.#realm);
  record.consent=freeze({principal:a.principal,profile:a.profile,wallet,chainId:CHAIN,protocolSource:source.reference,
   protocolManifestDigest:source.manifestDigest,scopes:[SCOPE],generation:a.generation,nonce:'0x'+nonce,
   challengeId:record.id,requestId:input.requestId,siweMessageHash:c.messageHash(record.message),expiresAt:record.expiresAt,
   consentVersion:'pilot0c/1',consentTextDigest:c.keccakText(CONSENT_TEXT),authProject:this.#realm.project});
  const response=freeze({challengeId:record.id,message:record.message,consent:record.consent,consentDomain:this.#realm.consentDomain,
   consentTypes:TYPES,consentText:CONSENT_TEXT,expiresAt:record.expiresAt});
  this.#auth(handle);this.#records.set(record.id,record);this.#requests.set(key,requestDigest);this.#nonces.add(nonce);return response;
 }
 revokeConsent(handle,id){const a=this.#auth(handle),r=this.#records.get(id);need(r&&r.principal===a.principal&&r.profile===a.profile,'PROOF_DENIED');r.consentStatus='REVOKED';}
 async verify(handle,input,options={}){
  const traceId=randomUUID();const started=this.#mono();let last=started;let actor='unknown',requestId='unknown';
  const limit=Math.min(started+1000,options.deadline===undefined?started+1000:options.deadline);
  const budget=()=>{const now=this.#mono();need(!options.signal?.aborted,'REQUEST_ABORTED');need(Number.isFinite(now)&&Number.isFinite(limit)&&now>=last&&now<limit,'AUTHORIZATION_EXPIRED');last=now;};
  try{
   budget();plain(input,['challengeId','message','siweSignature','consent','consentSignature']);
   need(uuid(input.challengeId),'PROOF_DENIED');const a=this.#auth(handle);const r=this.#records.get(input.challengeId);
   need(r&&r.principal===a.principal&&r.profile===a.profile&&r.sessionId===a.sessionId,'PROOF_DENIED');
   actor=a.principal;requestId=r.requestId;this.#live(r,a);const parsed=parseSiwe(input.message,this.#realm);
   need(parsed.domain===this.#realm.domain&&parsed.uri===this.#realm.uri&&parsed.chainId===CHAIN&&parsed.wallet===r.wallet&&parsed.nonce===r.nonce&&parsed.requestId===r.requestId,'SIWE_CONTEXT_MISMATCH');
   need(parsed.issuedAt===r.issuedAt&&parsed.expiresAt===r.expiresAt&&parsed.notBefore===r.issuedAt&&input.message===r.message,'SIWE_CONTEXT_MISMATCH');
   need(c.recoverMessage(input.message,input.siweSignature)===r.wallet,'SIWE_SIGNER_MISMATCH');budget();
   // Exact server-derived consent. SIWE never substitutes for this signature.
   need(typeof input.consent==='string'&&input.consent.length<=4096&&input.consent===JSON.stringify(r.consent),'CONSENT_CONTEXT_MISMATCH');
   need(c.recoverConsent(this.#realm.consentDomain,TYPES,r.consent,input.consentSignature)===r.wallet,'CONSENT_SIGNER_MISMATCH');budget();
   // Separate concurrent attempts can reach this point; final commit is synchronous.
   await Promise.resolve();budget();
   const result=freeze({kind:'OFFLINE_READ_ONLY_OBSERVATION',traceId,principal:r.principal,profile:r.profile,wallet:r.wallet,
    chainId:CHAIN,protocolSource:r.source.reference,protocolManifestDigest:r.source.manifestDigest,generation:r.generation,
    scopes:[SCOPE],expiresAt:r.expiresAt,sourceClassification:r.source.classification,
    evidenceClassifications:['DEMO_FIXTURE','VERIFIED_WALLET_CONTROL',r.source.classification],
    consentDigest:c.typedHash(this.#realm.consentDomain,TYPES,r.consent),productionAuthorized:false,canonicalXpAuthorized:false,
    mutationCapabilities:[],entitlements:[],reusable:false});
   // An approval event is not a delivery receipt. Recheck authority AFTER audit.
   const beforeAudit=this.#auth(handle);this.#live(r,beforeAudit);budget();
   need(this.#audit.approve({traceId,requestId:r.requestId,principal:r.principal,code:'PROOF_APPROVAL'})===true,'AUDIT_UNAVAILABLE');
   budget();const final=this.#auth(handle);need(final.principal===a.principal&&final.profile===a.profile&&final.sessionId===a.sessionId,'AUTH_UNVERIFIED');
   this.#live(r,final);budget();r.status='CONSUMED';this.#deliveries.set(result,r);return result;
  }catch(error){const reason=error instanceof Denied?error.code:'CRYPTO_OR_DEPENDENCY_INVALID';
   try{this.#audit.approve({traceId,requestId,principal:actor,code:'DENIED:'+reason});}catch{}
   return freeze({kind:'DENIED',traceId,reason,
   productionAuthorized:false,canonicalXpAuthorized:false,mutationCapabilities:[],entitlements:[],reusable:false});}
 }
 // Trusted transport only: final, synchronous, one-shot handoff after its audit.
 // A serialized/forged observation is not a delivery capability. No state is reactivated.
 deliver(handle,observation,handoff){
  const r=this.#deliveries.get(observation);need(r&&typeof handoff==='function','DELIVERY_INVALID');
  const a=this.#auth(handle);need(r.principal===a.principal&&r.profile===a.profile&&r.sessionId===a.sessionId,'AUTH_UNVERIFIED');
  need(r.status==='CONSUMED','PROOF_REPLAY');this.#consentLive(r,a);
  this.#deliveries.delete(observation);handoff();
 }
 #live(r,a){need(r.status==='PENDING','PROOF_REPLAY');this.#consentLive(r,a);}
 #consentLive(r,a){need(r.consentStatus==='ACTIVE','CONSENT_REVOKED');
  need(r.generation===a.generation,'GENERATION_STALE');const now=this.#time();need(now>=r.issuedAt&&now<r.expiresAt,'CONSENT_EXPIRED');}
}
module.exports=Object.freeze({OfflineProof,SyntheticAuthority,SyntheticFence,SyntheticAudit,Denied,parseSiwe,
 localhostRealm,LOCAL_ORIGIN,DOMAIN,URI,CHAIN,PROJECT,STATEMENT,CONSENT_TEXT,SCOPE,CONSENT_DOMAIN,TYPES,digest});

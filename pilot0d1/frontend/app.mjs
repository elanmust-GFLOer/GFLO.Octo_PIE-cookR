// @ts-check
import {WalletAdapter} from './wallet.mjs';
const ORIGIN='http://127.0.0.1:43817';
/** @typedef {import('../contracts.js').FixtureBridge} FixtureBridge */
/** @type {FixtureBridge|undefined} */
const bridge=window.__GFLO_SYNTHETIC_PILOT__;
/** @param {string} id */
const el=id=>{const item=document.getElementById(id);if(!item)throw Error('UI_MISSING');return item;};
/** @param {string} id @param {string} text */
const show=(id,text)=>{el(id).textContent=text;};
/** @param {string} id @param {boolean} disabled */
const disable=(id,disabled)=>{/** @type {HTMLButtonElement} */(el(id)).disabled=disabled;};
/** @type {ReturnType<typeof setTimeout>|null} */let expiration=null;
let version=0,busy=false,address='',siweSignature='',consentSignature='';
/** @type {import('../contracts.js').Challenge|null} */let challenge=null;
/** @type {AbortController|null} */let pending=null;
/** @type {WalletAdapter|null} */let adapter=null;
function controls(){disable('connect',busy||!adapter);disable('challenge',busy||!address);disable('siwe',busy||!challenge);disable('consent',busy||!challenge||!siweSignature||!/** @type {HTMLInputElement} */(el('agree')).checked);disable('verify',busy||!challenge||!siweSignature||!consentSignature);}
function clear(){if(expiration!==null)clearTimeout(expiration);version++;pending?.abort();address='';challenge=null;siweSignature='';consentSignature='';show('wallet','No wallet control proven');show('siwe-message','');show('typed-consent','');show('consent-text','');show('result','');/** @type {HTMLInputElement} */(el('agree')).checked=false;show('status','Wallet or chain changed. Start a fresh proof.');controls();}
/** @param {string} route @param {object} body */
async function api(route,body){if(!bridge||bridge.mode!=='SYNTHETIC_AUTOMATED'||location.origin!==ORIGIN)throw Error('FIXTURE_NOT_ATTACHED');
 pending=new AbortController();const controller=pending;let expired=false;const timer=setTimeout(()=>{expired=true;controller.abort();},1500);
 try{const credentials=await Promise.race([bridge.session(),/** @type {Promise<never>} */(new Promise((_,reject)=>controller.signal.addEventListener('abort',()=>reject(Error('CLIENT_TIMEOUT')),{once:true})))]);if(expired||controller.signal.aborted)throw Error('CLIENT_TIMEOUT');
 const response=await fetch(route,{method:'POST',mode:'same-origin',credentials:'omit',cache:'no-store',redirect:'error',signal:controller.signal,
  headers:{'Content-Type':'application/json','Authorization':'Bearer '+credentials.token,'X-GFLO-CSRF':credentials.csrf},body:JSON.stringify(body)});
 const value=await response.json();if(!response.ok||value.kind==='DENIED')throw Error(typeof value.reason==='string'?value.reason:'REQUEST_DENIED');return value;}finally{clearTimeout(timer);}
}
/** @param {()=>Promise<void>} work */
async function run(work){if(busy)return;busy=true;controls();try{await work();}catch(error){const code=error instanceof Error&&/^[A-Z_]{1,64}$/.test(error.message)?error.message:'REQUEST_DENIED';show('status','Denied: '+code);show('result','');}finally{busy=false;pending=null;controls();}}
if(bridge?.mode==='SYNTHETIC_AUTOMATED'&&location.origin===ORIGIN){adapter=new WalletAdapter(bridge.provider,text=>window.confirm(text),clear);show('status','Synthetic fixture attached. No real wallet connection.');}
else show('status','Synthetic fixture not attached. Real wallet interaction is disabled in Pilot 0D-1.');
el('connect').addEventListener('click',()=>run(async()=>{if(!adapter)throw Error('FIXTURE_NOT_ATTACHED');address=await adapter.connect();show('wallet',address+' — DISCOVERED, NOT VERIFIED');show('status','Address discovery is not proof of wallet control.');}));
el('challenge').addEventListener('click',()=>run(async()=>{const current=version;challenge=null;siweSignature='';consentSignature='';if(expiration!==null)clearTimeout(expiration);show('result','');show('siwe-message','');show('typed-consent','');show('consent-text','');show('wallet',address+' — DISCOVERED, NOT VERIFIED');/** @type {HTMLInputElement} */(el('agree')).checked=false;
 const value=await api('/api/challenges',{wallet:address,chainId:11155111,requestId:crypto.randomUUID(),source:/** @type {HTMLSelectElement} */(el('source')).value});
 if(current!==version)throw Error('WALLET_CHANGED');challenge=value;show('siwe-message',value.message);show('consent-text',value.consentText);show('typed-consent',JSON.stringify({domain:value.consentDomain,types:value.consentTypes,message:value.consent},null,2));show('status','Read the SIWE message and the separate consent before signing.');}));
el('siwe').addEventListener('click',()=>run(async()=>{if(!adapter||!challenge)throw Error('CHALLENGE_REQUIRED');const current=version;siweSignature='';consentSignature='';show('result','');const signature=await adapter.signSiwe(challenge.message,address);if(current!==version)throw Error('WALLET_CHANGED');siweSignature=signature;show('status','SIWE signed. Separate consent is still required.');}));
el('agree').addEventListener('change',()=>{if(!/** @type {HTMLInputElement} */(el('agree')).checked){version++;pending?.abort();consentSignature='';show('result','');show('status','Consent withdrawn locally. A fresh consent signature is required.');}controls();});
el('source').addEventListener('change',clear);
el('consent').addEventListener('click',()=>run(async()=>{if(!adapter||!challenge||!/** @type {HTMLInputElement} */(el('agree')).checked)throw Error('CONSENT_REQUIRED');const current=version;consentSignature='';show('result','');
 const signature=await adapter.signConsent({domain:challenge.consentDomain,types:challenge.consentTypes,message:challenge.consent},address);if(current!==version)throw Error('WALLET_CHANGED');consentSignature=signature;show('status','Separate consent signed. Submit this proof once.');}));
el('verify').addEventListener('click',()=>run(async()=>{if(!adapter||!challenge)throw Error('CHALLENGE_REQUIRED');const current=version;await adapter.check(address);
 const result=await api('/api/verify',{challengeId:challenge.challengeId,message:challenge.message,siweSignature,consent:JSON.stringify(challenge.consent),consentSignature});
 if(current!==version)throw Error('WALLET_CHANGED');if(result.wallet?.toLowerCase()!==address.toLowerCase()||result.principal!==challenge.consent.principal||result.profile!==challenge.consent.profile||result.chainId!==11155111||result.protocolSource!==challenge.consent.protocolSource||result.protocolManifestDigest!==challenge.consent.protocolManifestDigest||result.scopes?.length!==1||result.scopes[0]!=='id-entity.proof.read'||(challenge.consent.protocolSource.endsWith('legacy-sepolia')&&result.sourceClassification!=='LEGACY_UNTRUSTED_XP')||result.productionAuthorized!==false||result.canonicalXpAuthorized!==false||result.reusable!==false||result.mutationCapabilities?.length!==0||result.entitlements?.length!==0||!['DEMO_FIXTURE','LEGACY_UNTRUSTED_XP'].includes(result.sourceClassification)||result.syntheticPie?.canonicalXp!==null)throw Error('UNSAFE_RESULT');siweSignature='';consentSignature='';show('wallet',result.wallet+' — VERIFIED_WALLET_CONTROL (synthetic)');show('result',JSON.stringify(result,null,2));show('status','Read-only observation received. No persistent binding or protocol privileges.');if(expiration!==null)clearTimeout(expiration);expiration=setTimeout(()=>{show('result','');show('wallet',address+' — DISCOVERED, NOT VERIFIED');show('status','Observation expired. Start a fresh proof.');},Math.max(0,result.expiresAt*1000-Date.now()));}));
controls();

// @ts-check
// Public fixed signing policy; never authority or an AuthContext constructor.
export const SALT='0x5f92f26c1297c10ff77ea8356dc7c22c365d95dbcd923ffd921fec6b1315242b';
export const TEXT_DIGEST='0x5a6013477e9836ffe31e8c8a7af6d66f4633888a7b45a7caada9e2c81881df93';
export const CONSENT_TEXT='Authorize one offline synthetic ID-Entity proof only. No persistent binding, XP, token, governance or access privileges.';
export const FIELDS=Object.freeze([
 ['principal','string'],['profile','string'],['wallet','address'],['chainId','uint256'],['protocolSource','string'],['protocolManifestDigest','bytes32'],['scopes','string[]'],['generation','uint256'],['nonce','bytes32'],['challengeId','string'],['requestId','string'],['siweMessageHash','bytes32'],['expiresAt','uint256'],['consentVersion','string'],['consentTextDigest','bytes32'],['authProject','string']
].map(([name,type])=>Object.freeze({name,type})));
/** @param {boolean} valid */
const requireSafe=valid=>{if(!valid)throw Error('UNSAFE_CHALLENGE');};
/** @param {unknown} value */
const isId=value=>typeof value==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value);
/** @param {any} value @param {string} address @param {string} source */
export function validateChallenge(value,address,source){
 requireSafe(value!==null&&typeof value==='object'&&value.consent!==null&&typeof value.consent==='object'&&typeof value.message==='string'&&value.message.length<=4096);
 const c=value.consent,d=value.consentDomain;
 requireSafe(d&&Object.keys(d).sort().join('|')==='chainId|name|salt|version'&&d.name==='GFLO Pilot 0D-1 Localhost Consent'&&d.version==='0'&&d.chainId===11155111&&d.salt===SALT);
 requireSafe(value.consentTypes&&Object.keys(value.consentTypes).join('|')==='BindingConsent'&&JSON.stringify(value.consentTypes.BindingConsent)===JSON.stringify(FIELDS));
 requireSafe(Object.keys(c).join('|')===FIELDS.map(f=>f.name).join('|')&&isId(c.principal)&&isId(c.profile)&&isId(c.challengeId)&&isId(c.requestId));
 requireSafe(typeof c.wallet==='string'&&c.wallet.toLowerCase()===address.toLowerCase()&&c.chainId===11155111&&c.protocolSource===source&&['https://pilot0d1.invalid/protocol/demo','https://pilot0d1.invalid/protocol/legacy-sepolia'].includes(source));
 requireSafe(/^0x[a-f0-9]{64}$/.test(c.protocolManifestDigest)&&/^0x[a-f0-9]{64}$/.test(c.nonce)&&/^0x[a-f0-9]{64}$/.test(c.siweMessageHash));
 requireSafe(Array.isArray(c.scopes)&&c.scopes.length===1&&c.scopes[0]==='id-entity.proof.read'&&Number.isSafeInteger(c.generation)&&c.generation>=0);
 requireSafe(Number.isSafeInteger(c.expiresAt)&&c.expiresAt===value.expiresAt&&c.expiresAt>Date.now()/1000&&c.expiresAt<=Date.now()/1000+90&&c.challengeId===value.challengeId);
 requireSafe(c.authProject==='GFLO-PILOT-0D1-SYNTHETIC'&&c.consentVersion==='pilot0c/1'&&c.consentTextDigest===TEXT_DIGEST&&value.consentText===CONSENT_TEXT);
 const lines=value.message.split('\n');
 requireSafe(lines.length===18&&lines[0]==='127.0.0.1:43817 wants you to sign in with your Ethereum account:'&&lines[1].toLowerCase()===address.toLowerCase()&&lines[3]==='Prove wallet control for one synthetic ID-Entity observation.');
 requireSafe(lines[5]==='URI: http://127.0.0.1:43817/id-entity'&&lines[6]==='Version: 1'&&lines[7]==='Chain ID: 11155111'&&lines[8]==='Nonce: '+c.nonce.slice(2));
 requireSafe(lines[10]==='Expiration Time: '+new Date(c.expiresAt*1000).toISOString().replace('.000Z','Z')&&lines[12]==='Request ID: '+c.requestId&&lines[13]==='Resources:');
 requireSafe(lines[14]==='- urn:gflo:pilot0c:principal:'+c.principal&&lines[15]==='- urn:gflo:pilot0c:profile:'+c.profile&&lines[16]==='- urn:gflo:pilot0c:challenge:'+c.challengeId&&lines[17]==='- '+source);
}

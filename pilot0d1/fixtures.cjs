'use strict';
// Test-controller-only module. The HTTP server and frontend never import it.
const e=require('../pilot0c/vendor/ethers.umd.min.cjs');
function signingFixture(){
 const keys={A:e.Wallet.createRandom(),B:e.Wallet.createRandom()};let selected='A',chain='0xaa36a7',rejectConsent=false;
 const calls=[];
 return {wallets:[{address:keys.A.address,kind:'EOA'},{address:keys.B.address,kind:'EOA'}],address:name=>keys[name].address,
  calls:()=>[...calls],switchWallet:name=>{selected=name;},setChain:value=>{chain=value;},denyConsent:()=>{rejectConsent=true;},
  request:async({method,params=[]})=>{calls.push(method);
   if(['eth_requestAccounts','eth_accounts'].includes(method))return [keys[selected].address];
   if(method==='eth_chainId')return chain;
   const address=method==='personal_sign'?params[1]:params[0];if(typeof address!=='string'||address.toLowerCase()!==keys[selected].address.toLowerCase())throw Error('WALLET_CHANGED');
   if(method==='personal_sign'){if(typeof params[0]!=='string'||!/^0x[0-9a-f]+$/.test(params[0]))throw Error('INPUT_INVALID');return keys[selected].signMessage(e.getBytes(params[0]));}
   if(method==='eth_signTypedData_v4'){if(rejectConsent)throw Object.assign(Error('DECLINED'),{code:4001});
    const typed=JSON.parse(params[1]);const types={...typed.types};delete types.EIP712Domain;return keys[selected].signTypedData(typed.domain,types,typed.message);}
   throw Error('METHOD_DENIED');},
  sign:async(challenge,name='A')=>({challengeId:challenge.challengeId,message:challenge.message,
   siweSignature:await keys[name].signMessage(challenge.message),consent:JSON.stringify(challenge.consent),
   consentSignature:await keys[name].signTypedData(challenge.consentDomain,challenge.consentTypes,challenge.consent)})};
}
function gate(){let unlock,entered;const seen=new Promise(r=>{entered=r;});const pending=new Promise(r=>{unlock=r;});return {seen,release:()=>unlock(),wait:()=>{entered();return pending;}};}
module.exports={signingFixture,gate};

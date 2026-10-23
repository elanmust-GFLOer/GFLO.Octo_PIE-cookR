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
async function isolatedSigner(){
 const {fork}=require('node:child_process'),path=require('node:path');
 const child=fork(path.join(__dirname,'signer-worker.cjs'),[],{stdio:['ignore','ignore','ignore','ipc']});
 let retired=false,sequence=0;const pending=new Map(),calls=[];
 const exited=new Promise(resolve=>child.once('exit',resolve));
 async function stop(){if(retired&&child.exitCode!==null)return;retired=true;child.kill('SIGTERM');
  const first=await Promise.race([exited.then(()=>true),new Promise(r=>setTimeout(()=>r(false),100))]);
  if(!first){child.kill('SIGKILL');const reaped=await Promise.race([exited.then(()=>true),new Promise(r=>setTimeout(()=>r(false),500))]);if(!reaped)throw Error('SIGNER_NOT_REAPED');}}
 let ready;try{ready=await new Promise((resolve,reject)=>{const timer=setTimeout(()=>{child.kill('SIGKILL');reject(Error('SIGNER_START_TIMEOUT'));},3000);child.once('message',message=>{clearTimeout(timer);if(message.ready)resolve(message.wallets);else reject(Error('SIGNER_START_DENIED'));});child.once('error',()=>{clearTimeout(timer);reject(Error('SIGNER_START_DENIED'));});});}catch(error){await stop();throw error;}
 child.on('message',message=>{if(!Number.isSafeInteger(message.id))return;const item=pending.get(message.id);if(!item)return;pending.delete(message.id);clearTimeout(item.timer);message.ok?item.resolve(message.value):item.reject(Error(message.code));});
 child.on('exit',()=>{retired=true;for(const item of pending.values()){clearTimeout(item.timer);item.reject(Error('SIGNER_UNAVAILABLE'));}pending.clear();});
 function rpc(method,value){if(retired||pending.size>=8)return Promise.reject(Error('SIGNER_UNAVAILABLE'));const message={id:++sequence,method,value};if(JSON.stringify(message).length>16384)return Promise.reject(Error('SIGNER_INPUT_DENIED'));
  return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{pending.delete(message.id);stop().then(()=>reject(Error('SIGNER_TIMEOUT')),()=>reject(Error('SIGNER_NOT_REAPED')));},3000);pending.set(message.id,{resolve,reject,timer});child.send(message,error=>{if(error){clearTimeout(timer);pending.delete(message.id);reject(Error('SIGNER_UNAVAILABLE'));}});});}
 return {wallets:ready,address:name=>ready[name==='A'?0:1].address,calls:()=>[...calls],switchWallet:name=>rpc('switch',name),setChain:value=>rpc('chain',value),denyConsent:()=>rpc('decline',null),
  request:value=>{calls.push(value.method);return rpc('request',value);},sign:(challenge,name='A')=>rpc('sign',{challenge,name}),stats:()=>({pid:child.pid,retired,pending:pending.size}),close:stop};
}
module.exports={signingFixture,isolatedSigner,gate};

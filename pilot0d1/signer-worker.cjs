'use strict';
// Disposable test-only key process. No HTTP listener, persistence or key-export RPC.
require('../pilot0c/crypto.cjs'); // Verify the immutable crypto artifact first.
const {signingFixture}=require('./fixtures.cjs');
const fixture=signingFixture();
process.send({ready:true,wallets:fixture.wallets});
process.on('message',async message=>{
 const id=message?.id;
 try{
  if(!Number.isSafeInteger(id)||JSON.stringify(message).length>16384)throw Error('SIGNER_INPUT_DENIED');
  let value;
  if(message.method==='request')value=await fixture.request(message.value);
  else if(message.method==='sign')value=await fixture.sign(message.value.challenge,message.value.name);
  else if(message.method==='switch')value=fixture.switchWallet(message.value);
  else if(message.method==='chain')value=fixture.setChain(message.value);
  else if(message.method==='decline')value=fixture.denyConsent();
  else throw Error('SIGNER_METHOD_DENIED');
  process.send({id,ok:true,value});
 }catch(error){process.send({id,ok:false,code:error?.code===4001?'SIGNING_DECLINED':'SIGNER_REQUEST_DENIED'});}
});
process.on('disconnect',()=>process.exit(0));

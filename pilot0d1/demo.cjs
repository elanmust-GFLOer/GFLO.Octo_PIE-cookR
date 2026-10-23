'use strict';
// Optional manual SYNTHETIC demo. No extension, real wallet, or auto-signing.
const {chromium}=require('playwright');
const {makeApplication,ORIGIN}=require('./server.cjs');
const {isolatedSigner}=require('./fixtures.cjs');
const {attachFixture}=require('./browser-fixture.cjs');
async function main(){
 if(process.env.GFLO_DISPOSABLE_LOCALHOST!=='YES')throw Error('DISPOSABLE_ACK_REQUIRED');
 const signer=await isolatedSigner();let app,browser;
 try{
  app=makeApplication({disposable:true,wallets:signer.wallets});await app.listen();
  browser=await chromium.launch({headless:false});const context=await browser.newContext();
  await attachFixture(context,app,signer);const page=await context.newPage();await page.goto(ORIGIN+'/');
  console.log('PILOT_0D1_SYNTHETIC_DEMO_READY_NO_REAL_WALLET');
  await new Promise(resolve=>{browser.once('disconnected',resolve);for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>browser.close().finally(resolve));});
 }finally{if(browser)await browser.close();if(app)await app.close();await signer.close();}
}
main().catch(()=>{console.error('PILOT_0D1_DEMO_UNAVAILABLE');process.exitCode=1;});

'use strict';
// Test/demo controller only. Never served or imported by the application server.
const assert=require('node:assert/strict');
const {ORIGIN}=require('./server.cjs');
async function attachFixture(context,app,signer,who='A'){
 const check=frame=>{assert.equal(frame.url(),ORIGIN+'/');assert.equal(frame,frame.page().mainFrame());};
 await context.exposeBinding('__gfloSyntheticSession',({frame})=>{check(frame);return app.fixture.credentials(who);});
 await context.exposeBinding('__gfloSyntheticRpc',async({frame},value)=>{check(frame);return signer.request(value);});
 await context.addInitScript(()=>{
  const listeners=new Map();const provider={request:args=>window.__gfloSyntheticRpc(args),on:(name,fn)=>{if(!listeners.has(name))listeners.set(name,new Set());listeners.get(name).add(fn);},removeListener:(name,fn)=>listeners.get(name)?.delete(fn)};
  window.__GFLO_SYNTHETIC_PILOT__=Object.freeze({mode:'SYNTHETIC_AUTOMATED',provider,session:()=>window.__gfloSyntheticSession()});
  window.__GFLO_TEST_EVENT__=(name,value)=>{for(const fn of listeners.get(name)||[])fn(value);};
 });
}
module.exports={attachFixture};

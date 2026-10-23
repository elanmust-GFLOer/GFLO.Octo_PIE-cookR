'use strict';
const http=require('node:http'),fs=require('node:fs'),path=require('node:path');
const {randomBytes,randomUUID}=require('node:crypto');
const {performance}=require('node:perf_hooks');
const p=require('../pilot0c/proof.cjs');
const ORIGIN=p.LOCAL_ORIGIN,HOST='127.0.0.1:43817',PORT=43817;
const A='11111111-1111-4111-8111-111111111111',B='22222222-2222-4222-8222-222222222222';
const PA='33333333-3333-4333-8333-333333333333',PB='44444444-4444-4444-8444-444444444444';
const CSP="default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'";
const STATIC=new Map([['/',['index.html','text/html']],['/app.mjs',['app.mjs','text/javascript']],['/wallet.mjs',['wallet.mjs','text/javascript']],['/style.css',['style.css','text/css']]]);
function secure(res){for(const [k,v] of Object.entries({'Content-Security-Policy':CSP,'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Cache-Control':'no-store','Cross-Origin-Opener-Policy':'same-origin','Cross-Origin-Resource-Policy':'same-origin','Permissions-Policy':'camera=(), microphone=(), geolocation=(), payment=(), usb=()','Connection':'close'}))res.setHeader(k,v);}
function strictJson(raw){
 // Only the flat transport schemas are accepted; duplicate/escaped keys deny.
 const text=raw.toString('utf8');if(!Buffer.from(text).equals(raw))throw Error('INPUT_INVALID');
 const keys=[...text.matchAll(/(?:^|[,{])\s*"([^"\\]*)"\s*:/g)].map(m=>m[1]);
 const value=JSON.parse(text);
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||keys.length!==Object.keys(value).length||new Set(keys).size!==keys.length)throw Error('INPUT_INVALID');
 return value;
}
function shape(value,keys){if(Object.keys(value).sort().join('|')!==[...keys].sort().join('|')||Object.values(value).some(v=>typeof v!=='string'&&typeof v!=='number'))throw Error('INPUT_INVALID');}
function makeApplication({disposable=false,wallets=[],wall=()=>Date.now()/1000,mono=()=>performance.now(),auditHook=null,deliveryGate=null}={}){
 if(disposable!==true)throw Error('DISPOSABLE_ACK_REQUIRED');
 const authority=new p.SyntheticAuthority([[A,PA],[B,PB]],wall),fence=new p.SyntheticFence([A,B]),audit=new p.SyntheticAudit();
 const handles={A:authority.issue(A),B:authority.issue(B)};
 const cap=new Map(),credentials={};
 for(const name of ['A','B']){const token=randomBytes(32).toString('hex'),csrf=randomBytes(32).toString('hex');cap.set(token,{handle:handles[name],csrf});credentials[name]=Object.freeze({token,csrf});}
 const sink={approve(event){const ok=audit.approve(event);if(auditHook)auditHook({event,authority,fence,audit,handles});return ok;}};
 const sources=[{reference:'https://pilot0d1.invalid/protocol/demo',chainId:p.CHAIN,contract:'0x1111111111111111111111111111111111111111',manifestDigest:p.digest('synthetic-pie-records-v1'),classification:'DEMO_FIXTURE'},
 {reference:'https://pilot0d1.invalid/protocol/legacy-sepolia',chainId:p.CHAIN,contract:'0x9cf55d0b9d61dc28ef3cb10765cf4b861cd0991e',manifestDigest:p.digest(fs.readFileSync(path.join(__dirname,'../pilot0b/legacy-sepolia.incomplete.json'))),classification:'LEGACY_UNTRUSTED_XP'}];
 const proof=new p.OfflineProof({authority,fence,audit:sink,wallets,sources,clock:wall,monotonic:mono,realm:p.localhostRealm()});
 const locks=new Map(),sockets=new Set();let active=0,protectedHandoffs=0;
 // No privileged fixture control is mounted as an HTTP route.
 function observe(handle){const a=authority.observe(handle),local=fence.observe(a.principal);
  if(a.state!=='ACTIVE')throw Error(a.state==='REVOKED'?'SESSION_REVOKED':'AUTHORITY_UNAVAILABLE');
  if(local.state!=='READY'||local.generation!==a.generation)throw Error('GENERATION_STALE');return a;}
 async function acquire(key,deadline,signal){
  const previous=locks.get(key)||Promise.resolve();let release;const held=new Promise(r=>{release=r;});const mine=previous.then(()=>held);locks.set(key,mine);
  mine.then(()=>{if(locks.get(key)===mine)locks.delete(key);});
  try{await bounded(previous,deadline,signal,mono);return ()=>release();}
  catch(error){release();throw error;}
 }
 async function handle(req,res){
  const deadline=mono()+1000,abort=new AbortController();let release=null,slot=false,actor='unknown',requestId='unknown',terminal=false;let traceId=randomUUID();
  secure(res);const deny=(reason,status=403)=>{if(terminal)return;terminal=true;try{sink.approve({traceId,requestId,principal:actor,code:'TRANSPORT_DENIED:'+reason});}catch{}if(!res.headersSent&&!res.destroyed)res.writeHead(status,{'Content-Type':'application/json'}).end(JSON.stringify({kind:'DENIED',reason,traceId}));else res.destroy();};
  const check=()=>{if(abort.signal.aborted||!Number.isFinite(mono())||mono()>=deadline)throw Error('AUTHORIZATION_EXPIRED');};
  const timer=setTimeout(()=>{abort.abort();deny('AUTHORIZATION_EXPIRED',503);},1000);timer.unref();
  req.on('aborted',()=>abort.abort());res.on('close',()=>{if(!res.writableFinished)abort.abort();});
  try{
   if(req.headers.host!==HOST||req.rawHeaders.filter((x,i)=>i%2===0&&x.toLowerCase()==='host').length!==1)throw Error('HOST_DENIED');
   if(req.headers.origin!==undefined&&req.headers.origin!==ORIGIN)throw Error('ORIGIN_DENIED');
   if(req.url==='/healthz'&&req.method==='GET'){res.writeHead(200,{'Content-Type':'application/json'}).end('{"status":"ok","environment":"PILOT_0D1"}');return;}
   if(req.method==='GET'&&STATIC.has(req.url)){
    const [file,type]=STATIC.get(req.url);const raw=fs.readFileSync(path.join(__dirname,'frontend',file));res.writeHead(200,{'Content-Type':type+'; charset=utf-8'}).end(raw);return;
   }
   if(req.method!=='POST'||!['/api/challenges','/api/verify'].includes(req.url))throw Error('ROUTE_DENIED');
   if(req.headers.origin!==ORIGIN||req.headers['sec-fetch-site']!=='same-origin')throw Error('ORIGIN_DENIED');
   if(req.headers.cookie!==undefined||req.headers['content-type']!=='application/json')throw Error('CREDENTIAL_TRANSPORT_DENIED');
   if(req.rawHeaders.filter((x,i)=>i%2===0&&x.toLowerCase()==='authorization').length!==1)throw Error('AUTH_UNVERIFIED');
   const m=/^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization||'');const credential=m&&cap.get(m[1]);
   if(!credential||req.headers['x-gflo-csrf']!==credential.csrf)throw Error('AUTH_UNVERIFIED');
   const initial=observe(credential.handle);actor=initial.principal;if(active>=4)throw Error('CAPACITY_EXHAUSTED');active++;slot=true;
   if(req.headers['transfer-encoding']!==undefined||!/^\d{1,5}$/.test(req.headers['content-length']||''))throw Error('INPUT_INVALID');
   const expected=Number(req.headers['content-length']);if(expected>16384)throw Error('INPUT_TOO_LARGE');
   const chunks=[];let size=0;
   await bounded(new Promise((resolve,reject)=>{req.on('data',chunk=>{size+=chunk.length;if(size>expected||size>16384){reject(Error('INPUT_TOO_LARGE'));req.destroy();}else chunks.push(chunk);});req.on('end',resolve);req.on('error',()=>reject(Error('INPUT_INVALID')));}),deadline,abort.signal,mono);
   check();if(size!==expected)throw Error('INPUT_INVALID');const body=strictJson(Buffer.concat(chunks));
   release=await acquire(initial.principal,deadline,abort.signal);check();const locked=observe(credential.handle);
   if(locked.generation!==initial.generation)throw Error('GENERATION_STALE');
   if(req.url==='/api/challenges'){
    shape(body,['wallet','chainId','requestId','source']);if(body.chainId!==p.CHAIN)throw Error('CHAIN_DENIED');
    const source=sources.find(s=>s.reference===body.source);if(!source)throw Error('SOURCE_UNKNOWN');
    const challenge=proof.issue(credential.handle,{wallet:body.wallet,source:source.reference,requestId:body.requestId});
    requestId=body.requestId;const raw=JSON.stringify(challenge);check();sink.approve({traceId,requestId,principal:actor,code:'CHALLENGE_RELEASE_APPROVAL'});const final=observe(credential.handle);check();if(final.generation!==initial.generation)throw Error('GENERATION_STALE');res.writeHead(200,{'Content-Type':'application/json'}).end(raw);return;
   }
   shape(body,['challengeId','message','siweSignature','consent','consentSignature']);
   const result=await proof.verify(credential.handle,body,{deadline,signal:abort.signal});traceId=result.traceId;check();
   if(result.kind!=='OFFLINE_READ_ONLY_OBSERVATION'){deny(result.reason);return;}
   if(deliveryGate)await bounded(deliveryGate.wait(),deadline,abort.signal,mono);check();
   // Read-only synthetic data, selected exclusively by the verified server principal.
   const syntheticPie={classification:'DEMO_FIXTURE',demoXp:result.principal===A?25:40,canonicalXp:null,historicalTier:null,
    path:['SYNTHETIC'],note:'Synthetic fixture only. No canonical XP or Tier authority.'};
   const response={...result,syntheticPie,environment:'PILOT_0D1_LOCALHOST'};
   const raw=JSON.stringify(response);check();
   sink.approve({traceId:result.traceId,requestId:'transport',principal:result.principal,code:'TRANSPORT_RELEASE_APPROVAL'});
   const final=observe(credential.handle);check();
   if(final.principal!==result.principal||final.profile!==result.profile||final.generation!==result.generation||final.sessionId!==initial.sessionId)throw Error('GENERATION_STALE');
   res.writeHead(200,{'Content-Type':'application/json','Content-Length':Buffer.byteLength(raw)});check();protectedHandoffs++;res.end(raw);
  }catch(error){const allowed=new Set(['HOST_DENIED','ORIGIN_DENIED','ROUTE_DENIED','CREDENTIAL_TRANSPORT_DENIED','AUTH_UNVERIFIED','AUTHORITY_UNAVAILABLE','SESSION_REVOKED','GENERATION_STALE','CAPACITY_EXHAUSTED','INPUT_INVALID','INPUT_TOO_LARGE','CHAIN_DENIED','SOURCE_UNKNOWN','AUTHORIZATION_EXPIRED','AUDIT_UNAVAILABLE']);deny(allowed.has(error.message)?error.message:'REQUEST_DENIED');}
  finally{clearTimeout(timer);if(release)release();if(slot)active--;}
 }
 const server=http.createServer({maxHeaderSize:8192},(req,res)=>{handle(req,res).catch(()=>res.destroy());});
 server.maxRequestsPerSocket=1;server.requestTimeout=1500;server.headersTimeout=1500;server.keepAliveTimeout=1;
 server.on('connection',socket=>{if(sockets.size>=16){socket.destroy();return;}sockets.add(socket);const timer=setTimeout(()=>socket.destroy(),3000);timer.unref();socket.on('close',()=>{clearTimeout(timer);sockets.delete(socket);});});
 server.on('clientError',(_error,socket)=>socket.destroy());
 return {server,listen:()=>new Promise((resolve,reject)=>{server.once('error',reject);server.listen(PORT,'127.0.0.1',resolve);}),
  close:async()=>{for(const socket of sockets)socket.destroy();if(server.listening)await new Promise(resolve=>server.close(resolve));},
  fixture:Object.freeze({authority,fence,audit,handles,credentials:name=>credentials[name],proof,source:sources[0].reference,legacy:sources[1].reference,
   serialFence:acquire,stats:()=>({active,sockets:sockets.size,locks:locks.size,protectedHandoffs})})};
}
function bounded(promise,deadline,signal,mono){return new Promise((resolve,reject)=>{
 let ended=false;const finish=(fn,v)=>{if(ended)return;ended=true;clearTimeout(timer);signal.removeEventListener('abort',abort);fn(v);};
 const abort=()=>finish(reject,Error('AUTHORIZATION_EXPIRED'));
 const timer=setTimeout(abort,Math.max(0,deadline-mono()));signal.addEventListener('abort',abort,{once:true});
 if(signal.aborted||mono()>=deadline){abort();return;}
 Promise.resolve(promise).then(v=>finish(resolve,v),()=>finish(reject,Error('REQUEST_DENIED')));
});}
if(require.main===module){if(process.env.GFLO_DISPOSABLE_LOCALHOST!=='YES')throw Error('DISPOSABLE_ACK_REQUIRED');makeApplication({disposable:true}).listen().then(()=>console.log('PILOT_0D1_LOCALHOST_READY_NO_REAL_WALLET')).catch(()=>{console.error('PILOT_0D1_START_DENIED');process.exitCode=1;});}
module.exports={makeApplication,strictJson,bounded,ORIGIN,HOST,PORT,CSP,A,B,PA,PB};

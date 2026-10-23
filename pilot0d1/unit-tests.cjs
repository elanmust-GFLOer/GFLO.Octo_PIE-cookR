'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {randomUUID}=require('node:crypto');
const p=require('../pilot0c/proof.cjs');
const {makeApplication,strictJson,ORIGIN,HOST,CSP,A,PA}=require('./server.cjs');
const {signingFixture}=require('./fixtures.cjs');
const tests=[];const test=(name,run)=>tests.push({name,run});
function core(realm=p.localhostRealm()){
 const wallet=signingFixture();const authority=new p.SyntheticAuthority([[A,PA]]),handle=authority.issue(A),fence=new p.SyntheticFence([A]);
 const proof=new p.OfflineProof({authority,fence,audit:new p.SyntheticAudit(),wallets:wallet.wallets,
  sources:[{chainId:11155111,contract:'0x1111111111111111111111111111111111111111',reference:'https://pilot0d1.invalid/protocol/demo',manifestDigest:p.digest('demo'),classification:'DEMO_FIXTURE'}],realm});
 const ch=proof.issue(handle,{wallet:wallet.address('A'),source:'https://pilot0d1.invalid/protocol/demo',requestId:randomUUID()});return {wallet,proof,handle,ch};}
test('realm.fixed_verified_origin',()=>{const f=core();assert.equal(f.ch.message.startsWith(HOST+' wants'),true);assert.equal(f.ch.message.includes('URI: '+ORIGIN+'/id-entity'),true);assert.equal(f.ch.consent.authProject,'GFLO-PILOT-0D1-SYNTHETIC');});
test('realm.real_localhost_signatures',async()=>{const f=core();const r=await f.proof.verify(f.handle,await f.wallet.sign(f.ch));assert.equal(r.kind,'OFFLINE_READ_ONLY_OBSERVATION');});
test('realm.caller_constructed_realm_denied',()=>{assert.throws(()=>core({domain:HOST,uri:ORIGIN+'/id-entity'}),e=>e.code==='REALM_UNVERIFIED');});
test('realm.foreign_domain_resigned_rejected',async()=>{const f=core();const input=await f.wallet.sign(f.ch);input.message=input.message.replace(HOST,'attacker.invalid');input.siweSignature=await f.wallet.request({method:'personal_sign',params:['0x'+Buffer.from(input.message).toString('hex'),f.wallet.address('A')]});assert.equal((await f.proof.verify(f.handle,input)).kind,'DENIED');});
test('realm.original_pilot_domain_not_local',()=>{assert.throws(()=>p.parseSiwe(core().ch.message),e=>e.code==='SIWE_MALFORMED');});
test('deadline.aborted_request_cannot_consume',async()=>{const f=core(),input=await f.wallet.sign(f.ch),abort=new AbortController();abort.abort();assert.equal((await f.proof.verify(f.handle,input,{signal:abort.signal})).kind,'DENIED');assert.equal((await f.proof.verify(f.handle,input)).kind,'OFFLINE_READ_ONLY_OBSERVATION');});
test('deadline.external_deadline_only_shortens',async()=>{const f=core();assert.equal((await f.proof.verify(f.handle,await f.wallet.sign(f.ch),{deadline:0})).kind,'DENIED');});
test('deadline.abort_between_crypto_and_consume',async()=>{const f=core(),input=await f.wallet.sign(f.ch),abort=new AbortController();const result=f.proof.verify(f.handle,input,{signal:abort.signal});abort.abort();assert.equal((await result).kind,'DENIED');});
test('transport.duplicate_json_keys_rejected',()=>{assert.throws(()=>strictJson(Buffer.from('{"wallet":"A","wallet":"B"}')));});
test('transport.escaped_json_keys_rejected',()=>{assert.throws(()=>strictJson(Buffer.from('{"\\u0077allet":"A"}')));});
test('transport.nested_consent_string_preserved',()=>{const value={consent:JSON.stringify({profile:'fixture',scopes:['id-entity.proof.read']})};assert.equal(strictJson(Buffer.from(JSON.stringify(value))).consent,value.consent);});
test('transport.no_real_wallet_fixture_by_default',async()=>{const app=makeApplication({disposable:true});assert.equal(app.server.listening,false);assert.equal(typeof app.fixture.credentials('A').token,'string');await app.close();});
test('transport.disposable_ack_mandatory',()=>{assert.throws(()=>makeApplication(),/DISPOSABLE_ACK_REQUIRED/);});
test('browser.csp_no_inline_or_external_script',()=>{assert.equal(CSP.includes("script-src 'self'"),true);assert.equal(CSP.includes('unsafe-inline'),false);assert.equal(CSP.includes("frame-ancestors 'none'"),true);});
test('boundary.frontend_imports_only_wallet_adapter',()=>{const client=fs.readFileSync(path.join(__dirname,'frontend/app.mjs'),'utf8');assert.equal(client.includes("import {WalletAdapter} from './wallet.mjs'"),true);for(const forbidden of ['localStorage','sessionStorage','window.ethereum','innerHTML','eval(','pilot0c/','node:'])assert.equal(client.includes(forbidden),false);});
test('boundary.fixture_signer_not_server_import',()=>{const server=fs.readFileSync(path.join(__dirname,'server.cjs'),'utf8');assert.equal(server.includes("require('./fixtures.cjs')"),false);assert.equal(server.includes('privateKey'),false);assert.equal(server.includes('signTypedData'),false);});
async function main(){const expected=JSON.parse(fs.readFileSync(path.join(__dirname,'unit-manifest.json'),'utf8'));assert.deepEqual(tests.map(t=>t.name).sort(),expected);const rows=[];
 for(const t of tests){try{await t.run();rows.push({test:t.name,status:'PASS'});console.log('PASS '+t.name);}catch{rows.push({test:t.name,status:'FAIL'});console.log('FAIL '+t.name);}}
 const out=path.resolve(process.env.GFLO_EVIDENCE_DIR||'evidence');fs.mkdirSync(out,{recursive:true});const ok=rows.every(r=>r.status==='PASS');fs.writeFileSync(path.join(out,'pilot0d1-unit-ledger.json'),JSON.stringify({status:ok?'PASS':'FAIL',runtime:process.version,executed:rows,skipped:0},null,2)+'\n');console.log('PILOT_0D1 UNIT '+(ok?'PASS':'FAIL')+' '+rows.filter(r=>r.status==='PASS').length+'/'+rows.length);if(!ok)process.exitCode=1;}
if(require.main===module)main().catch(()=>{console.error('UNIT_RUNNER_FAILED');process.exitCode=1;});

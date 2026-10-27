import {spawnSync} from 'node:child_process';
import {randomBytes,createHmac,createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const esc=x=>"'"+String(x).replaceAll("'","''")+"'";
function pg(query,role='gflo_enforcer_lab',password='lab-enforcer-only'){
 const x=spawnSync('psql',['-X','-qAt','-v','ON_ERROR_STOP=1','-c',query],{
 encoding:'utf8',timeout:12000,env:{...process.env,PGHOST:'127.0.0.1',PGPORT:'5432',
 PGDATABASE:'gflo_test',PGUSER:role,PGPASSWORD:password}});
 if(x.status!==0)throw Error('DENIED '+x.stderr.slice(0,130));
 return x.stdout.trim();
}
const owner=x=>pg(x,'gflo_test','test_only_password');
const key=randomBytes(32),wallet='0x'+'ab'.repeat(20),digest=createHash('sha256').update('isolated proof').digest('hex');
const chain=11155111,subject='alice',kid='lab_key_1',ttl=300,epoch=1;
const expiry=BigInt(Math.floor(Date.now()/1000)+60);
owner('INSERT INTO ib03l.keys VALUES('+esc(kid)+",decode("+esc(key.toString('hex'))+",'hex'),true,1)");
owner('INSERT INTO ib03d2.bindings VALUES('+esc(subject)+','+chain+','+esc(wallet)+",'ACTIVE',1)");
owner('INSERT INTO ib03d2.consents VALUES('+esc(subject)+','+chain+",'pie:xp:read',true,now()+interval '10 minutes',1)");
const nonce=n=>owner('INSERT INTO ib03d2.challenges VALUES('+esc(n)+','+esc(subject)+','+esc(wallet)+','+chain+",'example.test',now()+interval '5 minutes',NULL,"+esc(digest)+')');
const tag=(n,s)=>createHmac('sha256',key).update(['GFLO_IB03L_V1',kid,epoch,n,subject,chain,wallet,digest,s,1,1,ttl,expiry].join('|')).digest('hex');
const call=(n,s,t=tag(n,s),keyEpoch=epoch)=>'SELECT ib03l.admit('+[esc(n),esc(subject),chain,esc(wallet),esc(digest),esc(s),1,1,ttl,expiry,esc(kid),keyEpoch,esc(t)].join(',')+')';
const deny=x=>assert.throws(()=>pg(x));
deny('SELECT secret FROM ib03l.keys');
deny("SELECT ib03j.redeem_receipt('x','x',300)");
deny("SELECT ib03d2.issue_verified_session('x','x',1,'x','x','x',1,1,60)");
console.log('PASS compromised enforcer cannot read secret or bypass legacy issuance');
const n='GFLO_L_NONCE_00001',s='SESSION_IB03L_000001';nonce(n);
assert.equal(pg(call(n,s,'0'.repeat(64))),'f');
assert.equal(pg(call(n,s+'x',tag(n,s))),'f');
assert.equal(owner('SELECT consumed_at IS NULL FROM ib03d2.challenges WHERE id='+esc(n)),'t');
console.log('PASS invalid proof and session tampering denied without nonce consumption');
assert.equal(pg(call(n,s)),'t');
assert.equal(pg(call(n,s)),'f');
assert.equal(owner('SELECT count(*) FROM ib03d2.sessions'),'1');
console.log('PASS DB checks MAC inside atomic issuance and denies replay');
const n2='GFLO_L_NONCE_00002',s2='SESSION_IB03L_000002';nonce(n2);
owner('UPDATE ib03l.keys SET enabled=false,epoch=epoch+1 WHERE kid='+esc(kid));
assert.equal(pg(call(n2,s2)),'f');
owner('UPDATE ib03l.keys SET enabled=true WHERE kid='+esc(kid));
assert.equal(pg(call(n2,s2)),'f');
console.log('PASS key disabled / stale epoch rejected');
owner('UPDATE ib03l.keys SET epoch=1 WHERE kid='+esc(kid));
assert.equal(owner("SELECT ib03d2.revoke_consent('alice',11155111)"),'2');
assert.equal(pg(call(n2,s2)),'f');
console.log('PASS revoked consent blocks otherwise valid tag');
console.log('IB03L_ATOMIC_HMAC_GATE_PASS production=BLOCK');

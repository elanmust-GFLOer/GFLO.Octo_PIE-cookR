// Source-level sanity only. These are NOT PostgreSQL runtime tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const sql=readFileSync(new URL('../sql/001_gflo_bridge_RT6D4_CANDIDATE.sql',import.meta.url),'utf8');
const suite=readFileSync(new URL('./01_postgres_security.sql',import.meta.url),'utf8');
const concurrency=readFileSync(new URL('./02_concurrency.sh',import.meta.url),'utf8');
test('static: no browser-role GRANTs',()=>assert.doesNotMatch(sql,/GRANT\s+(?:INSERT|UPDATE|DELETE|EXECUTE)[^;]+\b(?:anon|authenticated)\b/gi));
test('static: RLS on all three tables',()=>assert.equal((sql.match(/ENABLE ROW LEVEL SECURITY/g)||[]).length,3));
test('static: security definer fixed search paths',()=>{
 assert.equal((sql.match(/SECURITY DEFINER SET search_path = pg_catalog, pg_temp/g)||[]).length,3);
 assert.match(sql,/REVOKE ALL ON ALL FUNCTIONS IN SCHEMA gflo_bridge FROM PUBLIC/);
});
test('static: transaction and replay tuple are present',()=>{
 assert.match(sql,/BEGIN;[\s\S]+COMMIT;/);
 assert.match(sql,/INSERT INTO gflo_bridge\.used_source_keys/);
 assert.match(sql,/INSERT INTO gflo_bridge\.attestation_outbox/);
});
test('static: lease fencing and SKIP LOCKED implemented',()=>{
 assert.match(sql,/FOR UPDATE SKIP LOCKED/);
 assert.match(sql,/lease_token=p_lease_token/);
 assert.match(sql,/leased_until > clock_timestamp\(\)/);
});
test('static: signed fake review remains outside SQL assertions',()=>{
 assert.match(suite,/self.review is refused/i);
 assert.doesNotMatch(sql,/XPPolicyV03\.submit/);
});
test('static: SQL suite tests rejection cases',()=>{
 assert.match(suite,/WHEN insufficient_privilege/);
 assert.match(suite,/WHEN unique_violation/);
 assert.match(suite,/WHEN check_violation/);
});
test('static: independent DB connection test included',()=>{
 assert.match(concurrency,/RT6D4_ROW_LOCK_HELD/);
 assert.match(concurrency,/lease_next_event/);
});

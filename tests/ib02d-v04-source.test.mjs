// IB-02D source-only invariants; does NOT compile or run Solidity.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const s = readFileSync(new URL('../contracts/XPPolicyV04.sol',import.meta.url),'utf8');
test('candidate: bounded expiry after challenge and finalization window (source only)',()=>{
 assert.match(s,/FINALIZATION_WINDOW = 4 days/);
 assert.match(s,/enum Status \{ NONE, PENDING, VALID, REVOKED, EXPIRED \}/);
 assert.match(s,/function expirePending\(bytes32 claimId\) external returns \(bool\)/);
 assert.match(s,/grant.status=Status.EXPIRED;/);
 assert.match(s,/if\(block.timestamp >= uint256\(grant.finalizesAt\)\+FINALIZATION_WINDOW\) revert FinalizationExpired\(\)/);
});
test('candidate: pending releases quota, valid revoke does not (source only)',()=>{
 assert.match(s,/if\(grant.status==Status.PENDING\) _releasePendingQuota\(grant\);/);
 assert.match(s,/else validEarnedXP\[grant.recipient\]-=grant.amount;/);
 assert.match(s,/claimsPerRule\[grant.recipient\]\[grant.ruleId\]-=1;/);
});
test('candidate: canonical XP read pauses (source only)',()=>{
 assert.match(s,/function totalXP\(address wallet\) external view returns\(uint64\) \{\s*if\(paused\) revert Paused\(\);/);
});

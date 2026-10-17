// AR01: fail-closed static source compatibility gate. NOT an EVM execution test.
// Usage: GFLO_PIE_DIR=../gflo-pie node --test tests/ar01-xp-source-gate.test.mjs
// Checkout gflo-pie at feature/pie-core-v0.2 and pin its full commit SHA in the run log.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';

const root=process.env.GFLO_PIE_DIR;
if (!root) throw new Error('GFLO_PIE_DIR is required: fail closed');
const source=(path)=>readFileSync(resolve(root,path),'utf8');
const legacy=source('contracts/PIECore.sol');
const core=source('contracts/PIECoreIgnitionV01.sol');
const policy=source('contracts/XPPolicyV03.sol');
const registry=source('contracts/TrustedXPSourceRegistryV02.sol');
const gate=source('contracts/EffectiveTierGateV01.sol');

test('AR01-01 legacy public self-award is detected and forbidden as trusted source',()=>{
 assert.match(legacy,/function\s+gainXP\s*\(\s*uint256\s+amount\s*\)\s*external/);
 assert.match(legacy,/identities\[msg\.sender\]\.xp\s*\+=\s*amount/);
});
test('AR01-02 pilot core has 25 Genesis XP and no external addXP/gainXP',()=>{
 assert.match(core,/GENESIS_XP\s*=\s*25/);
 assert.doesNotMatch(core,/function\s+(?:addXP|gainXP)\s*\(/);
});
test('AR01-03 policy totalXP includes only core XP plus finalized valid earned XP',()=>{
 assert.match(policy,/return\s+identity\.xp\s*\+\s*validEarnedXP\[wallet\]/);
 assert.match(policy,/validEarnedXP\[grant\.recipient\]\s*\+=\s*grant\.amount/);
 assert.match(policy,/if\s*\(grant\.status==Status\.VALID\)\s*validEarnedXP\[grant\.recipient\]-=grant\.amount/);
});
test('AR01-04 registry fail-closed read and policy provenance shape',()=>{
 assert.match(registry,/bool\s+public\s+paused\s*=\s*true/);
 assert.match(registry,/if\s*\(paused\s*\|\|\s*activeSource\.policy\s*==\s*address\(0\)\)\s*revert\s+RegistryInactive/);
 assert.match(registry,/policy\.codehash\s*!=\s*codehash/);
 assert.match(registry,/\.pie\(\)\s*!=\s*pieCore/);
 assert.match(registry,/\.owner\(\)\s*!=\s*expectedOwner/);
});
test('AR01-05 effective tier uses registry and not direct policy totalXP',()=>{
 assert.match(gate,/registry\.totalXP\(wallet\)/);
 assert.doesNotMatch(gate,/policy\.totalXP\(wallet\)/);
});

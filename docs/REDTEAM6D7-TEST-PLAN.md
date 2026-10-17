# RED TEAM 6D.7 — issuer collusion and governance allowlist rotation

Status: PROPOSED EVM REPRODUCER; NOT RUN as of creation. No production change.

The 6D.6 owner-run signed local EVM 9/9 tests verified that immutable XPPolicyV04 attestor pinning defeats the particular Safe-authorized *alternate EOA attestor* bypass. This does NOT establish source event truth. GFLOSourceBoundAttestorV01 still allows Safe 2/3 to call setIssuer(address,true). A permitted new issuer can sign any arbitrary proofDigest; ERC-1271 responds with a valid signature on that digest.

## Runner
`scripts/rt6d7-issuer-rotation-evm.mjs` extends the proven 6D.6 fixture; 10 checks total, **9 reused**. The new check RT6D7-09:
1. Simulate a fictitious Builder completion, with no real OctoPush source record.
2. Confirm new outsider key cannot register approval before governance permission.
3. Execute genuine Safe 2-of-3 setIssuer to authorize the colluding key.
4. Submit issuer-signed EIP-712 source approval bound to the fabricated XP proof digest.
5. Submit proof through pinned XPPolicyV04 + GFLOSourceBoundAttestorV01; observe PENDING.
6. After challenge period, finalize to canonical XP.
7. Disable issuer, and verify finalized XP remains until independent Safe XPPolicy revoke.
8. Revoke fabricated claim to restore active XP. Then run baseline Safe revocation/registry fail-closed check.

No live tokens or external signatures. An intentionally successful attack is a **HIGH security finding**, not an authorization safety pass.

## Run in Termux
```sh
cd ~/GFLO.Octo_PIE-cookR
git fetch origin
git switch -c feature/rt6d7-issuer-rotation-attack --track origin/feature/rt6d7-issuer-rotation-attack
cp scripts/rt6d7-issuer-rotation-evm.mjs ~/gflo-v02-evm/rt6d7.mjs
cd ~/gflo-v02-evm
node --check rt6d7.mjs && node rt6d7.mjs
```

## Release constraints
- Verify user-run 10/10 output; static file review or a claim about expected tests is not a passing result.
- Flag source issuer compromise, governance collusion and a trusted issuer signing false work as OPEN trust risks.
- Define independent reviewer and issuer rotation governance, restricted signing service, dual-approval source provenance, delayed timelocked key changes, evidence storage and audit before signing.
- Neither V04 nor this fixture alone makes source events factual. Never treat GFO/PIE identity XP as a simple token accounting problem.

# AR01 Signed EVM 6C — verified CI evidence

Date: 2026-10-17
Run: https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39068879916
Job ID: `117502153624`, conclusion: **success**
Workflow: `.github/workflows/ar01-signed-evm-6c.yml`
Compiler: `solc 0.8.34+commit.80d5c536.Emscripten.clang`

## Executed results

The signed local EthereumJS EVM fixture `scripts/rt6c-source-authenticity.mjs` reported all **8/8 checks PASS**:

1. Safe 2/3 governance controls fresh XPPolicyV03; gate reads canonical XP.
2. Unauthorized signer/unsigned proof rejected.
3. **HIGH FINDING:** colluding authorized signers can submit fabricated source event as PENDING.
4. PENDING XP does not raise canonical XP or unlock Tier 1.
5. **HIGH FINDING:** fabricated authorized event finalizes after challenge; 1000 unverified XP becomes canonical.
6. Finalized grant enables signed Tier 1 burn and effective tier.
7. Governance revocation removes effective tier despite historical achieved tier.
8. Replay after revocation rejected; paused Registry fails closed.

## Interpretation

**PASS means the test assertions executed successfully, including assertions proving a critical open weakness.** It does NOT mean source authenticity is secure. The fixture reuses RED TEAM 5A scenarios; eight passing checks are not eight independent novel security guarantees. No mainnet deployment or real wallet/fund operations were involved. No production-readiness claim is justified.

## Provenance

The run checked out PIE branch `feature/pie-core-v0.2` and legacy GasFeeLoop; see the job's `Record exact sources` step for precise commit SHAs. The EVM test itself ran to completion.

## Next gate

Add source-bound issuer authorization, prevent direct fabricated attestation paths, and rerun the same signed EVM regression including adversarial bypass attempts. Preserve the original HIGH finding as baseline evidence.

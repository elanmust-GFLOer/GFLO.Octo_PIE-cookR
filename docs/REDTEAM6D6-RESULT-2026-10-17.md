# RED TEAM 6D.6 — owner-run signed EVM result

Date: 2026-10-17
Environment: Android Termux local EthereumJS with synthetic keys
Solc: `0.8.34+commit.80d5c536.Emscripten.clang`
Branch: `feature/rt6d6-pinned-attestor`
Runner: `scripts/rt6d6-pinned-attestor-evm.mjs`
Runner fix verified in user output: `224f8d5`
Status: **9/9 user-executed scenarios PASS; source authenticity HIGH residual risk OPEN**.

## Observed outcomes

1. Safe 2/3 controls V04 and only pinned ERC-1271 attestor is usable — PASS.
2. Fabricated direct XP with no approved source authorization reverts — PASS.
3. Unauthorized source issuer cannot register forged approval — PASS.
4. Authorized issuer permits exact XP digest, prevents replay — PASS.
5. Permitted verifier sends approved claim PENDING; replay rejected — PASS.
6. Expiry, pause and governance revocation fail closed — PASS.
7. Finalized grant allows signed Tier 1 burn — PASS.
8. **Central security result:** Safe 2/3 cannot add an alternate EOA attestor via the former `setAttestor` interface. Outer failed transaction was expected; alternative EOA-signed XP claim also reverted. Safe nonce and protected state were checked by the runner. **Previously reproduced V03 alternate-attestor bypass denied on this V04 deployment.**
9. Safe XP revoke and paused Registry both remove future effective-Tier access — PASS.

## Safety interpretation

Passing 9/9 **does not resolve RT6C overall source authenticity finding**. Even a pinned SourceBoundAttestorV01 accepts issuer-signed proofs without independent proof that the work occurred, and Safe governance controls allowed issuer keys in SourceBoundAttestorV01. Compromised issuers and governance collusion remain feasible attack paths. The V04 pin is global, constructor-immutable and codehash-pinned; this test does not verify all possible policy-switch, source contract, consumer or deployment upgrades.

No production chain deploy, independent audit, real-world Builder event, signer custody or live Supabase integration was verified. The fixture shares prior RT6D.5 tests and must not be counted as nine wholly new security properties.

## Next gates

- Source issuer honesty and governance issuer-rotation collusion (RT6D.7).
- Adversarial EVM tests against registry/policy replacement or alternate consumer reads.
- Off-chain reviewed completion event binding plus auditable custody/recovery design.
- Review legacy unused `ruleAttestors` getter and source-key authorization policy, and independently audit before testnet.

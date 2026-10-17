# RED TEAM 6D.6 — immutable source-bound attestor in XPPolicyV04

Status: **EXPERIMENTAL / NOT EVM-EXECUTED / NOT AUDITED**.
Source inputs: GFLO PIE feature/pie-core-v0.2 XPPolicyV03 and RT6D.5 GFLOSourceBoundAttestorV01. This V04 is a NEW policy, not an in-place deployment upgrade.

## Threat / change

RT6D.5 showed that Safe 2/3 could add an alternate EOA attestor through XPPolicyV03.setAttestor and pass unverified activity as PENDING. In XPPolicyV04, constructor receives `pinnedSourceAttestor`, validates its runtime code, and records `sourceBoundAttestor` plus initial `sourceBoundRuntimeHash` as immutable values. `submit` requires the exact pinned address and codehash. The legacy `setAttestor(bytes32,address,bool)` entry point always reverts, even when called by the Safe owner. This is a **global pinned source-bound attestor**, stricter than a per-rule lookup; separate rule-specific pins are deferred. XPPolicyV04 retains the same proof hash and XP accounting behavior as V03.

The old `ruleAttestors` public mapping remains as read-only legacy ABI compatibility and is never writable, always false; code reviewers should decide whether to remove it before audit to avoid misleading off-chain clients.

## Tests

Run from checked-out cookR `feature/rt6d6-pinned-attestor` and existing EthereumJS test installation:

```sh
cd ~/GFLO.Octo_PIE-cookR && git pull --ff-only
cp scripts/rt6d6-pinned-attestor-evm.mjs ~/gflo-v02-evm/rt6d6.mjs
cd ~/gflo-v02-evm && node --check rt6d6.mjs && node rt6d6.mjs
```

The runner reuses RT6D.5's 9 scenarios but changes setup to V04 and **inverts RT6D6-08**: Safe's attempt to set another EOA attestor must produce Safe ExecutionFailure, and fake EOA-signed submission must revert. Reused checks do not count as independent security properties. **9/9 is a target, not a claimed result.**

## Critical residual risk / no claims of full source truth

- Trusted source issuer can still sign fabricated events. An issuer key signature alone does not prove task completion.
- Safe governance can alter the issuer allowlist and pause SourceBoundAttestor; malicious governance can register its own issuer key, then authorize fabricated source data without bypassing the pinned contract. Governance can disable registry and propose separate policy before activation; existing TrustedXPSourceRegistryV02 pins one active policy, but constitutional change control remains external.
- Contract immutability prevents ordinary `setAttestor` bypass **only within this specific V04 instance**. A different policy contract, a different XP-reading consumer, compromised registry/governance, or a malicious initial pinned contract remains outside the invariant.
- SourceBoundAttestorV01 has no explicit binding to source row integrity or the off-chain authenticated reviewer/transactional outbox. Complete bridge provenance and anti-collusion design are pending.
- Challenge period allows suspected fraud to be contested, not automatically proven real.
- No Safe owners' real keys, RPC, deployed token funds, migrations or live data touched.

## Audit and release gates

1. Compile V04 and execute new signed EthereumJS fixture; investigate failures, never redefine acceptance to pass.
2. Verify initial pinned contract code and issuer custody; test a malicious source issuer, source codehash mutation and governance issuer rotation.
3. Examine whether removal of legacy mapping and EIP-712 domain/version change are warranted for future upgrade boundaries.
4. Formal review: signer governance capabilities, recovery procedure, live register/bridge sources, public-chain tests and independent contract audit.

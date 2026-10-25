# GFLO IB-03W — Independent Codex Review (READ ONLY)

**Scope:** `elanmust-GFLOer/GFLO.Octo_PIE-cookR`, PR #20 draft, reproducible commit `75cbffeef085926143fca3043329567cc0327a59`, Actions evidence https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/40225245362.

**Authorization:** Read-only audit, local ephemeral tests permitted. NO remote push, branch update, merge, PR edit, secret extraction, real wallet signing, Etherscan writes, deployment, live RPC transaction, or Supabase/Lovable modification. Never print secret keys beyond explicitly public disposable fixture identifiers.

## Examine
- `pilots/ib03w/local-erc1271.test.mjs`: Ethereum secp256k1 EIP-191 message digest/recovery, explicit SIWE domain/URI/nonce/chain/time checks, Solidity EIP-1271 contract compilation and EVM execution.
- `pilots/ib03d/siwe-core.mjs`: EIP-4361 parser deviation from ABNF, dynamic ERC-1271 ownership/revocation, EIP-191 hashing and finality claims.
- `pilots/ib03u` and `pilots/ib03v`: binary canonical format versus actual EOA SIWE signature, version/downgrade handling.
- Pinned `package-lock.json` at `1ea68bc5b796901e5f652b6580c0584236ba2c5f`: supply-chain reproducibility.
- Etherscan Sepolia read-only verified ABI/source: legacy PIECore at `0x9CF55d0b9D61Dc28EF3cb10765CF4b861Cd0991e`; nonverified GFLOIgnition at `0x414DEDcf9264614Fd087BDa58bE27a0B698CcC54`, GFLOToken at `0x563b2e3b499818a2f84c472efb3169a2667807fe`.

## Adversarial checklist
1. Require real EIP-1271 `isValidSignature` EVM execution; identify any synthetic finality/blockHash metadata. Show that local EVM is not Sepolia chain finality.
2. Test 1271 malformed signature, wrong magic, signer-owner rotation (stateful), contract bytecode replacement, RPC errors, unexpected chain/address and message digest changes.
3. Distinguish "valid EOA SIWE" from "authorized session" (nonce, binding and explicit consent still required).
4. Attempt an Ed25519 service-envelope or HMAC attestation substitution for the secp256k1 SIWE signature; must fail.
5. Verify no bridge to canonical V04 is claimed from a legacy PIECore ABI. Analyze `gainXP(uint256)` access risk in legacy contract only; do not merge legacy XP into V04.
6. Re-run `node pilots/ib03w/local-erc1271.test.mjs` in pinned isolated harness; capture exact Node, solc, ethers, EthereumJS versions and hashes, record independent negative cases.
7. Give all findings with severity, line/file, exploit preconditions, minimal failing test and recommended fix. Do not mark production PASS.

## Required report
`EXECUTIVE VERDICT: PASS / CONDITIONAL / BLOCK`
`EVIDENCE: commit, run, lock, source SHA, commands, outcomes`
`EIP-191 / EIP-4361 / EIP-1271 compatibility matrix`
`ATTACK PATHS`, `OPEN TRUST BOUNDARIES`, `PRE-MERGE GATES`
If test environment cannot run, report `NOT EXECUTED`, not PASS.

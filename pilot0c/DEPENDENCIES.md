# Cryptographic dependency and vector evidence

The unchanged ethers **6.15.0** UMD release artifact is vendored as
`vendor/ethers.umd.min.cjs` (only the filename suffix differs).

* Upstream commit: `9fd9d41d017a5e3b329aca47c79786e69cd40b99`.
* Upstream path: `dist/ethers.umd.min.js`, exactly 517486 bytes.
* Git blob: `36002edde8d2ba5f6ed39d9774b62b9bc80f63ee`.
* SHA-256: `fcfd9597005606eabed524ed9f97df69dbc5cac461119a9bb8a4c6b280cfa3f1`.
* Origin: https://github.com/ethers-io/ethers.js/blob/9fd9d41d017a5e3b329aca47c79786e69cd40b99/dist/ethers.umd.min.js

The release package identifies `@noble/curves` **1.2.0** (secp256k1 recovery) and
`@noble/hashes` **1.3.2** (Keccak/SHA primitives). Full upstream release dependency
metadata and the local verification record are in `dependency-manifest.json`.
No alternative handwritten ECC, NIST SHA3-as-Keccak, or network fallback exists.
`crypto.cjs` verifies the artifact hash before requiring it, then exports only
address/hash/recovery primitives. Its exact EOA signature profile is in README.
The test harness alone accesses ephemeral key generation and signing.

Independent review evidence: Trail of Bits' January–February 2023 noble-curves
review includes abstract curve/modular/weierstrass helpers and **secp256k1**.
The upstream audit scope at the pinned dependency release is preserved in
`vendor/NOBLE-AUDIT-SCOPE.md`:
https://github.com/paulmillr/noble-curves/blob/1.2.0/audit/README.md
Report: https://github.com/trailofbits/publications/blob/master/reviews/2023-01-ryanshea-noblecurveslibrary-securityreview.pdf

This is historical independent review of the underlying implementation, **not
an assertion that every post-audit change, ethers bundle, or this pilot has an
independent audit certificate**. The audit baseline is historical 0.7.3 and
subsequent release changes need separate review for production acceptance.
The public EIP-712 vector and ephemeral positive/negative tests verify concrete
behavior, not absence of all cryptographic or supply-chain defects. No independent
rebuild of the minified distribution or blanket current-advisory clearance is
claimed. Retain these limits in the laboratory/production verdicts.

The bundle also contains ethers' other components. Upstream package metadata
pins ens-normalize 1.10.1, aes-js 4.0.0-beta.5, tslib 2.7.0 and ws 8.17.1
(@types/node 22.7.5 is build/type metadata). No provider, RPC, socket, ENS lookup,
transaction or token method is constructed/called by the proof service. Artifact
hashing uses Node's builtin crypto; nonces, UUIDs, test-key entropy and audit HMAC
use Node's cryptographic runtime. The ledger records Node/OpenSSL versions.

MIT licenses for ethers/noble-curves/noble-hashes are preserved under `vendor/`.
Node CI runtime is **22.14.0**, setup-node commit
`49933ea5288caeca8642d1e84afbd3f7d6820020`; local runtime is **24.19.0**.
Inherited Python wheels, Action pins and PostgreSQL image digest are unchanged.
Hosted OS, runtime downloads/toolcache and artifact service are recorded trust
inputs; this is not a hermetic platform rebuild.

Public vectors:

* EIP-712 Ether Mail: expected signer
  `0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826`, digest
  `0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2`,
  published r/s/v signature from the standard's Example.sol/JSON-RPC example.
  Source: https://github.com/ethereum/EIPs/blob/f1bcca1b56ee91fe115d2a8d8fd731fd6ca38bb3/assets/eip-712/Example.sol
  Only public vector material is included; **no fixed signing key**.
* SIWE formatting/parser profile follows EIP-4361 ABNF:
  https://github.com/ethereum/ERCs/blob/6b7a48ffa791e30ceee94d869b5eae9521fe158f/ERCS/erc-4361.md
* Runtime-generated EOA vectors: distinct fresh keys for A/B; real ERC-191 SIWE
  and EIP-712 consent signatures; context-isolation cases are re-signed after
  changing exactly the tested field, so rejection is not explained by an
  unrelated random nonce or stale signature.

Unsupported wallet types: ERC-1271, EIP-6492/counterfactual, delegated account
semantics, real wallet transports and alternative signature encodings. Unknown
types fail closed; no smart-wallet compatibility or production key security is
inferred from successful EOA tests.

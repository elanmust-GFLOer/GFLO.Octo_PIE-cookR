# Pilot 0B: offline protocol-source consistency gate

This pure-Python typed validator has no network, wallet, database, RPC, token or
mutation capability. It does not connect to the gateway or published OctoGFLO.
It cannot create authentication context, canonical XP, Tier or other rights.

`Manifest` describes chain/address, creation/deployment and runtime code hashes,
canonical ABI hash, verified source ID/hash, DIRECT or EIP1967 implementation
identity, source class, read selectors, evidence reference/status and validity.
`ReadSource` describes the requested source and selectors. Trusted server/test
configuration supplies a separate `Registry` of immutable raw `Evidence` records.
Caller-provided VERIFIED labels cannot create an observation or registry entry.
The registry itself is a trust input, not proof that a chain was independently
queried. All current complete entries are synthetic test fixtures.

`validate(manifest, request, registry, now)` returns DENY or
CONSISTENT_OFFLINE_NON_PRODUCTION plus a stable reason/classification and, on
consistency, a canonical manifest digest. Every result has
`production_authorized=False`, `canonical_xp_authorized=False`, and no
entitlements. REVIEWED_PROTOCOL_DATA is a provenance label, never activation
or entitlement authority. Wallet control and account authentication stay separate.

Hashes are explicitly **SHA-256** over raw bytecode/source and over the ABI
serialized as sorted-key, compact JSON. They are not Ethereum Keccak code hashes.
Missing bytes/digests are never invented or inferred from a contract address.
Unknown algorithms, wrong or conflicting hashes, chain/address/source mismatch,
UNKNOWN/REVOKED status, absent reviewer, expired/future/stale evidence, duplicate
references, unknown proxy kind and implementation mismatch deny. The maximum
manifest age is 24 hours; boundary equality expires. This freshness policy is
offline evidence age, not a proof of present chain state or reorg finality.

Read selectors must match a view/pure ABI method and an independent evidence
proof. This first package deliberately supports only the pinned standard vector
`balanceOf(address) -> 0x70a08231`. Unknown signatures and forged mappings deny;
no NIST SHA3 substitution or guessed PIE selector is used. General Keccak
selector derivation, bytecode semantics, deployment proof/recompilation, storage
layout/proxy-slot proof and chain finality are not implemented. Even an accepted
synthetic EIP1967 record is only internal consistency, not chain verification.

`legacy-sepolia.incomplete.json` preserves genuine SHA-256 ABI/source snapshots
from Pilot 0A. It intentionally has **null creation/runtime hashes, UNKNOWN
verification, no approved selectors and no Registry entry**. It is a descriptive
incomplete record, not an accepted Manifest. Historical Keccak evidence is left
in the frozen source report and is not relabeled as SHA-256. Sepolia chain
11155111 / `0x9CF55d0b9D61Dc28EF3cb10765CF4b861Cd0991e` is always
LEGACY_UNTRUSTED_XP. Permissionless self-awarded XP never establishes canonical
XP, Tier, reputation, governance or access authority.

The exact original Pilot 0A package and archived evidence live in
`pilot0a-frozen/`; `pilot0a-inventory.json` pins every preserved byte. The frozen
runner creates a disposable worktree of R6A commit
`12e2df4c32ef51d08c799ec63a565c90221e8bcd` and reruns the unchanged 59 tests in
a copy. Known-vulnerability diagnostics PASS by reproducing the old findings;
they are not evidence of safe new behavior. Archived evidence is never rewritten.

Run new checks: `python3 b23r6a/run_verified.py pilot0b/tests/test_manifest.py`.
Run history: `python3 b23r6a/frozen_pilot.py`. Full CI runs the preserved 86,
25 deadline tests, 37 source tests and frozen 59 (207 total), plus unchanged SQL
gates in distinct disposable databases. Zero skips/expected failures accepted.

Production remains BLOCKED: no reviewed canonical PIE deployment manifest,
live Auth/session authority, durable gateway audit/fencing, SIWE, separately
signed consent, recovery authorization or real wallet proof. gfloDEVaccount
remains NOT VERIFIED. No automatic R6B or real integration follows this package.

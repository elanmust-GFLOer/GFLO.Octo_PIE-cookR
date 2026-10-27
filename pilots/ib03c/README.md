# GFLO IB-03C — Trusted RPC & Identity Adapter Boundary
**LAB-ONLY / NO LIVE AUTHORIZATION / RELEASE BLOCK**

Commit base: IB-03B PR #20 head `6f051d38ba4f459c110f7e9685022bad3f2a4065`; this work is appended to the same draft PR.
The boundary is dependency-injected and intentionally lacks a real network, durable SIWE ledger, wallet, or production cryptographic service. The names `TrustedRpcBoundary` and `TrustedIdentityBoundary` designate required trust boundaries, **not attested trustworthiness of supplied mocks**.

## RPC requirements
- Verified provider/oracle must establish finality; the injected `finality.checkpoint()` is NOT an independent finality proof.
- Chain ID must equal configured pin; checkpoint block hash, block number and timestamp must be coherent.
- Every `eth_getCode` and `eth_call` uses EIP-1898 `{blockHash,requireCanonical:true}`, NEVER "latest" and NEVER a numeric fallback.
- The transport must enforce TLS endpoint identity, allowlisting, timeouts, JSON-RPC correctness, and reject untrusted rewrites.
- The injected `crypto.keccak256` must be Ethereum Keccak-256 (NOT NIST SHA3-256). ABI SHA-256 pinning belongs to a separate audited codec artifact. The current tests use synthetic hash fixtures.
- Registry core, active policy, runtime codehash, owner, and registry/policy pause flags must match pinned values. Unknown or stale data denies; no legacy XP fallback.
- No `eth_sendTransaction`, `eth_sendRawTransaction`, account permissions or wallet signing interfaces.

## Identity requirements
- `sessions.current()` MUST be a trusted SERVER session created only after verification of an EIP-4361 SIWE challenge and an EOA EIP-191 signature or an audited ERC-1271 path; enforce domain, URI, nonce one-time consumption, chain ID, issuedAt, expiry, request origin.
- `ledger.bindingSnapshot()` MUST be a server-managed, atomic and versioned ledger with explicit consent `pie:xp:read`, wallet and binding generations, immediate suspension, bounded validity and recovery protections.
- A browser-created `SIWE_VERIFIED` object is not authentic. Current code only checks server port shapes and input fields; it does not perform signature verification itself.
- Current IB-03B post-read revalidation mitigates trivial races; it is NOT an atomic distributed revocation proof. Revocation fencing remains BLOCKED.
- No live Lovable integration, no real wallet binding, no deployment, no XP/token writes.

## CI scope and blockers
The CI proves **synthetic boundary contract tests**, not real chain or SIWE security. Security acceptance needs separately audited production adapters, independent EIP-1898 transport tests, verified cryptographic codehash, honest finality oracle, durable anti-replay SIWE database and direct cross-system revocation race tests. No release from this PR.

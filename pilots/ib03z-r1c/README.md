# IB-03Z-R1C — F-03 / F-05 Codex remediation gate

Source of requirements: ERC-1271 has arbitrary `bytes signature`; only a specific ECDSA contract may insist on 65 bytes. The IB03X transport now accepts even-length hexadecimal signatures between 0 and 4096 bytes, passes them unchanged to `isValidSignature`, and denies longer/malformed data.

F-05 reproduces a genuine EVM-level zero-owner exploit against a deliberately vulnerable Solidity fixture, then demonstrates a hardened example rejecting zero-owner deployment, zero-owner rotation and recovered address(0). The patched hardened fixture is **a proposed implementation reference**, not a production smart-wallet upgrade; the prior W/Y demonstration contracts are unchanged and remain unsafe if used without hardening.

EIP-1271 ECDSA signatures, multisig/BLS formats, upstream provider trust, EIP-4361 ABNF, live 1271 owner-state pinning and production authorization remain gated. No deployment/merge/production.

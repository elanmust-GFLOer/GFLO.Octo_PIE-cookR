# GFLO IB-03D.1 Verifiable SIWE Core — DRAFT ONLY
Root: IB-03C PR #20; this work is appended to the same feature branch.

**What is verified:** Ethereum EIP-191 EOA recovery using pinned ethers, exact SIWE context and timestamps with strict bounded canonical form, plus an ERC-1271 verification port that requires externally provided finalized-block proof.

**What is not verified:** ERC-1271 on-chain proof is entirely injected/mocked here, not an actual eth_call. The constrained parser is not a full EIP-4361 ABNF compliance implementation; further parser conformance tests and standards review required. No SIWE server origin resolver, challenge creation, durable one-time nonce consumption, session issuance, atomic ledger, binding recovery, or live RPC is present. `CRYPTO_VERIFIED_ONLY` explicitly denies session authority.

Security note: Do NOT mint or consume a session on `verifySiweCore.ok` alone. The next step IB-03D.2 must provide serializable nonce consumption and session-to-consent version fencing. ERC-1271 must be authenticated against pinned deployment, block hash and current wallet state before real-world use.

Only synthetic wallet keys in tests; no production deployment, live wallet connection, user data, Supabase mutation, or Lovable write.

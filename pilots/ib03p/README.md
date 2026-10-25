# GFLO IB-03P — Independent Issuer Service & Key Custody Preflight

**CI LAB ONLY — PRODUCTION BLOCK.**

Separate Unix account with mode 0400 ephemeral HMAC key and 0700 parent directory; an isolated issuer Node process independently verifies real EIP-191 EOA signatures and immutable PostgreSQL context. It uses a dedicated DB login permitted to execute only the narrow context-read function. The admission account cannot directly read the key file. The issuer's MAC binds the context via IB-03O; the database verifies the MAC and issues a session once.

**Critical caveats:** CI root/sudo runner and test setup know the key, so the demonstration is Unix DAC-level isolation, NOT KMS/HSM, not a non-exportable key, not physical service or node isolation. Verifier and admission run in the same CI host; no mTLS or attested runtime identity. The issuer accepts requests via test stdin (not hardened HTTP/socket) and is not yet a long-running service. No key-rotation workflow or issuer-compromise containment is proven by this first gate. No production SIWE domain origin enforcement, ERC-1271 RPC, session cookie management, external audit, or distributed revocation and response-disclosure fencing.

The secret must NEVER be committed or logged. No Supabase, Lovable, wallet, merge or production deployment.

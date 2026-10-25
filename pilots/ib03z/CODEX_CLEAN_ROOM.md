# Codex IB-03Z — Clean Room Independent Audit, READ ONLY

Start from a new empty Codex session and clean temporary checkout. DO NOT paste earlier assistant verdicts, conclusions, or audit narratives. Only use:
- repository: elanmust-GFLOer/GFLO.Octo_PIE-cookR
- PR: #20, OPEN/DRAFT, pin and record current exact HEAD before any execution
- examine: pilots/ib03w/, pilots/ib03x/, pilots/ib03y/, pilots/ib03z/, pilots/ib03u/, pilots/ib03v/
- baseline GitHub run: 40225245362 / job 121265106240 (IB03W)
- CI run of IB03Z: resolve by pinned head and include actual status (NOT EXECUTED if unavailable)
- Sepolia chainId 11155111; three contract addresses are in pilots/ib03z/provenance.mjs

Never push, edit GitHub, merge, deploy, sign with a user wallet, touch Supabase/Lovable, or use a production credential. Only read-only RPC / source inspection and disposable local tests are allowed.

Research independently: EIP-191, EIP-4361, EIP-1271, EIP-1898; verify local EVM codehash and state-root tests, historical finalized block lookup and RPC inconsistencies. Check Etherscan verified source is not automatically deployed canonical V04; check exact runtime bytecode and ABI. Attack the premise that agreement between two providers proves independent finality. Confirm fail-closed behavior when data is missing, reorg occurs, or the providers diverge. Check EIP-1271 dynamic signer rotation across blocks, proxy reconfiguration, frontend/backend SIWE binding and replay revocation.

Report:
EXECUTIVE VERDICT PASS/CONDITIONAL/BLOCK; pinned HEAD/CI; exact commands/results; cryptographic compatibility matrix; critical adversarial findings (file:line); trust model; source and provider limitations; and concrete corrective tests. Do not inherit prior PASS conclusions.

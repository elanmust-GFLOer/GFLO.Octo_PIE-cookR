# IB-02E — Candidate-specific EVM security gate
Status: **RELEASE BLOCK** until a complete GitHub Actions execution is independently read.
This job compiles the candidate Solidity against pinned GFLO PIE fixtures, then executes 26 named synthetic EVM scenarios plus the existing 14 signed regressions.
All transactions are local EthereumJS EVM only, no RPC endpoint, no deployment, no secrets.
The gate is scoped to the new candidate and does not prove factual issuer work, consumer EXPIRED support, OctoPass binding, keeper liveness, or proxy upgrade safety.
No claim of completeness for all adversarial schedules, fuzzing, formally verified invariants or production release.

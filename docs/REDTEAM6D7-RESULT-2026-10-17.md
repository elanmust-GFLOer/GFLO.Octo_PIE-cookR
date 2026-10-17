# RED TEAM 6D.7 — issuer collusion and governance rotation result

Date: 2026-10-17
Evidence: owner-pasted Android Termux output (local signed EthereumJS fixture), **not independently rerun**.
Compiler: solc 0.8.34+commit.80d5c536.Emscripten.clang
Runner: scripts/rt6d7-issuer-rotation-evm.mjs
Result: **10/10 completed**; RT6C **HIGH source-trust attack reproduced**.

## Observed
RT6D7-01 through 08 (baseline reused from RT6D.6) passed: Safe 2-of-3 setup, unauthorized-source rejection, issuer signature binding and replay, PENDING gating, expiry/pause/revoke behavior, Tier 1 burn and the denial of alternate EOA attestor bypass.

**RT6D7-09 new attack:** Safe authorized a colluding source issuer; a fabricated Builder event received an issuer signature, passed the pinned XPPolicyV04 + ERC-1271 attestator, became canonical XP after the challenge period. Disabling the issuer alone did not remove already finalized XP; separate XPPolicy grant revocation did. The result is a successful HIGH-risk adversarial reproduction, not evidence of full security.

RT6D7-10 baseline Safe revocation and registry fail-closed checks passed.

## Scope and caveats
Nine scenarios substantially reuse 6D.6; not ten independent protections. All events/keys are synthetic, not empirical OctoPush completion evidence. The test cannot establish factual authenticity or social Sybil resistance. No external blockchain, production Supabase, signed live user data, independent audit or real treasury action was demonstrated.

## Security consequence
Global immutable EOA-bypass protection in XPPolicyV04 works for the tested contract, but governance control of SourceBoundAttestorV01's issuer allowlist remains a trusted point of failure. Issuer revocation does not retroactively erase canonical XP from already finalized grants. An independently protected evidence-approval authority, key-rotation delay/notice, conflict-of-interest controls, signed source evidence and emergency XP revocation policy are still required.

**RT6C HIGH source-authenticity concern: OPEN.** Do not deploy or declare a production security milestone complete.

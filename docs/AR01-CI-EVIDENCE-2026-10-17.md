# AR01 CI Evidence — 2026-10-17

## Verified GitHub Actions run

- Run: https://github.com/elanmust-GFLOer/GFLO.Octo_PIE-cookR/actions/runs/39067454070
- Run ID: `39067454070`
- Job: `static-source-gate`, ID `117497954649`
- Job conclusion: `success`
- Integration SHA: `e91bb0bc0d7de87eaebca52e4f07798b61835c5b`
- PIE source SHA: `dbd02d3f1ffd31abff3bda9caaa9852ee7cecf5c`
- Node.js: `v22.23.3`
- Command: `node --test tests/ar01-xp-source-gate.test.mjs` with `GFLO_PIE_DIR=_gflo_pie`
- TAP: `tests 5; pass 5; fail 0; skipped 0`

## Scope

These are **static source-pattern compatibility checks**, not deployed EVM execution, exploit prevention proof, source-attestation authenticity, bytecode verification, or a third-party audit. A future EVM test gate must independently exercise authorization, replay, revoke, pause and consumer behavior.

## Result

AR01 static source gate: PASS for pinned source commits. AR01 EVM/integration validation: OPEN.
